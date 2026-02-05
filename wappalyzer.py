"""
Wappalyzer detection engine — async-native Python port.

Loads 3,700+ technology fingerprints from Wappalyzer JSON files,
pre-compiles all regex patterns at startup, and exposes a pure-Python
`analyze()` function that matches collected page data against every
technology fingerprint.
"""

from __future__ import annotations

import json
import os
import re
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass(slots=True)
class Pattern:
    value: str
    regex: re.Pattern | None
    confidence: int = 100
    version: str = ""


@dataclass(slots=True)
class Category:
    id: int
    name: str
    slug: str
    priority: int = 0
    groups: list[int] = field(default_factory=list)


@dataclass(slots=True)
class Technology:
    name: str
    slug: str
    categories: list[int] = field(default_factory=list)
    website: str | None = None
    description: str | None = None
    icon: str = "default.svg"
    cpe: str | None = None
    pricing: list[str] = field(default_factory=list)

    # Detection patterns (pre-parsed)
    cookies: dict[str, list[Pattern]] = field(default_factory=dict)
    dns: dict[str, list[Pattern]] = field(default_factory=dict)
    headers: dict[str, list[Pattern]] = field(default_factory=dict)
    html: list[Pattern] = field(default_factory=list)
    css: list[Pattern] = field(default_factory=list)
    robots: list[Pattern] = field(default_factory=list)
    url: list[Pattern] = field(default_factory=list)
    xhr: list[Pattern] = field(default_factory=list)
    meta: dict[str, list[Pattern]] = field(default_factory=dict)
    scripts: list[Pattern] = field(default_factory=list)
    script_src: list[Pattern] = field(default_factory=list)
    text: list[Pattern] = field(default_factory=list)
    cert_issuer: list[Pattern] = field(default_factory=list)

    # Relationships
    implies: list[dict] = field(default_factory=list)
    excludes: list[str] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    requires_category: list[int] = field(default_factory=list)


@dataclass(slots=True)
class Detection:
    technology: Technology
    confidence: int
    version: str
    pattern_type: str


# ---------------------------------------------------------------------------
# Pattern parsing  (mirrors wappalyzer.js parsePattern / transformPatterns)
# ---------------------------------------------------------------------------

def _slugify(s: str) -> str:
    s = re.sub(r"[^a-z0-9-]", "-", s.lower())
    s = re.sub(r"--+", "-", s)
    return s.strip("-")


def _parse_one_pattern(raw: str | int, is_regex: bool = True) -> Pattern:
    """Parse a single Wappalyzer pattern string like ``regex\\;version:\\1\\;confidence:50``."""
    raw = str(raw)
    parts = raw.split("\\;")

    value = parts[0]
    confidence = 100
    version = ""

    for part in parts[1:]:
        if ":" in part:
            k, v = part.split(":", 1)
            if k == "confidence":
                try:
                    confidence = int(v)
                except ValueError:
                    pass
            elif k == "version":
                version = v

    compiled = None
    if is_regex and value:
        try:
            # Mirror JS behaviour: limit quantifiers to prevent ReDoS
            expr = value.replace("/", "\\/")
            expr = expr.replace("\\+", "__ESCAPED_PLUS__")
            expr = expr.replace("+", "{1,250}")
            expr = expr.replace("*", "{0,250}")
            expr = expr.replace("__ESCAPED_PLUS__", "\\+")
            compiled = re.compile(expr, re.IGNORECASE)
        except re.error:
            logger.debug("Bad regex in fingerprint: %s", value)
            compiled = None
    elif not is_regex:
        compiled = re.compile("", re.IGNORECASE)

    return Pattern(value=value, regex=compiled, confidence=confidence, version=version)


def _transform_patterns(
    raw: str | int | list | dict | None,
    case_sensitive: bool = False,
    is_regex: bool = True,
) -> list[Pattern] | dict[str, list[Pattern]]:
    """Transform raw pattern data from JSON into parsed Pattern objects."""
    if raw is None:
        return []

    # Normalise to dict with "main" key when needed
    if isinstance(raw, (str, int, list)):
        raw = {"main": raw}

    parsed: dict[str, list[Pattern]] = {}
    for key, values in raw.items():
        norm_key = key if case_sensitive else key.lower()
        if not isinstance(values, list):
            values = [values]
        parsed[norm_key] = [_parse_one_pattern(v, is_regex) for v in values]

    return parsed.get("main", parsed)


def _parse_implies(raw: str | list | None) -> list[dict]:
    if not raw:
        return []
    if isinstance(raw, str):
        raw = [raw]
    result = []
    for entry in raw:
        parts = str(entry).split("\\;")
        name = parts[0]
        confidence = 100
        version = ""
        for p in parts[1:]:
            if ":" in p:
                k, v = p.split(":", 1)
                if k == "confidence":
                    try:
                        confidence = int(v)
                    except ValueError:
                        pass
                elif k == "version":
                    version = v
        result.append({"name": name, "confidence": confidence, "version": version})
    return result


def _parse_excludes(raw: str | list | None) -> list[str]:
    if not raw:
        return []
    if isinstance(raw, str):
        return [raw]
    return [str(e) for e in raw]


def _parse_requires_category(raw: int | str | list | None) -> list[int]:
    if not raw:
        return []
    if isinstance(raw, (int, str)):
        return [int(raw)]
    return [int(x) for x in raw]


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

class WappalyzerEngine:
    """Loads fingerprints once and provides fast matching."""

    def __init__(self, fingerprints_dir: str | Path | None = None):
        if fingerprints_dir is None:
            fingerprints_dir = Path(__file__).parent / "fingerprints"
        self.fingerprints_dir = Path(fingerprints_dir)

        self.categories: dict[int, Category] = {}
        self.technologies: list[Technology] = []  # unconditional techs
        self._conditional_techs: list[Technology] = []  # requires/requiresCategory
        self._tech_by_name: dict[str, Technology] = {}

        self._load_categories()
        self._load_technologies()
        logger.info(
            "Wappalyzer engine loaded: %d technologies (%d conditional), %d categories",
            len(self.technologies) + len(self._conditional_techs),
            len(self._conditional_techs),
            len(self.categories),
        )

    # ---- loading helpers ---------------------------------------------------

    def _load_categories(self) -> None:
        path = self.fingerprints_dir / "categories.json"
        with open(path) as f:
            data = json.load(f)
        for cat_id_str, cat_data in data.items():
            cat_id = int(cat_id_str)
            self.categories[cat_id] = Category(
                id=cat_id,
                name=cat_data.get("name", ""),
                slug=_slugify(cat_data.get("name", "")),
                priority=cat_data.get("priority", 0),
                groups=cat_data.get("groups", []),
            )

    def _load_technologies(self) -> None:
        all_techs: list[Technology] = []
        for json_file in sorted(self.fingerprints_dir.glob("?.json")):
            with open(json_file) as f:
                data = json.load(f)
            for name, raw in data.items():
                tech = self._parse_technology(name, raw)
                all_techs.append(tech)
                self._tech_by_name[name] = tech
        # Also load _.json
        underscore = self.fingerprints_dir / "_.json"
        if underscore.exists():
            with open(underscore) as f:
                data = json.load(f)
            for name, raw in data.items():
                tech = self._parse_technology(name, raw)
                all_techs.append(tech)
                self._tech_by_name[name] = tech

        # Separate unconditional from conditional technologies
        for tech in all_techs:
            if tech.requires or tech.requires_category:
                self._conditional_techs.append(tech)
            else:
                self.technologies.append(tech)

    def _parse_technology(self, name: str, raw: dict) -> Technology:
        # Parse script_src (called scriptSrc in JSON)
        script_src = _transform_patterns(raw.get("scriptSrc"))
        if isinstance(script_src, dict):
            # flatten dict values to list
            flat: list[Pattern] = []
            for v in script_src.values():
                flat.extend(v)
            script_src = flat

        html = _transform_patterns(raw.get("html"))
        if isinstance(html, dict):
            flat = []
            for v in html.values():
                flat.extend(v)
            html = flat

        css = _transform_patterns(raw.get("css"))
        if isinstance(css, dict):
            flat = []
            for v in css.values():
                flat.extend(v)
            css = flat

        robots = _transform_patterns(raw.get("robots"))
        if isinstance(robots, dict):
            flat = []
            for v in robots.values():
                flat.extend(v)
            robots = flat

        url_pats = _transform_patterns(raw.get("url"))
        if isinstance(url_pats, dict):
            flat = []
            for v in url_pats.values():
                flat.extend(v)
            url_pats = flat

        xhr_pats = _transform_patterns(raw.get("xhr"))
        if isinstance(xhr_pats, dict):
            flat = []
            for v in xhr_pats.values():
                flat.extend(v)
            xhr_pats = flat

        text_pats = _transform_patterns(raw.get("text"))
        if isinstance(text_pats, dict):
            flat = []
            for v in text_pats.values():
                flat.extend(v)
            text_pats = flat

        cert_issuer = _transform_patterns(raw.get("certIssuer"))
        if isinstance(cert_issuer, dict):
            flat = []
            for v in cert_issuer.values():
                flat.extend(v)
            cert_issuer = flat

        scripts = _transform_patterns(raw.get("scripts"))
        if isinstance(scripts, dict):
            flat = []
            for v in scripts.values():
                flat.extend(v)
            scripts = flat

        headers = _transform_patterns(raw.get("headers"))
        if not isinstance(headers, dict):
            headers = {}

        cookies = _transform_patterns(raw.get("cookies"))
        if not isinstance(cookies, dict):
            cookies = {}

        meta = _transform_patterns(raw.get("meta"))
        if not isinstance(meta, dict):
            meta = {}

        dns_pats = _transform_patterns(raw.get("dns"))
        if not isinstance(dns_pats, dict):
            dns_pats = {}

        return Technology(
            name=name,
            slug=_slugify(name),
            categories=raw.get("cats", []),
            website=raw.get("website"),
            description=raw.get("description"),
            icon=raw.get("icon", "default.svg"),
            cpe=raw.get("cpe"),
            pricing=raw.get("pricing", []),
            cookies=cookies,
            dns=dns_pats,
            headers=headers,
            html=html,
            css=css,
            robots=robots,
            url=url_pats,
            xhr=xhr_pats,
            meta=meta,
            scripts=scripts,
            script_src=script_src,
            text=text_pats,
            cert_issuer=cert_issuer,
            implies=_parse_implies(raw.get("implies")),
            excludes=_parse_excludes(raw.get("excludes")),
            requires=_parse_excludes(raw.get("requires")),  # same format as excludes
            requires_category=_parse_requires_category(raw.get("requiresCategory")),
        )

    # ---- matching ----------------------------------------------------------

    def _resolve_version(self, pattern: Pattern, match_str: str) -> str:
        """Extract version from regex match using Wappalyzer's back-reference syntax."""
        if not pattern.version or not pattern.regex:
            return ""
        m = pattern.regex.search(match_str)
        if not m:
            return ""

        resolved = pattern.version
        for i, group in enumerate(m.groups(), start=1):
            group_val = group or ""
            if len(group_val) > 10:
                continue
            # Ternary: \1?yes:no
            ternary = re.search(rf"\\{i}\?([^:]+):(.*?)$", resolved)
            if ternary:
                resolved = resolved.replace(
                    ternary.group(0),
                    ternary.group(1) if group_val else ternary.group(2),
                )
            resolved = resolved.replace(f"\\{i}", group_val)

        # Remove unmatched back-references
        resolved = re.sub(r"\\\d", "", resolved).strip()
        return resolved

    def _match_one_to_one(
        self, tech: Technology, ptype: str, value: str
    ) -> list[Detection]:
        """Match a list of patterns against a single string value."""
        patterns: list[Pattern] = getattr(tech, ptype, [])
        results = []
        for pat in patterns:
            if pat.regex is None:
                continue
            if pat.regex.search(value):
                results.append(
                    Detection(
                        technology=tech,
                        confidence=pat.confidence,
                        version=self._resolve_version(pat, value),
                        pattern_type=ptype,
                    )
                )
        return results

    def _match_one_to_many(
        self, tech: Technology, ptype: str, values: list[str]
    ) -> list[Detection]:
        """Match patterns against a list of string values."""
        patterns: list[Pattern] = getattr(tech, ptype, [])
        results = []
        for val in values:
            for pat in patterns:
                if pat.regex is None:
                    continue
                if pat.regex.search(val):
                    results.append(
                        Detection(
                            technology=tech,
                            confidence=pat.confidence,
                            version=self._resolve_version(pat, val),
                            pattern_type=ptype,
                        )
                    )
        return results

    def _match_many_to_many(
        self, tech: Technology, ptype: str, items: dict[str, list[str]]
    ) -> list[Detection]:
        """Match keyed patterns against keyed value lists (headers, cookies, meta)."""
        pattern_map: dict[str, list[Pattern]] = getattr(tech, ptype, {})
        results = []
        for key, patterns in pattern_map.items():
            values = items.get(key, [])
            if not values:
                # For headers/cookies, pattern with empty regex means "key exists"
                continue
            for pat in patterns:
                if pat.regex is None:
                    continue
                for val in values:
                    if pat.regex.search(val):
                        results.append(
                            Detection(
                                technology=tech,
                                confidence=pat.confidence,
                                version=self._resolve_version(pat, val),
                                pattern_type=ptype,
                            )
                        )
        return results

    def _match_headers_exist(
        self, tech: Technology, headers: dict[str, list[str]]
    ) -> list[Detection]:
        """Check for header key existence when pattern value is empty."""
        results = []
        for key, patterns in tech.headers.items():
            if key in headers:
                for pat in patterns:
                    if not pat.value:
                        # Empty pattern = header existence check
                        results.append(
                            Detection(
                                technology=tech,
                                confidence=pat.confidence,
                                version="",
                                pattern_type="headers",
                            )
                        )
        return results

    def _match_cookies_exist(
        self, tech: Technology, cookies: dict[str, list[str]]
    ) -> list[Detection]:
        """Check for cookie key existence when pattern value is empty."""
        results = []
        for key, patterns in tech.cookies.items():
            if key in cookies:
                for pat in patterns:
                    if not pat.value:
                        results.append(
                            Detection(
                                technology=tech,
                                confidence=pat.confidence,
                                version="",
                                pattern_type="cookies",
                            )
                        )
        return results

    def analyze(self, page_data: dict[str, Any]) -> list[dict]:
        """
        Analyze collected page data against all technology fingerprints.

        ``page_data`` keys:
            url: str — the final URL
            html: str — raw HTML source
            headers: dict[str, list[str]] — response headers (lowercase keys)
            cookies: dict[str, list[str]] — cookie name→value
            meta: dict[str, list[str]] — <meta> name→content (lowercase keys)
            script_src: list[str] — all <script src="…"> URLs
            text: str — visible text content (optional)
        """
        url = page_data.get("url", "")
        html = page_data.get("html", "")
        headers = page_data.get("headers", {})
        cookies = page_data.get("cookies", {})
        meta = page_data.get("meta", {})
        script_src = page_data.get("script_src", [])
        text = page_data.get("text", "")

        raw_detections: list[Detection] = []

        def _scan_tech(tech: Technology) -> None:
            if url and tech.url:
                raw_detections.extend(self._match_one_to_one(tech, "url", url))
            if html and tech.html:
                raw_detections.extend(self._match_one_to_one(tech, "html", html))
            if headers and tech.headers:
                raw_detections.extend(self._match_many_to_many(tech, "headers", headers))
                raw_detections.extend(self._match_headers_exist(tech, headers))
            if cookies and tech.cookies:
                raw_detections.extend(self._match_many_to_many(tech, "cookies", cookies))
                raw_detections.extend(self._match_cookies_exist(tech, cookies))
            if meta and tech.meta:
                raw_detections.extend(self._match_many_to_many(tech, "meta", meta))
            if script_src and tech.script_src:
                raw_detections.extend(self._match_one_to_many(tech, "script_src", script_src))
            if html and tech.scripts:
                raw_detections.extend(self._match_one_to_one(tech, "scripts", html))
            if text and tech.text:
                raw_detections.extend(self._match_one_to_one(tech, "text", text))
            if html and tech.css:
                raw_detections.extend(self._match_one_to_one(tech, "css", html))

        # Pass 1: unconditional technologies
        for tech in self.technologies:
            _scan_tech(tech)

        # Pass 2: conditional technologies (requires / requiresCategory)
        # Build set of detected tech names and category IDs for prerequisite checks
        detected_names = {d.technology.name for d in raw_detections}
        detected_cat_ids: set[int] = set()
        for d in raw_detections:
            detected_cat_ids.update(d.technology.categories)

        for tech in self._conditional_techs:
            # Check requires: all named technologies must be detected
            if tech.requires and not all(r in detected_names for r in tech.requires):
                continue
            # Check requiresCategory: at least one required category must be detected
            if tech.requires_category and not any(
                c in detected_cat_ids for c in tech.requires_category
            ):
                continue
            _scan_tech(tech)

        return self._resolve(raw_detections)

    def _resolve(self, detections: list[Detection]) -> list[dict]:
        """Aggregate detections, resolve implies/excludes, return final results."""
        # Aggregate by technology name
        by_name: dict[str, dict] = {}
        for d in detections:
            name = d.technology.name
            if name not in by_name:
                by_name[name] = {
                    "technology": d.technology,
                    "confidence": 0,
                    "version": "",
                    "pattern_types": set(),
                }
            entry = by_name[name]
            entry["confidence"] = min(100, entry["confidence"] + d.confidence)
            entry["pattern_types"].add(d.pattern_type)
            # Keep the longest version that looks valid
            if (
                d.version
                and len(d.version) > len(entry["version"])
                and len(d.version) <= 15
            ):
                try:
                    if int(d.version.split(".")[0]) < 10000:
                        entry["version"] = d.version
                except ValueError:
                    entry["version"] = d.version

        # Resolve excludes
        exclude_names: set[str] = set()
        for entry in by_name.values():
            for ex in entry["technology"].excludes:
                exclude_names.add(ex)
        for name in exclude_names:
            by_name.pop(name, None)

        # Resolve implies
        changed = True
        while changed:
            changed = False
            for entry in list(by_name.values()):
                for imp in entry["technology"].implies:
                    imp_name = imp["name"]
                    if imp_name not in by_name and imp_name in self._tech_by_name:
                        imp_tech = self._tech_by_name[imp_name]
                        by_name[imp_name] = {
                            "technology": imp_tech,
                            "confidence": min(
                                entry["confidence"], imp["confidence"]
                            ),
                            "version": imp.get("version", ""),
                            "pattern_types": {"implied"},
                        }
                        changed = True

        # Build output
        results = []
        for entry in by_name.values():
            tech = entry["technology"]
            cats = []
            for cat_id in tech.categories:
                cat = self.categories.get(cat_id)
                if cat:
                    cats.append({"id": cat.id, "name": cat.name, "slug": cat.slug})
            results.append({
                "name": tech.name,
                "slug": tech.slug,
                "confidence": entry["confidence"],
                "version": entry["version"] or None,
                "categories": cats,
                "website": tech.website,
                "description": tech.description,
                "icon": tech.icon,
                "cpe": tech.cpe,
            })

        # Sort by confidence desc, then name
        results.sort(key=lambda r: (-r["confidence"], r["name"]))
        return results
