"""Shared scan state + the Finding model."""

from __future__ import annotations

import logging
import re
import zipfile
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional

from .dex import DexIndex, descriptor_to_java
from .knowledge import LIBRARY_PREFIXES
from .taxonomy import OWASP_MOBILE_2024, SEVERITY_ORDER, SEVERITY_RISK

# pyaxmlparser is chatty ("res1 is not zero!") - silence it.
logging.getLogger("pyaxmlparser").setLevel(logging.CRITICAL)
for _n in ("pyaxmlparser.core", "pyaxmlparser.axmlparser", "pyaxmlparser.arscparser",
           "pyaxmlparser.stringblock", "pyaxmlparser.axmlprinter"):
    logging.getLogger(_n).setLevel(logging.CRITICAL)

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"
SEVERITIES = ["Critical", "High", "Medium", "Low", "Info"]


def downgrade(sev: str, steps: int = 1) -> str:
    i = min(SEVERITIES.index(sev) + steps, len(SEVERITIES) - 1)
    return SEVERITIES[i]


@dataclass
class Finding:
    id: str
    title: str
    severity: str
    owasp: str                       # "M5"
    masvs: str                       # "MASVS-NETWORK"
    cwe: str                         # "CWE-295"
    category: str
    description: str
    remediation: str
    evidence: List[str] = field(default_factory=list)
    locations: List[str] = field(default_factory=list)
    confidence: str = "High"
    references: List[str] = field(default_factory=list)
    in_library: bool = False
    tags: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        o = OWASP_MOBILE_2024.get(self.owasp, {"title": "", "url": ""})
        ev = "\n".join(self.evidence[:12])
        if len(self.evidence) > 12:
            ev += f"\n… and {len(self.evidence) - 12} more"
        refs = list(self.references)
        if o.get("url"):
            refs.insert(0, o["url"])
        risk = SEVERITY_RISK.get(self.severity, 1.0)
        if self.confidence == "Low":
            risk -= 1.0
        return {
            "id": self.id,
            "title": self.title,
            "type": self.title,                        # backwards compatible
            "severity": self.severity,
            "confidence": self.confidence,
            "owasp_id": self.owasp,
            "owasp_title": o["title"],
            "owasp": f"{self.owasp} ({o['title']})",  # backwards compatible
            "masvs": self.masvs,
            "cwe": self.cwe,
            "category": self.category,
            "details": self.description,               # backwards compatible
            "description": self.description,
            "evidence": ev,
            "evidence_list": self.evidence[:50],
            "locations": self.locations[:50],
            "remediation": self.remediation,
            "references": refs,
            "in_library": self.in_library,
            "tags": self.tags,
            "risk_score": round(max(risk, 0.5), 1),
        }


class ScanContext:
    """Lazily loads every artefact rules need from the APK."""

    def __init__(self, apk_path: str, log: Callable[[str], None]):
        from pyaxmlparser import APK  # local import keeps module import cheap

        self.path = apk_path
        self.log = log
        self.zip = zipfile.ZipFile(apk_path)
        self.names: List[str] = self.zip.namelist()
        self.name_set = set(self.names)
        self.apk = APK(apk_path)
        self.manifest = self.apk.get_android_manifest_xml()
        self.package: str = self.apk.package or "unknown"
        self.min_sdk = _to_int(self.apk.get_min_sdk_version(), 1)
        self.target_sdk = _to_int(self.apk.get_target_sdk_version(), self.min_sdk)
        self.findings: List[Finding] = []
        self.capabilities: Dict[str, dict] = {}
        self.controls: Dict[str, List[str]] = {}
        self.malware_signals: List[dict] = []
        self.extra: Dict[str, object] = {}
        self._dex: Optional[DexIndex] = None
        self._arsc = None
        self._calls = None
        pkg_path = self.package.replace(".", "/")
        self.app_prefixes = {f"L{pkg_path}/"}
        app_cls = self.app_attr("name")
        if app_cls:
            self.app_prefixes.add("L" + self.qualify(app_cls).rsplit(".", 1)[0].replace(".", "/") + "/")

    # ---- manifest helpers --------------------------------------------- #
    @property
    def application(self):
        if self.manifest is None:
            return None
        return self.manifest.find("application")

    def app_attr(self, name: str) -> Optional[str]:
        app = self.application
        return None if app is None else app.get(ANDROID_NS + name)

    @staticmethod
    def attr(el, name: str, default=None):
        return el.get(ANDROID_NS + name, default)

    def qualify(self, name: str) -> str:
        if not name:
            return name
        if name.startswith("."):
            return self.package + name
        if "." not in name:
            return f"{self.package}.{name}"
        return name

    # ---- resources ------------------------------------------------------ #
    @property
    def arsc(self):
        if self._arsc is None:
            try:
                self._arsc = self.apk.get_android_resources()
            except Exception:
                self._arsc = False
        return self._arsc or None

    def resolve_resource(self, value: Optional[str]):
        """'@7F130000' -> 'res/xml/provider_paths.xml' or a string value."""
        if not value or not value.startswith("@"):
            return value
        try:
            rid = int(value[1:], 16)
        except ValueError:
            return value
        arsc = self.arsc
        if not arsc:
            return None
        try:
            res = arsc.get_resolved_res_configs(rid)
            if res:
                return res[0][1]
        except Exception:
            return None
        return None

    def read_xml(self, path: Optional[str]):
        if not path or path not in self.name_set:
            return None
        try:
            from pyaxmlparser.axmlprinter import AXMLPrinter
            return AXMLPrinter(self.zip.read(path)).get_xml_obj()
        except Exception:
            try:
                from lxml import etree
                return etree.fromstring(self.zip.read(path))
            except Exception:
                return None

    # ---- code ---------------------------------------------------------- #
    @property
    def dex(self) -> DexIndex:
        if self._dex is None:
            names = sorted(n for n in self.names if re.fullmatch(r"classes\d*\.dex", n))
            blobs = []
            for n in names:
                try:
                    blobs.append((n, self.zip.read(n)))
                except Exception as e:
                    self.log(f"could not read {n}: {e}")
            self._dex = DexIndex(blobs, self.log)
        return self._dex

    def is_library(self, descriptor: str) -> bool:
        if any(descriptor.startswith(p) for p in self.app_prefixes):
            return False
        return descriptor.startswith(LIBRARY_PREFIXES)

    # ---- findings -------------------------------------------------------- #
    def add(self, f: Finding) -> None:
        self.findings.append(f)

    def add_code_finding(self, f: Finding, sites, min_app_sites: int = 1) -> None:
        """Attach call-site locations and downgrade when only library code is involved."""
        app_sites = [s for s in sites if not self.is_library(s.caller_class)]
        lib_sites = [s for s in sites if self.is_library(s.caller_class)]
        ordered = app_sites + lib_sites
        f.locations = _dedupe([s.location + ("  [library]" if self.is_library(s.caller_class) else "")
                               for s in ordered])
        if len(app_sites) < min_app_sites:
            if not lib_sites:
                return
            f.in_library = True
            f.severity = downgrade(f.severity, 2 if f.severity in ("Medium", "Low") else 1)
            f.confidence = "Low"
            f.description += " Only observed inside third-party libraries, which may be unreachable code."
        self.add(f)

    def capability(self, key: str, label: str, evidence: str, weight: int = 0) -> None:
        c = self.capabilities.setdefault(key, {"key": key, "label": label, "evidence": [], "weight": weight})
        if evidence and evidence not in c["evidence"] and len(c["evidence"]) < 8:
            c["evidence"].append(evidence)

    def signal(self, key: str, label: str, weight: int, evidence: str = "") -> None:
        for s in self.malware_signals:
            if s["key"] == key:
                if evidence and evidence not in s["evidence"] and len(s["evidence"]) < 6:
                    s["evidence"].append(evidence)
                return
        self.malware_signals.append({"key": key, "label": label, "weight": weight,
                                     "evidence": [evidence] if evidence else []})

    def control(self, key: str, evidence: str) -> None:
        lst = self.controls.setdefault(key, [])
        if evidence not in lst and len(lst) < 5:
            lst.append(evidence)

    def sorted_findings(self) -> List[dict]:
        out = [f.to_dict() for f in self.findings]
        conf = {"High": 0, "Medium": 1, "Low": 2}
        out.sort(key=lambda d: (SEVERITY_ORDER.get(d["severity"], 9), d["in_library"],
                                conf.get(d["confidence"], 3), d["title"]))
        return out


def _to_int(v, default: int) -> int:
    try:
        return int(str(v).strip())
    except Exception:
        return default


def _dedupe(items: List[str]) -> List[str]:
    seen = set()
    out = []
    for i in items:
        if i not in seen:
            seen.add(i)
            out.append(i)
    return out


def java(desc: str) -> str:
    return descriptor_to_java(desc)
