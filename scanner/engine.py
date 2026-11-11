"""Scan orchestration and report assembly."""

from __future__ import annotations

import base64
import hashlib
import math
import os
import time
import traceback
import zipfile
from datetime import datetime, timezone
from typing import Callable, Optional

from . import checks_code, checks_intel, checks_manifest, checks_secrets, checks_signing
from .context import ScanContext
from .taxonomy import CONFIDENCE_FACTOR, MASVS, OWASP_MOBILE_2024, SEVERITY_WEIGHT

ENGINE_VERSION = "3.0.0"

ProgressFn = Callable[[int, str, str], None]   # (percent, stage, message)

STAGES = [
    ("manifest", "Decoding manifest & components", checks_manifest.run, 18),
    ("signing", "Verifying signatures & certificate", checks_signing.run, 26),
    ("dex", "Parsing DEX bytecode", None, 40),
    ("code", "Tracing dangerous API calls", checks_code.run, 66),
    ("secrets", "Hunting secrets & endpoints", checks_secrets.run, 82),
    ("intel", "Fingerprinting SDKs, trackers & packers", checks_intel.run, 92),
]


def _hashes(path: str) -> dict:
    h = {"md5": hashlib.md5(), "sha1": hashlib.sha1(), "sha256": hashlib.sha256()}
    size = 0
    with open(path, "rb") as f:
        while chunk := f.read(1024 * 1024):
            size += len(chunk)
            for v in h.values():
                v.update(chunk)
    return {"size": size, **{k: v.hexdigest() for k, v in h.items()}}


def extract_base_apk(path: str, workdir: str) -> str:
    """Support .xapk/.apks/.apkm bundles: return the path of the base APK."""
    try:
        with zipfile.ZipFile(path) as z:
            names = z.namelist()
            if "AndroidManifest.xml" in names:
                return path
            apks = [n for n in names if n.lower().endswith(".apk")]
            if not apks:
                return path
            base = next((n for n in apks if os.path.basename(n).lower() in ("base.apk", "base-master.apk")), None)
            if base is None:
                base = next((n for n in apks if "split" not in n.lower() and "config." not in n.lower()),
                            max(apks, key=lambda n: z.getinfo(n).file_size))
            out = os.path.join(workdir, "base_" + os.path.basename(base))
            with z.open(base) as src, open(out, "wb") as dst:
                while chunk := src.read(1024 * 1024):
                    dst.write(chunk)
            return out
    except zipfile.BadZipFile:
        return path


def _icon(ctx: ScanContext) -> Optional[str]:
    try:
        cand = []
        p = ctx.apk.get_app_icon()
        if p and p.endswith((".png", ".webp")):
            cand.append(p)
        dens = ["xxxhdpi", "xxhdpi", "xhdpi", "hdpi", "mdpi"]
        for d in dens:
            for n in ctx.names:
                if ("mipmap-" + d in n or "drawable-" + d in n) and n.endswith((".png", ".webp")) and \
                        ("ic_launcher" in n and "foreground" not in n and "background" not in n):
                    cand.append(n)
        for n in cand:
            if n in ctx.name_set:
                data = ctx.zip.read(n)
                if len(data) < 400_000:
                    mime = "image/webp" if n.endswith(".webp") else "image/png"
                    return f"data:{mime};base64," + base64.b64encode(data).decode()
    except Exception:
        return None
    return None


def security_score(findings: list) -> dict:
    penalty = 0.0
    for f in findings:
        w = SEVERITY_WEIGHT.get(f["severity"], 0) * CONFIDENCE_FACTOR.get(f["confidence"], 0.7)
        penalty += w
    score = int(round(100 * math.exp(-penalty / 90)))
    grade = "A" if score >= 85 else "B" if score >= 70 else "C" if score >= 55 else "D" if score >= 40 else "F"
    return {"score": score, "grade": grade, "penalty": round(penalty, 1)}


def analyze(apk_path: str, progress: Optional[ProgressFn] = None, original_name: Optional[str] = None) -> dict:
    t0 = time.time()
    logs: list = []

    def log(msg: str) -> None:
        logs.append(msg)

    def step(pct: int, stage: str, msg: str) -> None:
        log(f"[{pct:3d}%] {msg}")
        if progress:
            try:
                progress(pct, stage, msg)
            except Exception:
                pass

    step(2, "hash", "Hashing file")
    hashes = _hashes(apk_path)
    workdir = os.path.dirname(os.path.abspath(apk_path))
    real = extract_base_apk(apk_path, workdir)
    bundle = real != apk_path
    if bundle:
        step(5, "bundle", f"Split bundle detected - scanning {os.path.basename(real)}")

    step(8, "load", "Loading APK container")
    try:
        ctx = ScanContext(real, log)
    except Exception as e:
        raise ValueError(f"Not a valid Android package: {e}") from e

    errors = []
    for key, label, fn, pct in STAGES:
        step(pct - 6 if pct > 6 else pct, key, label)
        st = time.time()
        try:
            if fn is None:
                d = ctx.dex
                n_str = sum(len(x.strings) for x in d.dexes)
                n_cls = sum(len(x.classes) for x in d.dexes)
                log(f"      {len(d.dexes)} dex · {n_cls:,} classes · {n_str:,} strings")
                step(pct, key, f"{len(d.dexes)} DEX files · {n_cls:,} classes · {n_str:,} strings indexed")
            else:
                fn(ctx)
        except Exception as e:
            errors.append(f"{key}: {e}")
            log(f"      ! {key} failed: {e}")
            log(traceback.format_exc(limit=3))
        log(f"      {key} done in {time.time() - st:.2f}s")

    step(96, "score", "Scoring risk")
    findings = ctx.sorted_findings()
    malware = checks_intel.assess(ctx)
    sec = security_score(findings)

    summary = {k: 0 for k in ("critical", "high", "medium", "low", "info")}
    for f in findings:
        summary[f["severity"].lower()] += 1
    summary["total"] = len(findings)

    owasp = {}
    for mid, meta in OWASP_MOBILE_2024.items():
        items = [f for f in findings if f["owasp_id"] == mid]
        worst = items[0]["severity"] if items else None
        owasp[mid] = {"id": mid, "title": meta["title"], "summary": meta["summary"], "url": meta["url"],
                      "count": len(items), "worst": worst}
    masvs = {k: {"id": k, "title": v, "count": sum(1 for f in findings if f["masvs"] == k)} for k, v in MASVS.items()}

    comps = ctx.extra.get("components") or []
    comp_summary = {}
    for t in ("activity", "service", "receiver", "provider"):
        items = [c for c in comps if c["type"] == t]
        comp_summary[t] = {"total": len(items), "exported": sum(1 for c in items if c["exported"])}

    signing = ctx.extra.get("signing") or {}
    try:
        label = ctx.apk.get_app_name() or ctx.package
    except Exception:
        label = ctx.package
    duration = round(time.time() - t0, 2)
    step(100, "done", f"Done - {summary['total']} findings in {duration}s")

    report = {
        "engine": {"name": "KrackHack APK Scanner", "version": ENGINE_VERSION},
        "file_name": original_name or os.path.basename(apk_path),
        "bundle": bundle,
        "app_name": label,
        "package_name": ctx.package,
        "version_name": ctx.apk.version_name or "",
        "version_code": str(ctx.apk.version_code or ""),
        "min_sdk": str(ctx.min_sdk),
        "target_sdk": str(ctx.target_sdk),
        "icon": _icon(ctx),
        "file_size_mb": round(hashes["size"] / (1024 * 1024), 2),
        "file_hash_sha256": hashes["sha256"],
        "hashes": {k: hashes[k] for k in ("md5", "sha1", "sha256")},
        "security": sec,
        "overall_risk_score": round(10 - sec["score"] / 10, 1),
        "summary": summary,
        "vulnerabilities": findings,
        "owasp": owasp,
        "masvs": masvs,
        "malware": malware,
        "malware_detected": malware["verdict"] in ("suspicious", "malicious"),
        "malware_confidence": {"malicious": "High", "suspicious": "Medium", "low": "Low"}.get(malware["verdict"], "None"),
        "malware_indicators": [s["label"] for s in malware["signals"]],
        "permissions": ctx.extra.get("permission_table", []),
        "components": comps,
        "component_summary": comp_summary,
        "deep_links": ctx.extra.get("deep_links", []),
        "network_security_config": ctx.extra.get("network_security_config"),
        "domains": ctx.extra.get("domains", []),
        "secrets": ctx.extra.get("secrets", []),
        "signing": signing,
        "trackers": ctx.extra.get("trackers", []),
        "frameworks": ctx.extra.get("frameworks", []),
        "native": ctx.extra.get("native", {}),
        "packers": ctx.extra.get("packers", []),
        "payloads": ctx.extra.get("payloads", []),
        "security_controls": [{"key": k, "evidence": v} for k, v in ctx.controls.items()],
        "obfuscation": ctx.extra.get("obfuscation"),
        "stats": {
            "dex_files": len(ctx.dex.dexes),
            "classes": sum(len(x.classes) for x in ctx.dex.dexes),
            "methods": sum(x.method_ids_size for x in ctx.dex.dexes),
            "strings": sum(x.string_ids_size for x in ctx.dex.dexes),
            "files": len(ctx.names),
        },
        "scan_metadata": {
            "scan_time_seconds": duration,
            "file_size_mb": round(hashes["size"] / (1024 * 1024), 2),
            "scan_timestamp": datetime.now(timezone.utc).isoformat(),
            "errors": errors,
        },
        "log": logs[-400:],
    }
    try:
        ctx.zip.close()
    except Exception:
        pass
    if bundle and os.path.exists(real):
        try:
            os.remove(real)
        except OSError:
            pass
    return report
