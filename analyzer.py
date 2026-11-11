#!/usr/bin/env python3
"""
KrackHack APK Scanner - command line interface.

    python analyzer.py app.apk                      # pretty summary
    python analyzer.py app.apk --json report.json   # full JSON report
    python analyzer.py app.apk --sarif out.sarif    # SARIF for GitHub code scanning
    python analyzer.py app.apk --fail-on high       # non-zero exit for CI gates

`analyze_apk(path)` is kept for backwards compatibility with the old module.
"""

from __future__ import annotations

import argparse
import json
import os
import sys

from scanner.engine import analyze

SEV_ORDER = ["info", "low", "medium", "high", "critical"]
COLORS = {"Critical": "\033[1;97;41m", "High": "\033[1;91m", "Medium": "\033[1;93m", "Low": "\033[1;96m",
          "Info": "\033[2m"}
RESET = "\033[0m"


def analyze_apk(apk_path: str) -> dict:
    """Backwards compatible entry point used by the old main.py."""
    try:
        return analyze(apk_path)
    except Exception as e:  # keep the old contract: errors are reported in the dict
        return {"error": f"Analysis failed: {e}"}


def _print(report: dict, color: bool) -> None:
    c = (lambda s, k: f"{COLORS.get(k, '')}{s}{RESET}") if color else (lambda s, k: s)
    sec, mal = report["security"], report["malware"]
    print()
    print(f"  {report['app_name']}  ({report['package_name']} {report['version_name']})")
    print(f"  SHA-256 {report['file_hash_sha256']}")
    print(f"  minSdk {report['min_sdk']} · targetSdk {report['target_sdk']} · "
          f"{report['stats']['classes']:,} classes · {report['scan_metadata']['scan_time_seconds']}s")
    print()
    print(f"  Security score : {sec['score']}/100  grade {sec['grade']}")
    print(f"  Malware risk   : {mal['score']}/100  {mal['label']}")
    s = report["summary"]
    print(f"  Findings       : {s['critical']} critical · {s['high']} high · {s['medium']} medium · "
          f"{s['low']} low · {s['info']} info")
    print()
    for v in report["vulnerabilities"]:
        tag = c(f"{v['severity']:<8}", v["severity"])
        lib = " [lib]" if v["in_library"] else ""
        print(f"  {tag} {v['owasp_id']:<4} {v['id']:<9} {v['title']}{lib}")
    if mal["signals"]:
        print("\n  Malware signals:")
        for sig in mal["signals"][:10]:
            print(f"    +{sig['weight']:<3} {sig['label']}")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Static security & malware analysis for Android APKs "
                                            "(OWASP Mobile Top 10 2024 / MASVS).")
    p.add_argument("apk", help="path to .apk / .xapk / .apks")
    p.add_argument("--json", metavar="FILE", help="write the full JSON report")
    p.add_argument("--sarif", metavar="FILE", help="write a SARIF 2.1.0 report")
    p.add_argument("--fail-on", choices=SEV_ORDER, help="exit 1 if a finding of this severity or worse exists")
    p.add_argument("--quiet", action="store_true", help="no summary output")
    p.add_argument("--no-color", action="store_true")
    a = p.parse_args(argv)

    if not os.path.exists(a.apk):
        print(f"file not found: {a.apk}", file=sys.stderr)
        return 2

    def progress(pct, _stage, msg):
        if not a.quiet:
            print(f"\r  [{pct:3d}%] {msg:<70}", end="", file=sys.stderr, flush=True)

    report = analyze(a.apk, progress=progress)
    if not a.quiet:
        print(file=sys.stderr)
    report.pop("icon", None) if a.json is None else None

    if a.json:
        with open(a.json, "w") as f:
            json.dump(report, f, indent=2, default=str)
    if a.sarif:
        from scanner.sarif import to_sarif
        with open(a.sarif, "w") as f:
            json.dump(to_sarif(report), f, indent=2)
    if not a.quiet:
        _print(report, color=sys.stdout.isatty() and not a.no_color)

    if a.fail_on:
        limit = SEV_ORDER.index(a.fail_on)
        worst = [v for v in report["vulnerabilities"] if SEV_ORDER.index(v["severity"].lower()) >= limit
                 and not v["in_library"]]
        if worst:
            print(f"  ✗ {len(worst)} finding(s) at or above '{a.fail_on}'", file=sys.stderr)
            return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
