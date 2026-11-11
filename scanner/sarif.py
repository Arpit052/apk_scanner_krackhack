"""SARIF 2.1.0 export so results show up in GitHub code scanning / CI dashboards."""

from __future__ import annotations

from .engine import ENGINE_VERSION

LEVEL = {"Critical": "error", "High": "error", "Medium": "warning", "Low": "note", "Info": "note"}
SCORE = {"Critical": "9.5", "High": "8.0", "Medium": "5.5", "Low": "3.0", "Info": "0.0"}


def to_sarif(report: dict) -> dict:
    rules = {}
    results = []
    for f in report.get("vulnerabilities", []):
        rid = f["id"]
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": f["title"].replace(" ", ""),
                "shortDescription": {"text": f["title"]},
                "fullDescription": {"text": f["description"]},
                "help": {"text": f["remediation"], "markdown": f["remediation"]},
                "helpUri": (f.get("references") or [None])[0],
                "properties": {
                    "tags": ["security", f"OWASP-{f['owasp_id']}", f["masvs"], f["cwe"]],
                    "security-severity": SCORE.get(f["severity"], "0.0"),
                    "precision": {"High": "high", "Medium": "medium", "Low": "low"}.get(f["confidence"], "medium"),
                },
            }
        locs = f.get("locations") or ["AndroidManifest.xml"]
        results.append({
            "ruleId": rid,
            "level": LEVEL.get(f["severity"], "note"),
            "message": {"text": f"{f['title']}: {f['description']}"},
            "locations": [{
                "physicalLocation": {"artifactLocation": {"uri": report.get("file_name", "app.apk")}},
                "logicalLocations": [{"fullyQualifiedName": l.replace("  [library]", "")} for l in locs[:10]],
            }],
            "properties": {"severity": f["severity"], "confidence": f["confidence"], "evidence": f["evidence"]},
        })
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "KrackHack APK Scanner", "version": ENGINE_VERSION,
                                "informationUri": "https://github.com/Arpit052/apk_scanner_krackhack",
                                "rules": list(rules.values())}},
            "results": results,
            "properties": {"package": report.get("package_name"), "sha256": report.get("file_hash_sha256"),
                           "securityScore": report.get("security", {}).get("score")},
        }],
    }
