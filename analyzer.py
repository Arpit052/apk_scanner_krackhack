from androguard.misc import AnalyzeAPK
import re

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def analyze_apk(apk_path):
    print(f"\nScanning APK: {apk_path}\n")

    a, d, dx = AnalyzeAPK(apk_path)

    print("DEX FILES FOUND:", len(d))
    print("PERMISSIONS:", a.get_permissions())

    report = {
        "app_name": a.get_app_name() or "Unknown App",
        "package_name": a.get_package() or "Unknown Package",
        "vulnerabilities": []
    }

    # =====================================================
    # 1. MANIFEST SECURITY CHECKS
    # =====================================================

    manifest_xml = a.get_android_manifest_xml()

    if manifest_xml is not None:
        app_tag = manifest_xml.find("application")

        if app_tag is not None:

            # Debuggable
            if app_tag.get(ANDROID_NS + "debuggable") == "true":
                report["vulnerabilities"].append({
                    "type": "Debuggable App",
                    "severity": "High",
                    "details": "Application is debuggable"
                })

            # Allow Backup
            if app_tag.get(ANDROID_NS + "allowBackup") != "false":
                report["vulnerabilities"].append({
                    "type": "AllowBackup Enabled",
                    "severity": "Medium",
                    "details": "Application data can be extracted via ADB"
                })

            # Cleartext Traffic
            if app_tag.get(ANDROID_NS + "usesCleartextTraffic") == "true":
                report["vulnerabilities"].append({
                    "type": "Cleartext Traffic Allowed",
                    "severity": "Critical",
                    "details": "HTTP traffic permitted"
                })

    # =====================================================
    # 2. DANGEROUS PERMISSIONS
    # =====================================================

    dangerous = [
        "android.permission.READ_SMS",
        "android.permission.RECORD_AUDIO",
        "android.permission.READ_CONTACTS",
        "android.permission.ACCESS_FINE_LOCATION"
    ]

    for perm in dangerous:
        if perm in a.get_permissions():
            report["vulnerabilities"].append({
                "type": "Dangerous Permission",
                "severity": "Medium",
                "details": perm
            })

    # =====================================================
    # 3. EXPORTED ACTIVITIES (CORRECT METHOD)
    # =====================================================

    for activity in a.get_activities():
        if a.is_exported(activity):
            if activity != a.get_main_activity():
                report["vulnerabilities"].append({
                    "type": "Exported Activity",
                    "severity": "Low",
                    "details": activity
                })

    # =====================================================
    # 4. HARDCODED SECRETS (FIXED STRING EXTRACTION)
    # =====================================================

    patterns = {
        "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Private Key": re.compile(r'BEGIN PRIVATE KEY'),
        "Generic Secret": re.compile(r'(?i)(api_key|token|secret|password)["\s:=]+([A-Za-z0-9\-_]{8,})')
    }

    strings = []

    for dex in d:
        for s in dex.get_strings():
            strings.append(s)

    print("TOTAL STRINGS:", len(strings))

    found = set()

    for s in strings:
        if isinstance(s, str) and len(s) < 200:
            for name, pattern in patterns.items():
                if pattern.search(s):
                    if s not in found:
                        found.add(s)
                        report["vulnerabilities"].append({
                            "type": f"Hardcoded {name}",
                            "severity": "Critical",
                            "details": s[:50]
                        })

    return report


# ===============================
# Example Run
# ===============================

if __name__ == "__main__":
    apk = "sample.apk"
    result = analyze_apk(apk)

    print("\n========== REPORT ==========\n")
    print("App:", result["app_name"])
    print("Package:", result["package_name"])

    for v in result["vulnerabilities"]:
        print(v)
