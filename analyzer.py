import re
import zipfile
from pyaxmlparser import APK

DANGEROUS_PERMS = {
    "READ_SMS", "SEND_SMS", "RECORD_AUDIO",
    "READ_CONTACTS", "ACCESS_FINE_LOCATION",
    "READ_PHONE_STATE", "CAMERA"
}

SECRET_PATTERNS = {
    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
    "AWS Key": r'AKIA[0-9A-Z]{16}',
    "Firebase URL": r'https://[a-z0-9-]+\.firebaseio\.com',
    "Private Key": r'-----BEGIN PRIVATE KEY-----'
}

def analyze_apk(apk_path):

    apk = APK(apk_path)

    report = {
        "app": apk.application,
        "package": apk.package,
        "version": apk.version_name,
        "vulnerabilities": [],
        "summary": {"critical":0,"high":0,"medium":0,"low":0,"total":0}
    }

    manifest = apk.get_manifest()

    # ---------------- Manifest Checks ----------------

    # Debuggable
    if 'android:debuggable="true"' in manifest:
        add(report,"Debuggable Enabled","High","Disable android:debuggable in release build")

    # Allow Backup
    if 'android:allowBackup="true"' in manifest:
        add(report,"Backup Enabled","Medium","Set allowBackup=false")

    # Cleartext traffic
    if 'usesCleartextTraffic="true"' in manifest:
        add(report,"Cleartext Traffic Allowed","Critical","Enforce HTTPS only")

    # ---------------- Dangerous Permissions ----------------

    for p in apk.permissions:
        short = p.split(".")[-1]
        if short in DANGEROUS_PERMS:
            add(report,f"Dangerous Permission: {short}","Medium","Remove if unnecessary")

    # ---------------- Exported Components ----------------

    for activity in apk.get_activities():
        exported = apk.get_element("activity", "android:exported", activity)
        if exported == "true":
            add(report,f"Exported Activity: {activity}","High","Restrict exported components")

    # ---------------- Multi-DEX Secret Scan ----------------

    with zipfile.ZipFile(apk_path) as z:
        for f in z.namelist():
            if f.endswith(".dex"):
                data = z.read(f).decode("latin-1", errors="ignore")
                for name, pattern in SECRET_PATTERNS.items():
                    if re.search(pattern, data):
                        add(report,f"Hardcoded {name}","Critical","Move secrets to backend")

    report["summary"]["total"] = len(report["vulnerabilities"])
    return report


def add(r,title,sev,fix):
    r["vulnerabilities"].append({
        "type":title,
        "severity":sev,
        "fix":fix
    })
    r["summary"][sev.lower()] += 1
