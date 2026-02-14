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

    # ---------- Manifest Checks ----------

    if apk.debuggable:
        add(report,"Debuggable Enabled","High","Disable android:debuggable")

    if apk.allow_backup:
        add(report,"Backup Enabled","Medium","Set allowBackup=false")

    if apk.get_manifest().find("usesCleartextTraffic") != -1:
        add(report,"Cleartext Traffic","Critical","Force HTTPS")

    # ---------- Dangerous Permissions ----------

    for p in apk.permissions:
        short = p.split(".")[-1]
        if short in DANGEROUS_PERMS:
            add(report,f"Dangerous Permission: {short}","Medium","Remove if not required")

    # ---------- Exported Components ----------

    for a in apk.get_activities():
        if apk.get_activity(a).get("exported") == "true":
            add(report,f"Exported Activity: {a}","High","Restrict exported")

    # ---------- Multi-DEX Secret Scan ----------

    with zipfile.ZipFile(apk_path) as z:
        for f in z.namelist():
            if f.endswith(".dex"):
                data = z.read(f).decode("latin-1",errors="ignore")
                for name,pat in SECRET_PATTERNS.items():
                    if re.search(pat,data):
                        add(report,f"Hardcoded {name}","Critical","Move secrets server-side")

    report["summary"]["total"] = len(report["vulnerabilities"])
    return report


def add(r,title,sev,fix):
    r["vulnerabilities"].append({
        "type":title,
        "severity":sev,
        "fix":fix
    })
    r["summary"][sev.lower()] += 1
