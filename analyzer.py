import os
import re
import zipfile
from pyaxmlparser import APK # Fast and no system dependency

def analyze_apk(apk_path):
    print(f"🔍 Fast scanning: {apk_path}")
    
    report = {
        "app_name": "Unknown",
        "package_name": "Unknown",
        "version_name": "Unknown",
        "vulnerabilities": [],
        "summary": {"critical": 0, "high": 0, "medium": 0, "low": 0, "total": 0}
    }

    try:
        # STEP 1: Fast Parsing with pyaxmlparser (No aapt required!)
        # Ye library internal binary XML ko read kar legi
        apk = APK(apk_path)
        
        report['app_name'] = apk.application
        report['package_name'] = apk.package
        report['version_name'] = apk.version_name
        
        # STEP 2: Manifest Security Checks
        # Check Debuggable
        if apk.debuggable:
            _add_vuln(report, {
                "type": "App is Debuggable",
                "severity": "High",
                "details": "The app has debuggable=true. Attackers can attach a debugger and steal data.",
                "remediation": "Set android:debuggable='false' in your Manifest."
            })

        # Check AllowBackup
        if apk.allow_backup:
            _add_vuln(report, {
                "type": "Backup Enabled",
                "severity": "Medium",
                "details": "App data can be extracted via 'adb backup'.",
                "remediation": "Set android:allowBackup='false'."
            })

        # STEP 3: Permission Analysis
        dangerous_perms = {
            "READ_SMS": "Can read your private messages.",
            "RECORD_AUDIO": "Can listen to your surroundings.",
            "ACCESS_FINE_LOCATION": "Can track your exact location."
        }
        
        for perm in apk.permissions:
            short_perm = perm.split('.')[-1]
            if short_perm in dangerous_perms:
                _add_vuln(report, {
                    "type": f"Dangerous Permission: {short_perm}",
                    "severity": "Medium",
                    "details": dangerous_perms[short_perm],
                    "remediation": "Use only if absolutely necessary."
                })

        # STEP 4: Secret Scan (Optimized)
        # APK ko unzip karke classes.dex se strings nikalna
        with zipfile.ZipFile(apk_path, 'r') as z:
            if 'classes.dex' in z.namelist():
                content = z.read('classes.dex').decode('latin-1', errors='ignore')
                
                # Simple patterns for API Keys
                patterns = {
                    "Google API Key": r'AIza[0-9A-Za-z\-_]{35}',
                    "AWS Access Key": r'AKIA[0-9A-Z]{16}'
                }
                
                for name, pattern in patterns.items():
                    matches = re.findall(pattern, content)
                    if matches:
                        _add_vuln(report, {
                            "type": f"Hardcoded {name}",
                            "severity": "Critical",
                            "details": f"Found sensitive string: {matches[0][:10]}...",
                            "remediation": "Move secrets to a secure backend or use BuildConfig."
                        })

    except Exception as e:
        print(f"❌ Error during analysis: {e}")
        report['error'] = str(e)

    report['summary']['total'] = len(report['vulnerabilities'])
    return report

def _add_vuln(report, vuln):
    report['vulnerabilities'].append(vuln)
    sev = vuln['severity'].lower()
    if sev in report['summary']:
        report['summary'][sev] += 1
