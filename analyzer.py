from androguard.misc import AnalyzeAPK
import re

def analyze_apk(apk_path):
    print(f"Scanning {apk_path}...")
    a, d, dx = AnalyzeAPK(apk_path)
    
    report = {
        "app_name": a.get_app_name() or "Unknown App",
        "package_name": a.get_package() or "Unknown Package",
        "vulnerabilities": []
    }

    # ---------------------------------------------------------
    # 1. MANIFEST SECURITY CHECKS (OWASP M2, M3, M7)
    # ---------------------------------------------------------
    manifest_xml = a.get_android_manifest_xml()
    if manifest_xml is not None:
        application_tag = manifest_xml.find("application")
        if application_tag is not None:
            
            # Check Debuggable (OWASP M7: Client Code Quality)
            debuggable = application_tag.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                report["vulnerabilities"].append({
                    "type": "App is Debuggable",
                    "severity": "High",
                    "owasp": "M7 (Client Code Quality)",
                    "details": "The application is marked as debuggable. This allows attackers to easily attach debuggers and extract sensitive runtime data.",
                    "remediation": "Set android:debuggable='false' in AndroidManifest.xml before releasing to production."
                })
            
            # Check AllowBackup (OWASP M2: Insecure Data Storage)
            allow_backup = application_tag.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if allow_backup == "true" or allow_backup is None:
                report["vulnerabilities"].append({
                    "type": "Application Data Backup Enabled",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "details": "android:allowBackup is true. An attacker with physical access or malware could extract app data via ADB backup.",
                    "remediation": "Set android:allowBackup='false' in AndroidManifest.xml."
                })

            # Check Cleartext Traffic (OWASP M3: Insecure Communication)
            cleartext = application_tag.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
            if cleartext == "true":
                report["vulnerabilities"].append({
                    "type": "Cleartext HTTP Traffic Allowed",
                    "severity": "Critical",
                    "owasp": "M3 (Insecure Communication)",
                    "details": "The app explicitly allows unencrypted HTTP communication, making it highly vulnerable to Man-in-the-Middle (MITM) attacks.",
                    "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS for all connections."
                })

    # ---------------------------------------------------------
    # 2. EXCESSIVE PERMISSIONS (OWASP M1: Improper Platform Usage)
    # ---------------------------------------------------------
    dangerous_permissions = {
        "android.permission.READ_SMS": "Can read all SMS messages (risk of OTP theft).",
        "android.permission.ACCESS_FINE_LOCATION": "Tracks precise user location.",
        "android.permission.READ_CONTACTS": "Can read the user's entire contact list.",
        "android.permission.RECORD_AUDIO": "Can record audio without user interaction."
    }
    app_permissions = a.get_permissions()
    for perm, risk in dangerous_permissions.items():
        if perm in app_permissions:
            report["vulnerabilities"].append({
                "type": f"Dangerous Permission Detected",
                "severity": "Medium",
                "owasp": "M1 (Improper Platform Usage)",
                "details": f"The app requests {perm.split('.')[-1]}. {risk}",
                "remediation": "Remove this permission if not strictly necessary. Apply the principle of least privilege."
            })

    # ---------------------------------------------------------
    # 3. EXPORTED COMPONENTS (Filtering out the main launcher)
    # ---------------------------------------------------------
    activities = a.get_activities()
    for activity in activities:
        intent_filters = a.get_intent_filters("activity", activity)
        if intent_filters:
            # We must check if it's the main launcher activity. If it is, it's not a vulnerability!
            is_main_launcher = False
            for action, names in intent_filters.items():
                if "android.intent.action.MAIN" in names:
                    is_main_launcher = True
            
            if not is_main_launcher:
                report["vulnerabilities"].append({
                    "type": "Improperly Exported Activity",
                    "severity": "Low",
                    "owasp": "M1 (Improper Platform Usage)",
                    "details": f"Activity {activity} is exported and can be launched by other apps, potentially bypassing authentication.",
                    "remediation": "Set android:exported='false' in AndroidManifest.xml unless external access is strictly required."
                })

    # ---------------------------------------------------------
    # 4. HARDCODED SECRETS (OWASP M9: Insecure Data Storage)
    # ---------------------------------------------------------
    patterns = {
        "AWS API Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Private Key": re.compile(r'-----BEGIN PRIVATE KEY-----'),
        "Generic Password/Token": re.compile(r'(?i)(api_key|token|secret|password)["\s:=]+(["\'][a-zA-Z0-9\-_]{10,}["\'])')
    }
    
    strings = []
    for dex in d:
        strings.extend(dex.get_strings())
        
    found_secrets = set() # Use a set to prevent showing the exact same key 50 times
    for string_val in strings:
        if isinstance(string_val, str) and len(string_val) < 200:
            for secret_name, pattern in patterns.items():
                if pattern.search(string_val):
                    if string_val not in found_secrets:
                        found_secrets.add(string_val)
                        report["vulnerabilities"].append({
                            "type": f"Hardcoded {secret_name}",
                            "severity": "Critical",
                            "owasp": "M9 (Insecure Data Storage)",
                            "details": f"Found sensitive hardcoded string: '{string_val[:40]}...'",
                            "remediation": "Never hardcode secrets. Fetch them dynamically from a secure backend or use the Android Keystore system."
                        })

    return report