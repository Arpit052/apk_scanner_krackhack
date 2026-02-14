from androguard.misc import AnalyzeAPK
import re

ANDROID_NS = "{http://schemas.android.com/apk/res/android}"

def analyze_apk(apk_path):
    print(f"🔍 Scanning APK: {apk_path}")
    
    try:
        a, d, dx = AnalyzeAPK(apk_path)
        print(f"✓ APK loaded successfully")
        print(f"DEBUG: Found {len(d)} DEX files")
        print(f"DEBUG: Found {len(a.get_permissions())} permissions")
    except Exception as e:
        return {
            "error": f"Failed to parse APK: {str(e)}",
            "app_name": "Unknown",
            "package_name": "Unknown"
        }

    report = {
        "app_name": a.get_app_name() or "Unknown App",
        "package_name": a.get_package() or "Unknown Package",
        "version_name": a.get_androidversion_name() or "Unknown",
        "version_code": a.get_androidversion_code() or "Unknown",
        "min_sdk": a.get_min_sdk_version() or "Unknown",
        "target_sdk": a.get_target_sdk_version() or "Unknown",
        "vulnerabilities": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0
        }
    }

    # =====================================================
    # 1. MANIFEST SECURITY CHECKS
    # =====================================================
    print("🔎 Checking manifest security...")
    
    manifest_xml = a.get_android_manifest_xml()
    print(f"DEBUG: Manifest XML found: {manifest_xml is not None}")

    if manifest_xml is not None:
        app_tag = manifest_xml.find("application")
        print(f"DEBUG: Application tag found: {app_tag is not None}")

        if app_tag is not None:
            # Debuggable
            debuggable = app_tag.get(ANDROID_NS + "debuggable")
            print(f"DEBUG: Debuggable = {debuggable}")
            if debuggable == "true":
                _add_vulnerability(report, {
                    "type": "App is Debuggable",
                    "severity": "High",
                    "owasp": "M7 (Client Code Quality)",
                    "category": "Configuration",
                    "details": "The application is marked as debuggable. Attackers can attach debuggers to extract sensitive runtime data.",
                    "remediation": "Set android:debuggable='false' in AndroidManifest.xml before releasing to production.",
                    "cwe": "CWE-489: Active Debug Code"
                })

            # Allow Backup
            allow_backup = app_tag.get(ANDROID_NS + "allowBackup")
            print(f"DEBUG: AllowBackup = {allow_backup}")
            if allow_backup == "true" or allow_backup is None:
                _add_vulnerability(report, {
                    "type": "Application Data Backup Enabled",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": "android:allowBackup is enabled. An attacker with physical access could extract app data via ADB backup.",
                    "remediation": "Set android:allowBackup='false' in AndroidManifest.xml.",
                    "cwe": "CWE-200: Exposure of Sensitive Information"
                })

            # Cleartext Traffic
            cleartext = app_tag.get(ANDROID_NS + "usesCleartextTraffic")
            print(f"DEBUG: Cleartext Traffic = {cleartext}")
            if cleartext == "true":
                _add_vulnerability(report, {
                    "type": "Cleartext HTTP Traffic Allowed",
                    "severity": "Critical",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": "The app explicitly allows unencrypted HTTP communication, making it vulnerable to Man-in-the-Middle attacks.",
                    "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS for all connections.",
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information"
                })

    # =====================================================
    # 2. DANGEROUS PERMISSIONS
    # =====================================================
    print("🔎 Analyzing permissions...")
    
    dangerous_permissions = {
        "android.permission.READ_SMS": "Can read all SMS messages (OTP theft risk)",
        "android.permission.SEND_SMS": "Can send SMS to premium numbers",
        "android.permission.RECORD_AUDIO": "Can record audio without user interaction",
        "android.permission.READ_CONTACTS": "Can read entire contact list",
        "android.permission.ACCESS_FINE_LOCATION": "Tracks precise GPS location",
        "android.permission.CAMERA": "Can access camera without permission",
        "android.permission.READ_PHONE_STATE": "Can read device IMEI and phone number"
    }

    app_permissions = a.get_permissions()
    dangerous_count = 0
    
    for perm, risk in dangerous_permissions.items():
        if perm in app_permissions:
            dangerous_count += 1
            _add_vulnerability(report, {
                "type": f"Dangerous Permission: {perm.split('.')[-1]}",
                "severity": "Medium",
                "owasp": "M1 (Improper Platform Usage)",
                "category": "Permissions",
                "details": f"The app requests {perm.split('.')[-1]}. {risk}",
                "remediation": "Remove this permission if not strictly necessary. Apply the principle of least privilege.",
                "cwe": "CWE-250: Execution with Unnecessary Privileges"
            })
    
    print(f"DEBUG: Found {dangerous_count} dangerous permissions")

    # =====================================================
    # 3. EXPORTED ACTIVITIES
    # =====================================================
    print("🔎 Checking exported components...")
    
    main_activity = a.get_main_activity()
    exported_count = 0
    
    for activity in a.get_activities():
        try:
            # Check if activity has intent filters (which makes it exported)
            intent_filters = a.get_intent_filters("activity", activity)
            
            if intent_filters:
                # Skip main launcher activity
                is_main_launcher = False
                for action, names in intent_filters.items():
                    if "android.intent.action.MAIN" in names:
                        is_main_launcher = True
                        break
                
                if not is_main_launcher:
                    exported_count += 1
                    _add_vulnerability(report, {
                        "type": "Improperly Exported Activity",
                        "severity": "Low",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Component Security",
                        "details": f"Activity '{activity}' is exported and can be launched by other apps.",
                        "remediation": "Set android:exported='false' unless external access is required.",
                        "cwe": "CWE-927: Use of Implicit Intent for Sensitive Communication"
                    })
        except Exception as e:
            print(f"DEBUG: Error checking activity {activity}: {e}")
            continue
    
    print(f"DEBUG: Found {exported_count} exported activities")

    # =====================================================
    # 4. HARDCODED SECRETS
    # =====================================================
    print("🔎 Scanning for hardcoded secrets...")
    
    patterns = {
        "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "Private Key": re.compile(r'BEGIN PRIVATE KEY'),
        "API Key": re.compile(r'(?i)(api_key|apikey)["\s:=]+(["\'][A-Za-z0-9\-_]{20,}["\'])'),
        "Password": re.compile(r'(?i)(password|passwd)["\s:=]+(["\'][A-Za-z0-9!@#$%^&*]{8,}["\'])')
    }

    strings = []
    for dex in d:
        # Limit to first 5000 strings per DEX to save memory
        dex_strings = list(dex.get_strings())
        strings.extend(dex_strings[:5000])
        if len(strings) > 10000:
            break

    print(f"DEBUG: Analyzing {len(strings)} strings")

    found_secrets = set()
    secret_count = 0

    for s in strings:
        if isinstance(s, str) and len(s) < 200:
            for name, pattern in patterns.items():
                if pattern.search(s):
                    if s not in found_secrets:
                        found_secrets.add(s)
                        secret_count += 1
                        _add_vulnerability(report, {
                            "type": f"Hardcoded {name}",
                            "severity": "Critical",
                            "owasp": "M9 (Reverse Engineering)",
                            "category": "Secrets Management",
                            "details": f"Found sensitive hardcoded string: '{s[:60]}...'",
                            "remediation": "Never hardcode secrets. Use environment variables or Android Keystore.",
                            "cwe": "CWE-798: Use of Hard-coded Credentials"
                        })
                        
                        # Limit to 5 secrets to save memory
                        if secret_count >= 5:
                            break
        
        if secret_count >= 5:
            break
    
    print(f"DEBUG: Found {secret_count} hardcoded secrets")

    # =====================================================
    # FINAL REPORT
    # =====================================================
    print("✓ Analysis complete!")
    print(f"DEBUG: Total vulnerabilities: {len(report['vulnerabilities'])}")
    print(f"DEBUG: Summary - Critical: {report['summary']['critical']}, High: {report['summary']['high']}, Medium: {report['summary']['medium']}, Low: {report['summary']['low']}")
    
    # Update total
    report["summary"]["total"] = len(report["vulnerabilities"])
    
    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    report["vulnerabilities"].sort(key=lambda x: severity_order.get(x["severity"], 4))

    return report


def _add_vulnerability(report, vuln_data):
    """Helper function to add vulnerability and update summary"""
    report["vulnerabilities"].append(vuln_data)
    severity = vuln_data["severity"].lower()
    if severity in report["summary"]:
        report["summary"][severity] += 1


def generate_report_text(report):
    """Generate human-readable text report"""
    if "error" in report:
        return f"❌ ERROR: {report['error']}"
    
    output = []
    output.append("=" * 80)
    output.append("🛡️  APK SECURITY ANALYSIS REPORT")
    output.append("=" * 80)
    output.append(f"📱 App Name:        {report['app_name']}")
    output.append(f"📦 Package:         {report['package_name']}")
    output.append(f"🔢 Version:         {report.get('version_name', 'Unknown')}")
    output.append(f"🎯 Target SDK:      {report.get('target_sdk', 'Unknown')}")
    output.append("=" * 80)
    output.append("")
    
    # Summary
    summary = report["summary"]
    output.append("📊 VULNERABILITY SUMMARY")
    output.append("-" * 80)
    output.append(f"🔴 Critical: {summary['critical']}")
    output.append(f"🟠 High:     {summary['high']}")
    output.append(f"🟡 Medium:   {summary['medium']}")
    output.append(f"🟢 Low:      {summary['low']}")
    output.append(f"📈 Total:    {summary['total']}")
    output.append("=" * 80)
    output.append("")
    
    # Vulnerabilities
    if report["vulnerabilities"]:
        output.append("🔍 DETAILED FINDINGS")
        output.append("=" * 80)
        
        for idx, vuln in enumerate(report["vulnerabilities"], 1):
            severity_emoji = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}
            
            output.append(f"\n[{idx}] {severity_emoji.get(vuln['severity'], '⚪')} {vuln['type']}")
            output.append(f"    Severity:     {vuln['severity']}")
            output.append(f"    OWASP:        {vuln['owasp']}")
            output.append(f"    Category:     {vuln.get('category', 'Security')}")
            if 'cwe' in vuln:
                output.append(f"    CWE:          {vuln['cwe']}")
            output.append(f"    Details:      {vuln['details']}")
            output.append(f"    Remediation:  {vuln['remediation']}")
            output.append("-" * 80)
    else:
        output.append("✅ No vulnerabilities detected!")
    
    output.append("\n" + "=" * 80)
    output.append("Report generated by APK Security Analyzer")
    output.append("=" * 80)
    
    return "\n".join(output)
