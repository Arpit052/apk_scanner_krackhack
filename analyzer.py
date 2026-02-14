from androguard.apk import APK
from androguard.dex import DalvikVMFormat
import re
import os
from collections import defaultdict

def analyze_apk(apk_path):
    """
    Optimized APK Security Analyzer
    Combines memory efficiency with comprehensive security checks
    """
    print(f"🔍 Scanning {apk_path}...")
    
    # --- OPTIMIZED LOADING ---
    try:
        a, d, dx = AnalyzeAPK(apk_path)  # ✅ CHANGED THIS LINE
        print("✓ APK loaded successfully")
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

    # =================================================================
    # 1. MANIFEST SECURITY CHECKS (OWASP M1, M2, M3, M7)
    # =================================================================
    print("🔎 Checking manifest security...")
    manifest_xml = a.get_android_manifest_xml()
    
    if manifest_xml is not None:
        application_tag = manifest_xml.find("application")
        if application_tag is not None:
            
            # --- Debuggable Check (OWASP M7) ---
            debuggable = application_tag.get("{http://schemas.android.com/apk/res/android}debuggable")
            if debuggable == "true":
                _add_vulnerability(report, {
                    "type": "App is Debuggable",
                    "severity": "High",
                    "owasp": "M7 (Client Code Quality)",
                    "category": "Configuration",
                    "details": "The application is marked as debuggable. Attackers can attach debuggers to extract sensitive runtime data, modify behavior, and bypass security controls.",
                    "remediation": "Set android:debuggable='false' in AndroidManifest.xml before releasing to production.",
                    "cwe": "CWE-489: Active Debug Code"
                })
            
            # --- AllowBackup Check (OWASP M2) ---
            allow_backup = application_tag.get("{http://schemas.android.com/apk/res/android}allowBackup")
            if allow_backup == "true" or allow_backup is None:
                _add_vulnerability(report, {
                    "type": "Application Data Backup Enabled",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": "android:allowBackup is enabled (default: true). An attacker with physical access or malware could extract app data via ADB backup, including databases, shared preferences, and files.",
                    "remediation": "Set android:allowBackup='false' in AndroidManifest.xml unless backup functionality is explicitly required.",
                    "cwe": "CWE-200: Exposure of Sensitive Information"
                })

            # --- Cleartext Traffic Check (OWASP M3) ---
            cleartext = application_tag.get("{http://schemas.android.com/apk/res/android}usesCleartextTraffic")
            if cleartext == "true":
                _add_vulnerability(report, {
                    "type": "Cleartext HTTP Traffic Allowed",
                    "severity": "Critical",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": "The app explicitly allows unencrypted HTTP communication, making it highly vulnerable to Man-in-the-Middle (MITM) attacks. Sensitive data transmitted over HTTP can be intercepted and modified.",
                    "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS for all network connections. Implement certificate pinning for critical APIs.",
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information"
                })
            
            # --- Network Security Config Check ---
            network_security_config = application_tag.get("{http://schemas.android.com/apk/res/android}networkSecurityConfig")
            if not network_security_config:
                _add_vulnerability(report, {
                    "type": "Missing Network Security Configuration",
                    "severity": "Low",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": "No custom network security configuration detected. Consider implementing certificate pinning and restricting cleartext traffic.",
                    "remediation": "Create network_security_config.xml to enforce HTTPS and implement certificate pinning.",
                    "cwe": "CWE-295: Improper Certificate Validation"
                })

    # =================================================================
    # 2. DANGEROUS PERMISSIONS ANALYSIS (OWASP M1)
    # =================================================================
    print("🔎 Analyzing permissions...")
    dangerous_permissions = {
        "android.permission.READ_SMS": {
            "risk": "Can read all SMS messages, including OTPs and sensitive communications.",
            "severity": "High"
        },
        "android.permission.SEND_SMS": {
            "risk": "Can send SMS messages, potentially to premium numbers.",
            "severity": "High"
        },
        "android.permission.RECEIVE_SMS": {
            "risk": "Can intercept incoming SMS messages.",
            "severity": "High"
        },
        "android.permission.ACCESS_FINE_LOCATION": {
            "risk": "Tracks precise user location (GPS-level accuracy).",
            "severity": "Medium"
        },
        "android.permission.ACCESS_COARSE_LOCATION": {
            "risk": "Tracks approximate user location (cell tower/WiFi-based).",
            "severity": "Medium"
        },
        "android.permission.READ_CONTACTS": {
            "risk": "Can read the user's entire contact list.",
            "severity": "Medium"
        },
        "android.permission.WRITE_CONTACTS": {
            "risk": "Can modify or delete contacts.",
            "severity": "Medium"
        },
        "android.permission.RECORD_AUDIO": {
            "risk": "Can record audio without explicit user interaction.",
            "severity": "High"
        },
        "android.permission.CAMERA": {
            "risk": "Can access camera and take photos/videos.",
            "severity": "Medium"
        },
        "android.permission.READ_CALL_LOG": {
            "risk": "Can read call history.",
            "severity": "Medium"
        },
        "android.permission.WRITE_CALL_LOG": {
            "risk": "Can modify call history.",
            "severity": "Medium"
        },
        "android.permission.READ_EXTERNAL_STORAGE": {
            "risk": "Can read files from external storage.",
            "severity": "Low"
        },
        "android.permission.WRITE_EXTERNAL_STORAGE": {
            "risk": "Can write files to external storage.",
            "severity": "Low"
        },
        "android.permission.GET_ACCOUNTS": {
            "risk": "Can access the list of accounts on the device.",
            "severity": "Low"
        },
        "android.permission.READ_PHONE_STATE": {
            "risk": "Can read device IMEI, phone number, and call state.",
            "severity": "Medium"
        }
    }
    
    app_permissions = a.get_permissions()
    for perm in app_permissions:
        if perm in dangerous_permissions:
            perm_info = dangerous_permissions[perm]
            _add_vulnerability(report, {
                "type": f"Dangerous Permission: {perm.split('.')[-1]}",
                "severity": perm_info["severity"],
                "owasp": "M1 (Improper Platform Usage)",
                "category": "Permissions",
                "details": f"The app requests '{perm}'. {perm_info['risk']}",
                "remediation": "Remove this permission if not strictly necessary. Apply the principle of least privilege. Request permissions at runtime and explain why they are needed.",
                "cwe": "CWE-250: Execution with Unnecessary Privileges"
            })

    # =================================================================
    # 3. EXPORTED COMPONENTS ANALYSIS (OWASP M1)
    # =================================================================
    print("🔎 Checking exported components...")
    
    # --- Exported Activities ---
    activities = a.get_activities()
    for activity in activities:
        try:
            intent_filters = a.get_intent_filters("activity", activity)
            if intent_filters:
                is_main_launcher = False
                for action, names in intent_filters.items():
                    if "android.intent.action.MAIN" in names:
                        is_main_launcher = True
                        break
                
                if not is_main_launcher:
                    _add_vulnerability(report, {
                        "type": "Improperly Exported Activity",
                        "severity": "Medium",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Component Security",
                        "details": f"Activity '{activity}' is exported and can be launched by other apps, potentially bypassing authentication or accessing sensitive functionality.",
                        "remediation": f"Set android:exported='false' for '{activity}' in AndroidManifest.xml unless external access is strictly required. Implement proper authorization checks.",
                        "cwe": "CWE-927: Use of Implicit Intent for Sensitive Communication"
                    })
        except Exception as e:
            continue
    
    # --- Exported Services ---
    services = a.get_services()
    for service in services:
        try:
            intent_filters = a.get_intent_filters("service", service)
            if intent_filters:
                _add_vulnerability(report, {
                    "type": "Improperly Exported Service",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Component Security",
                    "details": f"Service '{service}' is exported and can be accessed by other apps.",
                    "remediation": f"Set android:exported='false' for '{service}' unless inter-app communication is required.",
                    "cwe": "CWE-927: Use of Implicit Intent for Sensitive Communication"
                })
        except:
            continue
    
    # --- Exported Broadcast Receivers ---
    receivers = a.get_receivers()
    for receiver in receivers:
        try:
            intent_filters = a.get_intent_filters("receiver", receiver)
            if intent_filters:
                _add_vulnerability(report, {
                    "type": "Improperly Exported Broadcast Receiver",
                    "severity": "Low",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Component Security",
                    "details": f"Broadcast Receiver '{receiver}' is exported and can receive broadcasts from other apps.",
                    "remediation": f"Set android:exported='false' or use signature-level permissions to restrict access.",
                    "cwe": "CWE-927: Use of Implicit Intent for Sensitive Communication"
                })
        except:
            continue

    # =================================================================
    # 4. HARDCODED SECRETS DETECTION (OWASP M9)
    # =================================================================
    print("🔎 Scanning for hardcoded secrets...")
    
    # Enhanced regex patterns for secret detection
    patterns = {
        "AWS Access Key": re.compile(r'AKIA[0-9A-Z]{16}'),
        "AWS Secret Key": re.compile(r'aws_secret_access_key["\s:=]+["\']([a-zA-Z0-9/+=]{40})["\']', re.IGNORECASE),
        "Private Key": re.compile(r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----'),
        "API Key": re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']([a-zA-Z0-9\-_]{20,})["\']'),
        "Auth Token": re.compile(r'(?i)(auth[_-]?token|access[_-]?token|bearer)["\s:=]+["\']([a-zA-Z0-9\-_\.]{20,})["\']'),
        "Password": re.compile(r'(?i)(password|passwd|pwd)["\s:=]+["\']([a-zA-Z0-9!@#$%^&*]{8,})["\']'),
        "Secret": re.compile(r'(?i)(secret|client_secret)["\s:=]+["\']([a-zA-Z0-9\-_]{15,})["\']'),
        "Database URL": re.compile(r'(?i)(mongodb|mysql|postgres|postgresql)://[^\s"\']+:[^\s"\']+@'),
        "Firebase URL": re.compile(r'https://[a-z0-9\-]+\.firebaseio\.com'),
        "Google API Key": re.compile(r'AIza[0-9A-Za-z\-_]{35}'),
        "JWT Token": re.compile(r'eyJ[a-zA-Z0-9\-_]+\.eyJ[a-zA-Z0-9\-_]+\.[a-zA-Z0-9\-_]+'),
        "Slack Token": re.compile(r'xox[pboa]-[0-9]{12}-[0-9]{12}-[a-zA-Z0-9]{24}'),
        "GitHub Token": re.compile(r'gh[pousr]_[A-Za-z0-9_]{36,}'),
        "Stripe API Key": re.compile(r'sk_live_[0-9a-zA-Z]{24}')
    }
    
    found_secrets = set()
    secret_contexts = {}  # Store context for each secret
    
    for dex_idx, dex in enumerate(d):
        try:
            strings = dex.get_strings()
            for string_val in strings:
                # Optimize by skipping very long strings
                if not isinstance(string_val, str) or len(string_val) > 500:
                    continue
                
                # Skip common false positives
                if any(fp in string_val.lower() for fp in ['example', 'test', 'demo', 'sample', 'placeholder']):
                    continue
                
                for secret_name, pattern in patterns.items():
                    match = pattern.search(string_val)
                    if match:
                        # Create a unique identifier for this secret
                        secret_key = f"{secret_name}:{string_val[:50]}"
                        
                        if secret_key not in found_secrets:
                            found_secrets.add(secret_key)
                            
                            # Truncate for display
                            display_string = string_val[:60] + "..." if len(string_val) > 60 else string_val
                            
                            _add_vulnerability(report, {
                                "type": f"Hardcoded {secret_name}",
                                "severity": "Critical",
                                "owasp": "M9 (Reverse Engineering / M2 Insecure Data Storage)",
                                "category": "Secrets Management",
                                "details": f"Sensitive {secret_name.lower()} found hardcoded in DEX file #{dex_idx + 1}: '{display_string}'",
                                "remediation": "Never hardcode secrets in application code. Use environment variables, fetch from a secure backend API, or use Android Keystore for encryption keys. Consider using secret management solutions.",
                                "cwe": "CWE-798: Use of Hard-coded Credentials"
                            })
                            
                            # Limit findings to avoid memory issues
                            if len(found_secrets) >= 20:
                                break
                
                if len(found_secrets) >= 20:
                    break
        except Exception as e:
            print(f"⚠ Warning: Error scanning DEX #{dex_idx + 1}: {str(e)}")
            continue

    # =================================================================
    # 5. INSECURE CODE PATTERNS (OWASP M7, M2)
    # =================================================================
    print("🔎 Analyzing code patterns...")
    
    insecure_patterns = {
        "SQL Injection Risk": re.compile(r'execSQL|rawQuery', re.IGNORECASE),
        "WebView JavaScript Enabled": re.compile(r'setJavaScriptEnabled\(true\)', re.IGNORECASE),
        "Insecure Random": re.compile(r'java\.util\.Random'),
        "Weak Crypto (DES/MD5/SHA1)": re.compile(r'(DES|MD5|SHA-1|SHA1)'),
        "File Permission Worldreadable": re.compile(r'MODE_WORLD_READABLE|MODE_WORLD_WRITEABLE'),
        "WebView addJavascriptInterface": re.compile(r'addJavascriptInterface'),
        "Insecure SSL/TLS": re.compile(r'SSLContext\.getInstance\(["\']SSL["\']|TLS')
    }
    
    pattern_findings = defaultdict(int)
    
    for dex in d:
        try:
            strings = dex.get_strings()
            for string_val in strings:
                if not isinstance(string_val, str) or len(string_val) > 300:
                    continue
                
                for pattern_name, pattern in insecure_patterns.items():
                    if pattern.search(string_val):
                        pattern_findings[pattern_name] += 1
        except:
            continue
    
    # Report patterns found multiple times (likely actual usage)
    for pattern_name, count in pattern_findings.items():
        if count >= 2:  # Only report if found at least twice
            severity = "High" if pattern_name in ["SQL Injection Risk", "File Permission Worldreadable"] else "Medium"
            
            _add_vulnerability(report, {
                "type": f"Insecure Code Pattern: {pattern_name}",
                "severity": severity,
                "owasp": "M7 (Client Code Quality)",
                "category": "Code Security",
                "details": f"Detected usage of {pattern_name} ({count} occurrences). This may indicate insecure coding practices.",
                "remediation": f"Review code for proper usage of {pattern_name}. Follow secure coding guidelines.",
                "cwe": "CWE-676: Use of Potentially Dangerous Function"
            })

    # =================================================================
    # FINAL REPORT ASSEMBLY
    # =================================================================
    print("✓ Analysis complete!")
    
    # Calculate summary
    report["summary"]["total"] = len(report["vulnerabilities"])
    
    # Sort vulnerabilities by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    report["vulnerabilities"].sort(key=lambda x: severity_order.get(x["severity"], 4))
    
    return report


def _add_vulnerability(report, vuln_data):
    """Helper function to add vulnerability and update summary"""
    report["vulnerabilities"].append(vuln_data)
    severity = vuln_data["severity"]
    report["summary"][severity.lower()] += 1


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
    output.append(f"🔢 Version:         {report['version_name']} (Code: {report['version_code']})")
    output.append(f"🎯 Target SDK:      {report['target_sdk']} (Min: {report['min_sdk']})")
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
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢"
            }
            
            output.append(f"\n[{idx}] {severity_emoji.get(vuln['severity'], '⚪')} {vuln['type']}")
            output.append(f"    Severity:     {vuln['severity']}")
            output.append(f"    OWASP:        {vuln['owasp']}")
            output.append(f"    Category:     {vuln['category']}")
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


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python apk_analyzer_optimized.py <path_to_apk>")
        sys.exit(1)
    
    apk_path = sys.argv[1]
    
    if not os.path.exists(apk_path):
        print(f"❌ Error: APK file not found: {apk_path}")
        sys.exit(1)
    
    # Analyze APK
    report = analyze_apk(apk_path)
    
    # Generate and print report
    print("\n")
    print(generate_report_text(report))
    
    # Optionally save to file
    output_file = f"{report['package_name']}_security_report.txt"
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write(generate_report_text(report))
    
    print(f"\n💾 Report saved to: {output_file}")
