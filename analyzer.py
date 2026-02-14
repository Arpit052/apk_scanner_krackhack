#!/usr/bin/env python3
"""
Fast & Accurate APK Security Analyzer
Uses pyaxmlparser for speed + targeted vulnerability detection
"""

import zipfile
import re
import os
from collections import defaultdict
from pyaxmlparser import APK
import xml.etree.ElementTree as ET


class APKSecurityAnalyzer:
    """Fast APK security analysis using pyaxmlparser"""
    
    # Android namespace
    NS = {'android': 'http://schemas.android.com/apk/res/android'}
    
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.report = {
            "app_name": "Unknown",
            "package_name": "Unknown",
            "version_name": "Unknown",
            "version_code": "Unknown",
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
            "vulnerabilities": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
            }
        }
        
    def analyze(self):
        """Main analysis entry point"""
        print(f"🔍 Analyzing: {self.apk_path}")
        
        try:
            self.apk = APK(self.apk_path)
            print("✓ APK loaded successfully")
        except Exception as e:
            self.report["error"] = f"Failed to parse APK: {str(e)}"
            return self.report
        
        # Extract basic info
        self._extract_app_info()
        
        # Run security checks
        print("🔎 Running security checks...")
        self._check_manifest_security()
        self._check_permissions()
        self._check_exported_components()
        self._check_hardcoded_secrets()
        self._check_code_vulnerabilities()
        self._check_native_libraries()
        
        # Finalize report
        self._finalize_report()
        print("✅ Analysis complete!")
        
        return self.report
    
    def _extract_app_info(self):
        """Extract basic app information"""
        try:
            self.report["app_name"] = self.apk.application or "Unknown"
            self.report["package_name"] = self.apk.package or "Unknown"
            self.report["version_name"] = self.apk.version_name or "Unknown"
            self.report["version_code"] = self.apk.version_code or "Unknown"
            self.report["min_sdk"] = self.apk.min_sdk_version or "Unknown"
            self.report["target_sdk"] = self.apk.target_sdk_version or "Unknown"
        except Exception as e:
            print(f"⚠️  Warning: Could not extract app info - {e}")
    
    def _check_manifest_security(self):
        """Check AndroidManifest.xml for security issues"""
        try:
            # Parse manifest XML
            manifest_xml = self.apk.get_android_manifest_xml()
            root = ET.fromstring(manifest_xml)
            
            # Find application tag
            app_tag = root.find('.//application')
            if app_tag is None:
                return
            
            # Check debuggable
            debuggable = app_tag.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
            if debuggable.lower() == 'true':
                self._add_vuln({
                    "type": "Application is Debuggable",
                    "severity": "Critical",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": "App is marked as debuggable. Attackers can attach debuggers, extract sensitive data, and modify app behavior at runtime.",
                    "remediation": "Remove android:debuggable='true' from AndroidManifest.xml before production release.",
                    "cwe": "CWE-489"
                })
            
            # Check allowBackup
            allow_backup = app_tag.get('{http://schemas.android.com/apk/res/android}allowBackup')
            if allow_backup is None or allow_backup.lower() == 'true':
                self._add_vuln({
                    "type": "Backup Enabled (Data Exposure Risk)",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": "android:allowBackup is enabled (default behavior). App data can be extracted via 'adb backup' by attackers with physical access or malware.",
                    "remediation": "Set android:allowBackup='false' unless explicitly needed. Use android:fullBackupContent to control what gets backed up.",
                    "cwe": "CWE-200"
                })
            
            # Check cleartext traffic
            cleartext = app_tag.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            target_sdk = int(self.report["target_sdk"]) if str(self.report["target_sdk"]).isdigit() else 28
            
            # Default is 'false' for API 28+, 'true' for older
            if cleartext is None:
                if target_sdk < 28:
                    self._add_vuln({
                        "type": "Cleartext Traffic Allowed (Default)",
                        "severity": "High",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": f"App targets SDK {target_sdk} where cleartext HTTP is allowed by default. Vulnerable to man-in-the-middle attacks.",
                        "remediation": "Set android:usesCleartextTraffic='false' and enforce HTTPS for all connections.",
                        "cwe": "CWE-319"
                    })
            elif cleartext.lower() == 'true':
                self._add_vuln({
                    "type": "Cleartext Traffic Explicitly Allowed",
                    "severity": "Critical",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": "App explicitly allows unencrypted HTTP traffic. All network communication is vulnerable to interception and tampering.",
                    "remediation": "Set android:usesCleartextTraffic='false'. Use HTTPS only. Implement certificate pinning for sensitive APIs.",
                    "cwe": "CWE-319"
                })
            
            # Check network security config
            nsc = app_tag.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
            if not nsc:
                if target_sdk >= 24:
                    self._add_vuln({
                        "type": "Missing Network Security Configuration",
                        "severity": "Low",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": "No custom network security config detected. Missing opportunity for certificate pinning and traffic restrictions.",
                        "remediation": "Implement network_security_config.xml with certificate pinning for critical domains.",
                        "cwe": "CWE-295"
                    })
            
            # Check for testOnly
            test_only = app_tag.get('{http://schemas.android.com/apk/res/android}testOnly', 'false')
            if test_only.lower() == 'true':
                self._add_vuln({
                    "type": "Test-Only Build in Production",
                    "severity": "High",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": "App is marked as testOnly but distributed. This may contain debug code or bypass security checks.",
                    "remediation": "Remove android:testOnly='true' before production release.",
                    "cwe": "CWE-489"
                })
            
        except Exception as e:
            print(f"⚠️  Manifest check error: {e}")
    
    def _check_permissions(self):
        """Analyze dangerous permissions"""
        dangerous_perms = {
            'android.permission.READ_SMS': ('Critical', 'Can read all SMS including OTP codes'),
            'android.permission.SEND_SMS': ('Critical', 'Can send SMS to premium numbers'),
            'android.permission.RECEIVE_SMS': ('High', 'Can intercept incoming SMS'),
            'android.permission.READ_CALL_LOG': ('High', 'Can read call history'),
            'android.permission.WRITE_CALL_LOG': ('High', 'Can modify call history'),
            'android.permission.PROCESS_OUTGOING_CALLS': ('High', 'Can monitor outgoing calls'),
            'android.permission.RECORD_AUDIO': ('High', 'Can record audio without user knowledge'),
            'android.permission.CAMERA': ('Medium', 'Can access camera'),
            'android.permission.READ_CONTACTS': ('Medium', 'Can read contact list'),
            'android.permission.WRITE_CONTACTS': ('Medium', 'Can modify contacts'),
            'android.permission.ACCESS_FINE_LOCATION': ('Medium', 'Can track precise location (GPS)'),
            'android.permission.ACCESS_COARSE_LOCATION': ('Low', 'Can track approximate location'),
            'android.permission.READ_PHONE_STATE': ('Medium', 'Can read IMEI and phone number'),
            'android.permission.GET_ACCOUNTS': ('Low', 'Can access device accounts'),
            'android.permission.READ_EXTERNAL_STORAGE': ('Low', 'Can read files from storage'),
            'android.permission.WRITE_EXTERNAL_STORAGE': ('Low', 'Can write files to storage'),
            'android.permission.SYSTEM_ALERT_WINDOW': ('High', 'Can draw over other apps (phishing risk)'),
            'android.permission.BIND_DEVICE_ADMIN': ('Critical', 'Can gain device admin privileges'),
            'android.permission.REQUEST_INSTALL_PACKAGES': ('High', 'Can install other apps'),
            'android.permission.PACKAGE_USAGE_STATS': ('Medium', 'Can monitor app usage'),
        }
        
        try:
            permissions = self.apk.permissions or []
            
            for perm in permissions:
                if perm in dangerous_perms:
                    severity, risk = dangerous_perms[perm]
                    perm_name = perm.split('.')[-1]
                    
                    self._add_vuln({
                        "type": f"Dangerous Permission: {perm_name}",
                        "severity": severity,
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Permissions",
                        "details": f"App requests '{perm}'. {risk}. Verify this is actually needed.",
                        "remediation": "Remove if unnecessary. Request at runtime with clear justification. Apply principle of least privilege.",
                        "cwe": "CWE-250"
                    })
            
        except Exception as e:
            print(f"⚠️  Permission check error: {e}")
    
    def _check_exported_components(self):
        """Check for improperly exported components"""
        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            root = ET.fromstring(manifest_xml)
            
            # Check activities
            for activity in root.findall('.//activity'):
                exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = activity.find('intent-filter')
                name = activity.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                
                # If has intent-filter, default is exported=true
                if intent_filter is not None:
                    # Check if it's NOT the main launcher
                    is_launcher = False
                    for action in intent_filter.findall('action'):
                        action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                        if action_name == 'android.intent.action.MAIN':
                            is_launcher = True
                            break
                    
                    if not is_launcher and (exported is None or exported.lower() == 'true'):
                        self._add_vuln({
                            "type": "Exported Activity Without Protection",
                            "severity": "High",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Activity '{name}' is exported and can be launched by any app, potentially bypassing authentication.",
                            "remediation": f"Set android:exported='false' or add permission protection. Validate all inputs.",
                            "cwe": "CWE-927"
                        })
            
            # Check services
            for service in root.findall('.//service'):
                exported = service.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = service.find('intent-filter')
                name = service.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                permission = service.get('{http://schemas.android.com/apk/res/android}permission')
                
                if intent_filter is not None or (exported and exported.lower() == 'true'):
                    if not permission:
                        self._add_vuln({
                            "type": "Exported Service Without Permission",
                            "severity": "High",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Service '{name}' is exported without permission protection. Can be accessed by malicious apps.",
                            "remediation": "Set android:exported='false' or require signature-level permission.",
                            "cwe": "CWE-927"
                        })
            
            # Check receivers
            for receiver in root.findall('.//receiver'):
                exported = receiver.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = receiver.find('intent-filter')
                name = receiver.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                
                if intent_filter is not None and (exported is None or exported.lower() == 'true'):
                    priority = intent_filter.get('{http://schemas.android.com/apk/res/android}priority', '0')
                    if int(priority) > 500:
                        self._add_vuln({
                            "type": "High-Priority Broadcast Receiver",
                            "severity": "Medium",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Receiver '{name}' has high priority ({priority}) and is exported. Can intercept broadcasts.",
                            "remediation": "Reduce priority or set android:exported='false'. Use local broadcasts when possible.",
                            "cwe": "CWE-927"
                        })
            
            # Check content providers
            for provider in root.findall('.//provider'):
                exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
                name = provider.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                grant_uri = provider.get('{http://schemas.android.com/apk/res/android}grantUriPermissions', 'false')
                
                if exported and exported.lower() == 'true':
                    self._add_vuln({
                        "type": "Exported Content Provider",
                        "severity": "Critical",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Component Security",
                        "details": f"Content Provider '{name}' is exported. Other apps can read/write app data.",
                        "remediation": "Set android:exported='false' unless data sharing is required. Implement proper access controls.",
                        "cwe": "CWE-200"
                    })
                
                if grant_uri.lower() == 'true':
                    self._add_vuln({
                        "type": "Insecure URI Grant Permissions",
                        "severity": "Medium",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Component Security",
                        "details": f"Provider '{name}' grants URI permissions. Ensure proper path validation.",
                        "remediation": "Restrict grantUriPermissions scope. Use path-permission tags to limit access.",
                        "cwe": "CWE-732"
                    })
                    
        except Exception as e:
            print(f"⚠️  Component check error: {e}")
    
    def _check_hardcoded_secrets(self):
        """Scan for hardcoded secrets in strings and resources"""
        secrets_found = set()
        max_secrets = 10
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Check strings.xml files
                for file_name in apk_zip.namelist():
                    if 'strings.xml' in file_name or file_name.endswith('.xml'):
                        try:
                            content = apk_zip.read(file_name).decode('utf-8', errors='ignore')
                            secrets_found.update(self._scan_for_secrets(content, file_name))
                            if len(secrets_found) >= max_secrets:
                                break
                        except:
                            continue
                
                # Check classes.dex strings (lightweight scan)
                if len(secrets_found) < max_secrets:
                    for file_name in apk_zip.namelist():
                        if file_name.endswith('.dex'):
                            try:
                                content = apk_zip.read(file_name)
                                # Extract printable strings
                                strings = re.findall(b'[ -~]{10,}', content)
                                for s in strings[:1000]:  # Limit to first 1000 strings
                                    try:
                                        string_val = s.decode('utf-8')
                                        secrets_found.update(self._scan_for_secrets(string_val, file_name))
                                        if len(secrets_found) >= max_secrets:
                                            break
                                    except:
                                        continue
                            except:
                                continue
                            if len(secrets_found) >= max_secrets:
                                break
        
        except Exception as e:
            print(f"⚠️  Secret scanning error: {e}")
    
    def _scan_for_secrets(self, content, source_file):
        """Scan content for potential secrets"""
        found = set()
        
        # Skip test/example content
        if any(skip in content.lower() for skip in ['example.com', 'test', 'demo', 'sample', 'placeholder']):
            return found
        
        patterns = {
            'AWS Access Key': r'AKIA[0-9A-Z]{16}',
            'Generic API Key': r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9\-_]{32,})["\']',
            'Authorization Token': r'["\']?authorization["\']?\s*[:=]\s*["\']?(Bearer\s+[a-zA-Z0-9\-_\.]+)["\']?',
            'Private Key Header': r'-----BEGIN (RSA |EC |DSA )?PRIVATE KEY-----',
            'Firebase URL': r'https://[a-z0-9-]+\.firebaseio\.com',
            'Google API Key': r'AIza[0-9A-Za-z\-_]{35}',
            'Slack Token': r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}',
            'Stripe Key': r'sk_live_[0-9a-zA-Z]{24,}',
        }
        
        for secret_type, pattern in patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(0)
                
                # Skip if too short or looks fake
                if len(secret_value) < 20:
                    continue
                
                secret_key = f"{secret_type}:{secret_value[:40]}"
                if secret_key not in found:
                    found.add(secret_key)
                    
                    display_val = secret_value[:50] + "..." if len(secret_value) > 50 else secret_value
                    
                    self._add_vuln({
                        "type": f"Hardcoded {secret_type}",
                        "severity": "Critical",
                        "owasp": "M9 (Reverse Engineering)",
                        "category": "Secrets Management",
                        "details": f"Found hardcoded {secret_type.lower()}: '{display_val}' in {source_file}",
                        "remediation": "Never hardcode secrets. Use Android Keystore, encrypted SharedPreferences, or secure backend API.",
                        "cwe": "CWE-798"
                    })
        
        return found
    
    def _check_code_vulnerabilities(self):
        """Check for common code-level vulnerabilities"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Sample DEX strings for vulnerability indicators
                for file_name in apk_zip.namelist():
                    if file_name.endswith('.dex'):
                        try:
                            content = apk_zip.read(file_name)
                            strings = re.findall(b'[ -~]{10,}', content)
                            
                            indicators = {
                                'SQL Injection Risk': [b'SELECT', b'INSERT', b'UPDATE', b'DELETE', b'WHERE', b'rawQuery'],
                                'WebView Security': [b'setJavaScriptEnabled', b'addJavascriptInterface'],
                                'Weak Crypto': [b'DES', b'MD5', b'SHA1', b'ECB'],
                                'Insecure Random': [b'java.util.Random', b'Math.random'],
                                'Root Detection': [b'su', b'/system/xbin/su', b'com.noshufou.android.su'],
                            }
                            
                            found_indicators = defaultdict(int)
                            
                            for s in strings[:2000]:  # Limit scan
                                for vuln_type, patterns in indicators.items():
                                    for pattern in patterns:
                                        if pattern in s:
                                            found_indicators[vuln_type] += 1
                            
                            # Report based on indicators
                            if found_indicators.get('SQL Injection Risk', 0) > 3:
                                self._add_vuln({
                                    "type": "Potential SQL Injection Vulnerability",
                                    "severity": "High",
                                    "owasp": "M7 (Code Quality)",
                                    "category": "Code Security",
                                    "details": "App uses SQL queries. Ensure all user inputs are properly sanitized and use parameterized queries.",
                                    "remediation": "Use Room database or parameterized queries. Never concatenate user input into SQL.",
                                    "cwe": "CWE-89"
                                })
                            
                            if found_indicators.get('WebView Security', 0) > 0:
                                self._add_vuln({
                                    "type": "WebView JavaScript Interface Risk",
                                    "severity": "High",
                                    "owasp": "M1 (Improper Platform Usage)",
                                    "category": "Code Security",
                                    "details": "App uses WebView with JavaScript enabled. Vulnerable to XSS if loading untrusted content.",
                                    "remediation": "Disable JavaScript if not needed. Validate all URLs. Use @JavascriptInterface annotation carefully.",
                                    "cwe": "CWE-79"
                                })
                            
                            if found_indicators.get('Weak Crypto', 0) > 2:
                                self._add_vuln({
                                    "type": "Weak Cryptographic Algorithms Detected",
                                    "severity": "High",
                                    "owasp": "M5 (Insufficient Cryptography)",
                                    "category": "Cryptography",
                                    "details": "App may use weak algorithms like DES, MD5, or SHA1. These are cryptographically broken.",
                                    "remediation": "Use AES-256 for encryption, SHA-256+ for hashing. Avoid ECB mode. Use Android Keystore.",
                                    "cwe": "CWE-327"
                                })
                            
                            if found_indicators.get('Insecure Random', 0) > 0:
                                self._add_vuln({
                                    "type": "Insecure Random Number Generation",
                                    "severity": "Medium",
                                    "owasp": "M5 (Insufficient Cryptography)",
                                    "category": "Cryptography",
                                    "details": "App uses java.util.Random or Math.random() which are predictable. Not suitable for security.",
                                    "remediation": "Use java.security.SecureRandom for all cryptographic operations.",
                                    "cwe": "CWE-338"
                                })
                            
                            break  # Only check first DEX file
                            
                        except:
                            continue
                            
        except Exception as e:
            print(f"⚠️  Code vulnerability check error: {e}")
    
    def _check_native_libraries(self):
        """Check for insecure native libraries"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                native_libs = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]
                
                if native_libs:
                    # Check for common architectures
                    archs = set()
                    for lib in native_libs:
                        parts = lib.split('/')
                        if len(parts) > 1:
                            archs.add(parts[1])
                    
                    # Info about native code
                    if len(native_libs) > 0:
                        self._add_vuln({
                            "type": f"Native Code Present ({len(native_libs)} libraries)",
                            "severity": "Info",
                            "owasp": "M7 (Code Quality)",
                            "category": "Code Security",
                            "details": f"App contains native libraries for: {', '.join(archs)}. Native code is harder to analyze and may contain vulnerabilities.",
                            "remediation": "Ensure native libraries are from trusted sources. Keep them updated. Consider RASP protection.",
                            "cwe": "CWE-937"
                        })
                        
        except Exception as e:
            print(f"⚠️  Native library check error: {e}")
    
    def _add_vuln(self, vuln_data):
        """Add vulnerability to report and update summary"""
        self.report["vulnerabilities"].append(vuln_data)
        severity = vuln_data["severity"].lower()
        if severity in self.report["summary"]:
            self.report["summary"][severity] += 1
    
    def _finalize_report(self):
        """Finalize report with sorting and totals"""
        self.report["summary"]["total"] = len(self.report["vulnerabilities"])
        
        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.report["vulnerabilities"].sort(
            key=lambda x: severity_order.get(x["severity"], 5)
        )


def generate_report_text(report):
    """Generate human-readable text report"""
    if "error" in report:
        return f"❌ ERROR: {report['error']}"
    
    lines = []
    lines.append("=" * 80)
    lines.append("🛡️  APK SECURITY ANALYSIS REPORT")
    lines.append("=" * 80)
    lines.append(f"📱 App Name:        {report['app_name']}")
    lines.append(f"📦 Package:         {report['package_name']}")
    lines.append(f"🔢 Version:         {report['version_name']} (Code: {report['version_code']})")
    lines.append(f"🎯 Target SDK:      {report['target_sdk']} (Min: {report['min_sdk']})")
    lines.append("=" * 80)
    lines.append("")
    
    summary = report["summary"]
    lines.append("📊 VULNERABILITY SUMMARY")
    lines.append("-" * 80)
    lines.append(f"🔴 Critical: {summary['critical']}")
    lines.append(f"🟠 High:     {summary['high']}")
    lines.append(f"🟡 Medium:   {summary['medium']}")
    lines.append(f"🟢 Low:      {summary['low']}")
    lines.append(f"ℹ️  Info:     {summary['info']}")
    lines.append(f"📈 Total:    {summary['total']}")
    lines.append("=" * 80)
    lines.append("")
    
    if report["vulnerabilities"]:
        lines.append("🔍 DETAILED FINDINGS")
        lines.append("=" * 80)
        
        severity_icons = {
            "Critical": "🔴",
            "High": "🟠",
            "Medium": "🟡",
            "Low": "🟢",
            "Info": "ℹ️"
        }
        
        for idx, vuln in enumerate(report["vulnerabilities"], 1):
            icon = severity_icons.get(vuln['severity'], '⚪')
            
            lines.append(f"\n[{idx}] {icon} {vuln['type']}")
            lines.append(f"    Severity:     {vuln['severity']}")
            lines.append(f"    OWASP:        {vuln['owasp']}")
            lines.append(f"    Category:     {vuln['category']}")
            if 'cwe' in vuln:
                lines.append(f"    CWE:          {vuln['cwe']}")
            lines.append(f"    Details:      {vuln['details']}")
            lines.append(f"    Remediation:  {vuln['remediation']}")
            lines.append("-" * 80)
    else:
        lines.append("✅ No major vulnerabilities detected!")
        lines.append("")
        lines.append("Note: This is a static analysis. Manual code review and dynamic testing")
        lines.append("are recommended for comprehensive security assessment.")
    
    lines.append("\n" + "=" * 80)
    lines.append("⚡ Powered by pyaxmlparser | Fast & Accurate APK Analysis")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def analyze_apk(apk_path):
    """Main entry point for APK analysis"""
    analyzer = APKSecurityAnalyzer(apk_path)
    report = analyzer.analyze()
    return report


# Example usage
if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python apk_security_analyzer.py <path_to_apk>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"❌ File not found: {apk_file}")
        sys.exit(1)
    
    print(f"🚀 Starting APK Security Analysis")
    print(f"📁 Target: {apk_file}\n")
    
    report = analyze_apk(apk_file)
    
    # Generate and print report
    report_text = generate_report_text(report)
    print("\n" + report_text)
    
    # Optionally save to file
    output_file = f"{os.path.basename(apk_file)}_security_report.txt"
    with open(output_file, 'w') as f:
        f.write(report_text)
    
    print(f"\n💾 Report saved to: {output_file}")
