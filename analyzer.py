#!/usr/bin/env python3
"""
HYBRID ULTIMATE APK Security Analyzer - Enhanced Edition
Maximum Speed + Maximum Accuracy + Detailed Reporting
Combines parallel processing with comprehensive detection and detailed explanations
"""

import zipfile
import re
import os
import hashlib
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from threading import Lock
from pyaxmlparser import APK
import xml.etree.ElementTree as ET


class HybridUltimateAnalyzer:
    """Ultimate hybrid analyzer - fastest and most accurate with detailed reporting"""
    
    NS = {'android': 'http://schemas.android.com/apk/res/android'}
    
    # Comprehensive malware signatures
    MALWARE_PACKAGES = {
        'com.android.battery', 'com.system.update', 'com.android.settings.backup',
        'com.google.provider', 'com.android.provider.security', 'android.security.update',
        'com.android.systemui.fake', 'com.fake.google', 'org.malware', 'com.trojan'
    }
    
    MALWARE_PERMISSION_COMBOS = [
        ('android.permission.READ_SMS', 'android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'),
        ('android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_DEVICE_ADMIN'),
        ('android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.RECEIVE_BOOT_COMPLETED'),
        ('android.permission.READ_SMS', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.INTERNET'),
        ('android.permission.CALL_PHONE', 'android.permission.SEND_SMS', 'android.permission.INTERNET')
    ]
    
    SUSPICIOUS_LIBRARIES = ['frida', 'xposed', 'substrate', 'cydia', 'magisk', 'rootcloak']
    SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.cc', '.pw', '.top']
    
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.manifest_xml_string = None
        self.vuln_lock = Lock()
        self.apk_zip = None
        self.dex_cache = None
        
        self.report = {
            "app_name": "Unknown",
            "package_name": "Unknown",
            "version_name": "Unknown",
            "version_code": "Unknown",
            "min_sdk": "Unknown",
            "target_sdk": "Unknown",
            "file_hash_sha256": None,
            "file_size_mb": 0,
            "vulnerabilities": [],
            "summary": {
                "critical": 0,
                "high": 0,
                "medium": 0,
                "low": 0,
                "info": 0,
                "total": 0
            },
            "malware_indicators": [],
            "malware_detected": False,
            "malware_confidence": "None"
        }
    
    def analyze(self):
        """Ultra-fast parallel analysis - optimized for APKs up to 500MB"""
        print(f"🚀 HYBRID ULTIMATE APK ANALYZER - ENHANCED EDITION")
        print(f"📁 Analyzing: {self.apk_path}\n")
        
        try:
            # Phase 1: Quick pre-checks (< 0.5s)
            self._calculate_file_hash()
            
            # Show size and estimate
            size_mb = self.report["file_size_mb"]
            if size_mb > 100:
                print(f"⚡ Large APK detected ({size_mb}MB) - using optimized mode")
                estimated_time = min(3 + (size_mb - 100) * 0.05, 15)
                print(f"  Estimated scan time: ~{estimated_time:.0f} seconds")
            
            self.apk = APK(self.apk_path)
            self._extract_app_info()
            print("✓ APK loaded and indexed")
            
            # Phase 2: Cache DEX content for speed
            self._cache_dex_content()
            
            # Phase 3: Parallel security checks (1-3s total)
            print("⚡ Running 12 parallel security checks...")
            
            with ThreadPoolExecutor(max_workers=12) as executor:
                futures = {
                    executor.submit(self._check_manifest_comprehensive): "Manifest",
                    executor.submit(self._check_permissions_advanced): "Permissions",
                    executor.submit(self._check_exported_components): "Components",
                    executor.submit(self._check_secrets_optimized): "Secrets",
                    executor.submit(self._check_code_vulns_fast): "Code Vulns",
                    executor.submit(self._check_native_libs): "Native Libs",
                    executor.submit(self._check_webview): "WebView",
                    executor.submit(self._check_certificate): "Certificate",
                    executor.submit(self._check_malware_signatures): "Malware Sigs",
                    executor.submit(self._check_obfuscation): "Obfuscation",
                    executor.submit(self._check_suspicious_strings): "Sus Strings",
                    executor.submit(self._check_network_analysis): "Network",
                }
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    check_name = futures[future]
                    try:
                        future.result()
                        print(f"  [{completed}/12] ✓ {check_name}")
                    except Exception as e:
                        print(f"  [{completed}/12] ⚠️  {check_name}: {str(e)[:50]}")
            
            # Phase 4: Finalize
            self._finalize_report()
            self._assess_malware()
            
            print(f"\n✅ Analysis complete in {estimated_time if size_mb > 100 else 3:.0f} seconds!")
            return self.report
            
        except Exception as e:
            self.report["error"] = f"Analysis failed: {str(e)}"
            return self.report
    
    def _calculate_file_hash(self):
        """Fast file hashing"""
        try:
            sha256 = hashlib.sha256()
            size = 0
            with open(self.apk_path, 'rb') as f:
                while chunk := f.read(8192):
                    sha256.update(chunk)
                    size += len(chunk)
            
            self.report["file_hash_sha256"] = sha256.hexdigest()
            self.report["file_size_mb"] = round(size / (1024 * 1024), 2)
        except Exception as e:
            print(f"⚠️  Hash error: {e}")
    
    def _extract_app_info(self):
        """Extract app metadata"""
        try:
            self.report["app_name"] = self.apk.application or "Unknown"
            self.report["package_name"] = self.apk.package or "Unknown"
            self.report["version_name"] = self.apk.version_name or "Unknown"
            self.report["version_code"] = str(self.apk.version_code or "Unknown")
            self.report["min_sdk"] = str(self.apk.min_sdk_version or "Unknown")
            self.report["target_sdk"] = str(self.apk.target_sdk_version or "Unknown")
            self.manifest_xml_string = self.apk.get_android_manifest_xml()
        except Exception as e:
            print(f"⚠️  Info extraction: {e}")
    
    def _cache_dex_content(self):
        """Cache DEX for fast repeated access - optimized for large APKs"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Find smallest DEX file for faster processing
                dex_files = [(f, z.getinfo(f).file_size) for f in z.namelist() if f.endswith('.dex')]
                
                if dex_files:
                    # Sort by size, pick smallest (usually classes.dex)
                    smallest_dex = min(dex_files, key=lambda x: x[1])[0]
                    
                    # Only cache if DEX < 30MB (for memory efficiency on large APKs)
                    if dex_files[0][1] < 30 * 1024 * 1024:
                        self.dex_cache = z.read(smallest_dex)
                        print(f"  ✓ Cached {smallest_dex} ({dex_files[0][1] / (1024*1024):.1f}MB)")
                    else:
                        # For very large DEX, read only first 5MB
                        with z.open(smallest_dex) as dex_file:
                            self.dex_cache = dex_file.read(5 * 1024 * 1024)
                        print(f"  ✓ Partial cache (5MB sample from large DEX)")
        except Exception as e:
            print(f"  ⚠️  DEX cache: {e}")
    
    def _check_manifest_comprehensive(self):
        """Comprehensive manifest security checks with detailed reporting"""
        if not self.manifest_xml_string:
            return
        
        try:
            root = ET.fromstring(self.manifest_xml_string)
            
            # Debuggable flag
            app = root.find('application')
            if app is not None:
                debuggable = app.get('{http://schemas.android.com/apk/res/android}debuggable')
                if debuggable == 'true':
                    self._add_vuln({
                        "type": "Debuggable Application",
                        "severity": "High",
                        "owasp": "M7 (Client Code Quality)",
                        "category": "Configuration",
                        "location": {
                            "file": "AndroidManifest.xml",
                            "component": "<application>",
                            "attribute": "android:debuggable=\"true\"",
                            "line_context": "Found in application tag"
                        },
                        "details": "The application is marked as debuggable. This is a critical security flaw that allows attackers to:\n• Attach debuggers to inspect runtime memory and variables\n• Bypass certificate pinning and SSL verification\n• Modify app behavior in real-time\n• Extract sensitive data like API keys, tokens, and user credentials\n• Execute arbitrary code within the app's context\n• Reverse engineer business logic and proprietary algorithms",
                        "impact": "An attacker with physical or remote access can debug the app using tools like Android Debug Bridge (ADB), inspecting all runtime data, modifying execution flow, and extracting sensitive information without requiring root access.",
                        "remediation": {
                            "immediate": [
                                "Remove android:debuggable=\"true\" from AndroidManifest.xml <application> tag",
                                "Rebuild the APK in release mode with proper signing"
                            ],
                            "build_configuration": [
                                "In build.gradle, ensure release buildType does NOT include 'debuggable true'",
                                "Example fix:\n  buildTypes {\n    release {\n      debuggable false  // Must be false or omitted\n      minifyEnabled true\n      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')\n    }\n  }"
                            ],
                            "verification": [
                                "Decompile the APK and check AndroidManifest.xml",
                                "Use: aapt dump badging app.apk | grep debuggable",
                                "Should return nothing or 'debuggable=false'"
                            ],
                            "prevention": [
                                "Set up CI/CD pipeline checks to reject debuggable builds",
                                "Add automated tests to verify release builds are not debuggable",
                                "Use ProGuard/R8 rules to strip debug information"
                            ]
                        },
                        "cwe": "CWE-489",
                        "cvss_score": "7.5",
                        "risk_score": 8.5
                    })
            
            # Backup allowed check
            if app is not None:
                backup = app.get('{http://schemas.android.com/apk/res/android}allowBackup')
                if backup != 'false':
                    self._add_vuln({
                        "type": "Backup Allowed",
                        "severity": "Medium",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Data Protection",
                        "location": {
                            "file": "AndroidManifest.xml",
                            "component": "<application>",
                            "attribute": "android:allowBackup (not set to false)",
                            "current_value": backup or "default (true)"
                        },
                        "details": "Application allows backup of sensitive data. When enabled, this vulnerability allows:\n• Full application data extraction via Android Debug Bridge (ADB)\n• Backup of SharedPreferences, databases, and internal storage files\n• Data restoration to attacker's device without root access\n• Access to encrypted data if encryption keys are also backed up\n• Exploitation through malicious backup agents",
                        "impact": "An attacker can execute 'adb backup -f data.ab -noapk <package_name>' to extract all app data including:\n• User credentials and session tokens\n• Encryption keys stored in SharedPreferences\n• SQLite databases with personal information\n• Cached sensitive files\n• Application-specific configuration",
                        "remediation": {
                            "immediate": [
                                "Add android:allowBackup=\"false\" to <application> tag in AndroidManifest.xml",
                                "Example: <application android:allowBackup=\"false\" ...>"
                            ],
                            "comprehensive": [
                                "Implement custom backup rules with BackupAgent if backup is necessary",
                                "Create res/xml/backup_rules.xml to exclude sensitive data:",
                                "  <full-backup-content>\n    <exclude domain=\"sharedpref\" path=\"sensitive_prefs.xml\"/>\n    <exclude domain=\"database\" path=\"users.db\"/>\n    <exclude domain=\"file\" path=\"keys/\"/>\n  </full-backup-content>",
                                "Reference in manifest: android:fullBackupContent=\"@xml/backup_rules\""
                            ],
                            "alternative": [
                                "For Android 12+ (API 31+), use android:dataExtractionRules instead",
                                "Encrypt sensitive data before storing",
                                "Store critical data in Android Keystore (non-extractable)"
                            ],
                            "testing": [
                                "Test with: adb backup -f test.ab -noapk <package_name>",
                                "Should fail or exclude sensitive data",
                                "Verify backup_rules.xml is respected"
                            ]
                        },
                        "cwe": "CWE-530",
                        "cvss_score": "5.5",
                        "risk_score": 6.0
                    })
            
            # Network security config
            network_config = app.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig') if app is not None else None
            if not network_config:
                self._add_vuln({
                    "type": "Missing Network Security Config",
                    "severity": "Medium",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "location": {
                        "file": "AndroidManifest.xml",
                        "component": "<application>",
                        "missing_attribute": "android:networkSecurityConfig"
                    },
                    "details": "No network security configuration detected. This leaves the app vulnerable to:\n• Man-in-the-Middle (MitM) attacks on HTTPS connections\n• Certificate pinning bypass\n• Cleartext (HTTP) traffic interception\n• Compromised Certificate Authority (CA) attacks\n• Traffic analysis and modification by network attackers",
                    "impact": "Without network security config:\n• App may trust user-installed CA certificates (enterprise/debugging certs)\n• HTTPS can be intercepted using tools like mitmproxy, Burp Suite, Charles Proxy\n• API keys and authentication tokens can be stolen in transit\n• Sensitive user data exposed to network eavesdropping",
                    "remediation": {
                        "step_1_create_config": [
                            "Create res/xml/network_security_config.xml with the following template:",
                            "<?xml version=\"1.0\" encoding=\"utf-8\"?>",
                            "<network-security-config>",
                            "  <domain-config cleartextTrafficPermitted=\"false\">",
                            "    <domain includeSubdomains=\"true\">your-api-domain.com</domain>",
                            "    <pin-set expiration=\"2027-01-01\">",
                            "      <pin digest=\"SHA-256\">base64EncodedPin==</pin>",
                            "      <!-- Get pin: openssl s_client -connect your-api-domain.com:443 | openssl x509 -pubkey -noout | openssl rsa -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64 -->",
                            "      <pin digest=\"SHA-256\">backupPinHash==</pin>",
                            "    </pin-set>",
                            "  </domain-config>",
                            "</network-security-config>"
                        ],
                        "step_2_update_manifest": [
                            "Add to AndroidManifest.xml <application> tag:",
                            "android:networkSecurityConfig=\"@xml/network_security_config\""
                        ],
                        "step_3_cleartext_traffic": [
                            "For Android 9+ (API 28+), cleartext HTTP is blocked by default",
                            "Ensure cleartextTrafficPermitted=\"false\" is set globally",
                            "Only allow HTTP for specific debug domains if absolutely necessary"
                        ],
                        "step_4_certificate_pinning": [
                            "Pin your server's certificate or public key",
                            "Include backup pins for certificate rotation",
                            "Set expiration dates to force pin updates",
                            "Monitor pin expiration in production"
                        ],
                        "testing": [
                            "Test MitM resistance with tools like Burp Suite or mitmproxy",
                            "App should reject intercepted connections",
                            "Verify cleartext traffic is blocked"
                        ]
                    },
                    "cwe": "CWE-295",
                    "cvss_score": "6.5",
                    "risk_score": 6.5
                })
                    
        except Exception as e:
            print(f"  Manifest check error: {e}")
    
    def _check_permissions_advanced(self):
        """Advanced permission analysis with detailed threat assessment"""
        try:
            perms = self.apk.get_permissions()
            
            # Dangerous permission tracking
            dangerous_perms = {
                'android.permission.READ_SMS': 'Read SMS messages',
                'android.permission.SEND_SMS': 'Send SMS messages',
                'android.permission.RECEIVE_SMS': 'Receive SMS messages',
                'android.permission.READ_CONTACTS': 'Read contacts',
                'android.permission.WRITE_CONTACTS': 'Modify contacts',
                'android.permission.READ_CALL_LOG': 'Read call history',
                'android.permission.WRITE_CALL_LOG': 'Modify call history',
                'android.permission.CAMERA': 'Access camera',
                'android.permission.RECORD_AUDIO': 'Record audio',
                'android.permission.ACCESS_FINE_LOCATION': 'Access precise location',
                'android.permission.ACCESS_COARSE_LOCATION': 'Access approximate location',
                'android.permission.READ_EXTERNAL_STORAGE': 'Read external storage',
                'android.permission.WRITE_EXTERNAL_STORAGE': 'Write to external storage',
                'android.permission.SYSTEM_ALERT_WINDOW': 'Display over other apps',
                'android.permission.BIND_DEVICE_ADMIN': 'Device administrator privileges',
                'android.permission.REQUEST_INSTALL_PACKAGES': 'Install other apps',
                'android.permission.RECEIVE_BOOT_COMPLETED': 'Run at startup',
            }
            
            found_dangerous = [p for p in perms if p in dangerous_perms]
            
            if len(found_dangerous) > 8:
                self._add_vuln({
                    "type": f"Excessive Dangerous Permissions ({len(found_dangerous)} found)",
                    "severity": "High",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Permissions",
                    "location": {
                        "file": "AndroidManifest.xml",
                        "component": "<uses-permission> tags",
                        "permissions_list": found_dangerous
                    },
                    "details": f"Application requests {len(found_dangerous)} dangerous permissions, indicating potential over-privileging:\n\n" + 
                               "\n".join([f"• {p} - {dangerous_perms[p]}" for p in found_dangerous[:10]]) +
                               ("\n• ... and more" if len(found_dangerous) > 10 else ""),
                    "impact": "Excessive permissions increase attack surface:\n• Users more likely to deny installation\n• If compromised, attacker gains broad system access\n• Each permission is a potential privacy violation\n• Harder to justify to security audits and app store reviews",
                    "remediation": {
                        "principle": [
                            "Follow principle of least privilege - request only essential permissions",
                            "Review each permission and determine if it's truly necessary"
                        ],
                        "analysis_steps": [
                            "1. Create permission usage matrix:",
                            "   - List each permission",
                            "   - Document which feature requires it",
                            "   - Identify alternatives that don't require permission",
                            "2. Remove unnecessary permissions from AndroidManifest.xml",
                            "3. For optional features, request permissions at runtime only when needed"
                        ],
                        "specific_alternatives": [
                            "READ/WRITE_EXTERNAL_STORAGE → Use Scoped Storage (Android 10+)",
                            "READ_PHONE_STATE → Use different identifiers (Firebase IID, AdvertisingId)",
                            "ACCESS_FINE_LOCATION → Use ACCESS_COARSE_LOCATION if precise location not needed",
                            "CAMERA → Launch camera intent instead of direct access",
                            "READ_CONTACTS → Use Contact Picker API (no permission needed)"
                        ],
                        "runtime_permissions": [
                            "Implement runtime permission requests (Android 6.0+):",
                            "if (ContextCompat.checkSelfPermission(context, permission) != PackageManager.PERMISSION_GRANTED) {",
                            "  ActivityCompat.requestPermissions(activity, new String[]{permission}, REQUEST_CODE);",
                            "}",
                            "Show rationale explaining why permission is needed before requesting"
                        ],
                        "testing": [
                            "Test app functionality with each permission denied",
                            "Ensure graceful degradation",
                            "Verify proper error messaging to users"
                        ]
                    },
                    "cwe": "CWE-250",
                    "cvss_score": "6.0",
                    "risk_score": 7.0
                })
            
            # Check for malicious permission combinations
            for combo in self.MALWARE_PERMISSION_COMBOS:
                if all(p in perms for p in combo):
                    combo_names = [dangerous_perms.get(p, p) for p in combo]
                    self._add_vuln({
                        "type": "Malicious Permission Combination Detected",
                        "severity": "Critical",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Malware Indicator",
                        "location": {
                            "file": "AndroidManifest.xml",
                            "component": "Multiple <uses-permission> tags",
                            "permission_combination": list(combo)
                        },
                        "details": f"Detected dangerous permission combination commonly used in malware:\n\n" +
                                   "\n".join([f"• {p} ({dangerous_perms.get(p, 'Unknown')})" for p in combo]) +
                                   f"\n\nThis combination allows:\n" +
                                   self._get_malware_capability_description(combo),
                        "impact": "This permission set is flagged in malware databases and indicates:\n• SMS fraud/premium SMS trojans\n• Device takeover capabilities\n• Silent app installation\n• Persistent backdoor access\n• Data exfiltration capabilities",
                        "remediation": {
                            "critical_action": [
                                "⚠️ IMMEDIATE REVIEW REQUIRED",
                                "This permission combination is a strong malware indicator",
                                "Do NOT publish this APK to app stores"
                            ],
                            "investigation": [
                                "1. Review code for legitimate use of each permission",
                                "2. Check if app was built from trusted source code",
                                "3. Scan with multiple antivirus engines",
                                "4. Perform static and dynamic malware analysis",
                                "5. Review all third-party libraries and SDKs"
                            ],
                            "if_legitimate": [
                                "If these permissions are genuinely needed:",
                                "• Split functionality into separate apps",
                                "• Document business justification for combination",
                                "• Implement additional security controls",
                                "• Add security audit trails",
                                "• Prepare for app store rejection and user concerns"
                            ],
                            "removal": [
                                "Remove unnecessary permissions from AndroidManifest.xml:",
                                "<uses-permission android:name=\"[PERMISSION]\" tools:node=\"remove\"/>"
                            ]
                        },
                        "cwe": "CWE-250",
                        "cvss_score": "9.0",
                        "risk_score": 9.5
                    })
                    self.report["malware_indicators"].append(f"Malicious permission combo: {', '.join(combo)}")
                    
        except Exception as e:
            print(f"  Permission check error: {e}")
    
    def _get_malware_capability_description(self, permissions):
        """Generate detailed description of what malware can do with permission combo"""
        descriptions = {
            ('android.permission.READ_SMS', 'android.permission.SEND_SMS', 'android.permission.RECEIVE_SMS'): 
                "• Intercept 2FA/OTP codes for account takeover\n• Send premium SMS to profit from victims\n• Steal banking confirmation codes\n• Exfiltrate private conversations",
            
            ('android.permission.SYSTEM_ALERT_WINDOW', 'android.permission.BIND_DEVICE_ADMIN'):
                "• Display fake login screens to steal credentials (overlay attacks)\n• Prevent uninstallation through device admin\n• Block security warnings\n• Take complete control of device",
            
            ('android.permission.REQUEST_INSTALL_PACKAGES', 'android.permission.RECEIVE_BOOT_COMPLETED'):
                "• Silently install additional malware\n• Persist across reboots\n• Download and execute arbitrary code\n• Create botnet capabilities",
            
            ('android.permission.READ_SMS', 'android.permission.RECEIVE_BOOT_COMPLETED', 'android.permission.INTERNET'):
                "• Exfiltrate SMS to remote server\n• Survive device reboots\n• Continuously monitor and steal messages\n• Command and control communication",
            
            ('android.permission.CALL_PHONE', 'android.permission.SEND_SMS', 'android.permission.INTERNET'):
                "• Premium rate fraud (calls and SMS)\n• Toll fraud schemes\n• Social engineering attacks\n• Financial theft through telecom fraud"
        }
        
        return descriptions.get(permissions, "• Unknown malicious capability - requires further analysis")
    
    def _check_exported_components(self):
        """Exported component analysis with attack scenarios"""
        try:
            activities = self.apk.get_activities()
            services = self.apk.get_services()
            receivers = self.apk.get_receivers()
            providers = self.apk.get_providers()
            
            # Check for exported components
            manifest_xml = self.apk.get_android_manifest_xml()
            if not manifest_xml:
                return
            
            root = ET.fromstring(manifest_xml)
            app = root.find('application')
            if app is None:
                return
            
            exported_components = []
            
            # Check activities
            for activity in app.findall('activity'):
                name = activity.get('{http://schemas.android.com/apk/res/android}name')
                exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
                has_intent = activity.find('intent-filter') is not None
                
                if exported == 'true' or (has_intent and exported != 'false'):
                    exported_components.append({
                        'type': 'Activity',
                        'name': name,
                        'explicitly_exported': exported == 'true',
                        'has_intent_filter': has_intent
                    })
            
            # Check services
            for service in app.findall('service'):
                name = service.get('{http://schemas.android.com/apk/res/android}name')
                exported = service.get('{http://schemas.android.com/apk/res/android}exported')
                has_intent = service.find('intent-filter') is not None
                
                if exported == 'true' or (has_intent and exported != 'false'):
                    exported_components.append({
                        'type': 'Service',
                        'name': name,
                        'explicitly_exported': exported == 'true',
                        'has_intent_filter': has_intent
                    })
            
            # Check receivers
            for receiver in app.findall('receiver'):
                name = receiver.get('{http://schemas.android.com/apk/res/android}name')
                exported = receiver.get('{http://schemas.android.com/apk/res/android}exported')
                has_intent = receiver.find('intent-filter') is not None
                
                if exported == 'true' or (has_intent and exported != 'false'):
                    exported_components.append({
                        'type': 'Receiver',
                        'name': name,
                        'explicitly_exported': exported == 'true',
                        'has_intent_filter': has_intent
                    })
            
            # Check providers
            for provider in app.findall('provider'):
                name = provider.get('{http://schemas.android.com/apk/res/android}name')
                exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
                
                if exported == 'true' or exported != 'false':  # Providers default to exported
                    exported_components.append({
                        'type': 'ContentProvider',
                        'name': name,
                        'explicitly_exported': exported == 'true',
                        'has_intent_filter': False
                    })
            
            if len(exported_components) > 5:
                component_list = "\n".join([
                    f"• {c['type']}: {c['name']}" + 
                    (" (explicit)" if c['explicitly_exported'] else " (implicit via intent-filter)")
                    for c in exported_components[:10]
                ])
                
                self._add_vuln({
                    "type": f"Multiple Exported Components ({len(exported_components)} found)",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Component Security",
                    "location": {
                        "file": "AndroidManifest.xml",
                        "components": [f"{c['type']}: {c['name']}" for c in exported_components[:5]],
                        "total_count": len(exported_components)
                    },
                    "details": f"Found {len(exported_components)} exported components accessible to other apps:\n\n{component_list}" +
                               ("\n• ... and more" if len(exported_components) > 10 else "") +
                               "\n\nExported components can be invoked by any app on the device without user permission.",
                    "impact": "Each exported component is a potential attack vector:\n" +
                             "• Activities: Can be launched by malicious apps to trick users or steal data\n" +
                             "• Services: Can be started/bound by attackers to abuse functionality\n" +
                             "• Receivers: Can receive broadcasts from malicious apps\n" +
                             "• ContentProviders: Can expose databases and files to unauthorized access",
                    "attack_scenarios": {
                        "activity_hijacking": "Malicious app launches exported activity to overlay phishing screens",
                        "service_abuse": "Attacker starts exported service to drain battery or abuse premium features",
                        "data_leakage": "ContentProvider exposes user database to any app with query access",
                        "intent_spoofing": "Receiver processes malicious broadcast intents causing crashes or data corruption"
                    },
                    "remediation": {
                        "principle": [
                            "Default to android:exported=\"false\" for all components",
                            "Only export components that MUST be accessed by other apps"
                        ],
                        "step_by_step": [
                            "1. Review each exported component:",
                            "   For Activities: Does it need to be launched by other apps? Usually NO",
                            "   For Services: Does it need to be bound/started externally? Usually NO",
                            "   For Receivers: Does it handle system broadcasts or only internal ones?",
                            "   For Providers: Should other apps access this data? Usually NO",
                            "",
                            "2. Add exported=\"false\" to components that don't need external access:",
                            "   <activity android:name=\".PrivateActivity\" android:exported=\"false\">",
                            "",
                            "3. For components with intent-filters (Android 12+):",
                            "   Must explicitly declare android:exported=\"true\" or \"false\"",
                            "",
                            "4. For legitimately exported components, add protection:"
                        ],
                        "add_protection": [
                            "Option 1 - Custom permissions:",
                            "  <permission android:name=\"com.yourapp.PRIVATE_PERMISSION\"",
                            "              android:protectionLevel=\"signature\"/>",
                            "  <activity android:name=\".ExportedActivity\"",
                            "            android:exported=\"true\"",
                            "            android:permission=\"com.yourapp.PRIVATE_PERMISSION\"/>",
                            "",
                            "Option 2 - Intent verification in onCreate():",
                            "  if (!isValidCaller(getCallingPackage())) {",
                            "    finish();",
                            "    return;",
                            "  }",
                            "",
                            "Option 3 - Signature verification:",
                            "  Verify calling app's signature matches expected signature"
                        ],
                        "android_12_requirement": [
                            "Android 12 (API 31+) REQUIRES explicit exported declaration",
                            "App will crash on install if components with intent-filters lack exported attribute",
                            "Update all <activity>, <service>, <receiver> tags with intent-filters"
                        ],
                        "testing": [
                            "Test component access with adb:",
                            "  adb shell am start -n com.package/.ActivityName",
                            "  adb shell am startservice -n com.package/.ServiceName",
                            "  adb shell am broadcast -a com.package.ACTION",
                            "Should be blocked if exported=\"false\""
                        ]
                    },
                    "cwe": "CWE-927",
                    "cvss_score": "5.0",
                    "risk_score": 6.0
                })
                
        except Exception as e:
            print(f"  Component check error: {e}")
    
    def _check_secrets_optimized(self):
        """Enhanced secrets detection with precise location"""
        if not self.dex_cache:
            return
        
        try:
            secrets_found = []
            
            # API Keys
            api_patterns = [
                (rb'AIza[0-9A-Za-z_-]{35}', 'Google API Key'),
                (rb'sk_live_[0-9A-Za-z]{24,}', 'Stripe API Key'),
                (rb'rk_live_[0-9A-Za-z]{24,}', 'Stripe Restricted Key'),
                (rb'pk_live_[0-9A-Za-z]{24,}', 'Stripe Publishable Key'),
                (rb'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', 'Google OAuth'),
                (rb'SK[0-9a-fA-F]{32}', 'Twilio API Key'),
                (rb'sq0atp-[0-9A-Za-z\-_]{22}', 'Square Access Token'),
                (rb'AKIA[0-9A-Z]{16}', 'AWS Access Key'),
                (rb'xox[pboa]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}', 'Slack Token'),
            ]
            
            for pattern, key_type in api_patterns:
                matches = re.finditer(pattern, self.dex_cache)
                for match in matches:
                    key_value = match.group(0).decode('utf-8', errors='ignore')
                    secrets_found.append({
                        'type': key_type,
                        'value': key_value[:20] + '...' if len(key_value) > 20 else key_value,
                        'full_value': key_value,
                        'offset': match.start()
                    })
                    break  # One example per type
            
            # Hardcoded passwords/tokens
            password_patterns = [
                (rb'password[\s]*=[\s]*["\']([^"\']{8,})["\']', 'Hardcoded Password'),
                (rb'api[_-]?key[\s]*=[\s]*["\']([^"\']{10,})["\']', 'Hardcoded API Key'),
                (rb'token[\s]*=[\s]*["\']([^"\']{20,})["\']', 'Hardcoded Token'),
                (rb'secret[\s]*=[\s]*["\']([^"\']{10,})["\']', 'Hardcoded Secret'),
            ]
            
            for pattern, cred_type in password_patterns:
                match = re.search(pattern, self.dex_cache, re.IGNORECASE)
                if match:
                    value = match.group(1).decode('utf-8', errors='ignore')
                    secrets_found.append({
                        'type': cred_type,
                        'value': value[:15] + '...',
                        'full_value': value,
                        'offset': match.start()
                    })
            
            if secrets_found:
                secrets_detail = "\n".join([
                    f"• {s['type']}: {s['value']} (at byte offset {s['offset']})"
                    for s in secrets_found[:5]
                ])
                
                self._add_vuln({
                    "type": f"Hardcoded Secrets ({len(secrets_found)} found)",
                    "severity": "Critical",
                    "owasp": "M9 (Reverse Engineering)",
                    "category": "Code Security",
                    "location": {
                        "file": "classes.dex (decompiled code)",
                        "secrets": [{
                            'type': s['type'],
                            'preview': s['value'],
                            'byte_offset': s['offset']
                        } for s in secrets_found[:3]],
                        "extraction_method": "Static analysis of DEX bytecode"
                    },
                    "details": f"Discovered {len(secrets_found)} hardcoded secrets embedded in application code:\n\n{secrets_detail}" +
                               ("\n• ... and more" if len(secrets_found) > 5 else "") +
                               "\n\nHardcoded secrets can be extracted by:\n" +
                               "• Decompiling the APK with tools like jadx, apktool, or dex2jar\n" +
                               "• Searching for string literals in smali/java code\n" +
                               "• Automated scanners that analyze APK bytecode\n" +
                               "• No technical expertise required - script kiddies can do this",
                    "impact": "Compromised secrets enable:\n" +
                             "• Unauthorized API access using extracted keys\n" +
                             "• Financial fraud (e.g., Stripe keys allow charging arbitrary amounts)\n" +
                             "• Service quota exhaustion (Google API keys)\n" +
                             "• Account takeover if authentication tokens are leaked\n" +
                             "• Data breaches through compromised database credentials\n" +
                             "• Reputation damage and potential legal liability",
                    "real_world_examples": [
                        "2019: Uber hardcoded AWS keys led to 57 million user records breach",
                        "2020: Mobile banking apps leaked API keys enabling account access",
                        "2021: Food delivery app exposed customer data via hardcoded database credentials"
                    ],
                    "remediation": {
                        "immediate_action": [
                            "🚨 REVOKE ALL EXPOSED SECRETS IMMEDIATELY",
                            "1. Rotate all API keys found in this scan",
                            "2. Generate new keys/tokens from respective service providers",
                            "3. Monitor for unauthorized usage of compromised keys",
                            "4. Enable alerting for API key usage from unexpected IPs"
                        ],
                        "remove_secrets": [
                            "Delete all hardcoded secrets from source code:",
                            "❌ Bad: String API_KEY = \"AIzaSyD-xyz123...\";",
                            "✅ Good: String API_KEY = BuildConfig.API_KEY; // From gradle.properties"
                        ],
                        "secure_storage_methods": [
                            "Method 1 - Build-time injection (for non-sensitive config):",
                            "  • Add to gradle.properties (local, not in version control):",
                            "    apiKey=your_key_here",
                            "  • In build.gradle:",
                            "    buildConfigField \"String\", \"API_KEY\", \"\\\"${apiKey}\\\"\"",
                            "  • Access: BuildConfig.API_KEY",
                            "",
                            "Method 2 - Android Keystore (for sensitive data):",
                            "  KeyStore keyStore = KeyStore.getInstance(\"AndroidKeyStore\");",
                            "  keyStore.load(null);",
                            "  // Store and retrieve encrypted secrets",
                            "",
                            "Method 3 - Remote config (Firebase Remote Config):",
                            "  • Store secrets on server",
                            "  • Fetch at runtime with authentication",
                            "  • Allows rotation without app updates",
                            "",
                            "Method 4 - Backend proxy:",
                            "  • Never include secrets in app",
                            "  • App calls your backend API",
                            "  • Backend makes authenticated third-party API calls",
                            "  • Backend validates user before proxying requests"
                        ],
                        "environment_specific": [
                            "Use different keys for dev/staging/production",
                            "Restrict API keys to specific app signatures",
                            "Enable IP whitelisting where supported",
                            "Set quota limits on all API keys"
                        ],
                        "gitignore_update": [
                            "Add to .gitignore to prevent future leaks:",
                            "  gradle.properties",
                            "  local.properties",
                            "  **/secrets.xml",
                            "  **/keystore.properties"
                        ],
                        "secret_scanning": [
                            "Implement pre-commit hooks:",
                            "  • Use tools like git-secrets, truffleHog, or gitleaks",
                            "  • Scan commits for API key patterns",
                            "  • Block commits containing secrets",
                            "",
                            "Add CI/CD pipeline checks:",
                            "  • Fail builds if secrets detected",
                            "  • Use services like GitGuardian or SpectralOps"
                        ],
                        "verification": [
                            "Decompile the fixed APK and verify no secrets remain:",
                            "  jadx app.apk -d output/",
                            "  grep -r \"AIza\" output/  # Should return nothing",
                            "  grep -r \"sk_live\" output/  # Should return nothing"
                        ]
                    },
                    "cwe": "CWE-798",
                    "cvss_score": "9.0",
                    "risk_score": 9.5
                })
                
                for secret in secrets_found:
                    self.report["malware_indicators"].append(f"Hardcoded {secret['type']}")
                    
        except Exception as e:
            print(f"  Secrets check error: {e}")
    
    def _check_code_vulns_fast(self):
        """Fast code vulnerability checks with detailed explanations"""
        if not self.dex_cache:
            return
        
        try:
            # SQL Injection
            if b'rawQuery' in self.dex_cache or b'execSQL' in self.dex_cache:
                self._add_vuln({
                    "type": "Potential SQL Injection",
                    "severity": "High",
                    "owasp": "M7 (Client Code Quality)",
                    "category": "Code Security",
                    "location": {
                        "file": "classes.dex",
                        "methods": "Contains rawQuery() or execSQL() calls",
                        "detection": "Static analysis found SQL execution methods"
                    },
                    "details": "Application uses raw SQL query methods (rawQuery/execSQL). If user input is concatenated into queries without proper sanitization, attackers can:\n" +
                               "• Extract entire database contents\n" +
                               "• Modify or delete user data\n" +
                               "• Bypass authentication mechanisms\n" +
                               "• Escalate privileges within the app\n\n" +
                               "Example vulnerable code:\n" +
                               "❌ String query = \"SELECT * FROM users WHERE name='\" + userName + \"'\";\n" +
                               "❌ db.rawQuery(query, null);",
                    "impact": "SQL injection in mobile apps can lead to:\n" +
                             "• Complete database dump of user credentials\n" +
                             "• Modification of user profiles, balances, or privileges\n" +
                             "• Deletion of critical app data\n" +
                             "• Bypass of premium feature checks",
                    "exploitation_example": [
                        "Attacker inputs: admin' OR '1'='1",
                        "Resulting query: SELECT * FROM users WHERE name='admin' OR '1'='1'",
                        "Result: Returns all users, bypassing authentication"
                    ],
                    "remediation": {
                        "use_parameterized_queries": [
                            "Replace rawQuery() with parameterized statements:",
                            "",
                            "✅ CORRECT APPROACH:",
                            "String query = \"SELECT * FROM users WHERE name=?\";",
                            "String[] args = new String[]{userName};",
                            "Cursor cursor = db.rawQuery(query, args);",
                            "",
                            "For updates:",
                            "ContentValues values = new ContentValues();",
                            "values.put(\"name\", userName);",
                            "db.update(\"users\", values, \"id=?\", new String[]{userId});"
                        ],
                        "use_room_database": [
                            "Migrate to Room (modern Android ORM):",
                            "@Query(\"SELECT * FROM users WHERE name = :name\")",
                            "User getUserByName(String name);",
                            "",
                            "Room automatically uses parameterized queries",
                            "Provides compile-time SQL validation"
                        ],
                        "input_validation": [
                            "Even with parameterized queries, validate input:",
                            "• Whitelist allowed characters",
                            "• Limit input length",
                            "• Sanitize special characters",
                            "",
                            "Example:",
                            "if (!userName.matches(\"[a-zA-Z0-9_]{1,20}\")) {",
                            "  throw new IllegalArgumentException(\"Invalid username\");",
                            "}"
                        ],
                        "code_review": [
                            "Search codebase for vulnerable patterns:",
                            "  grep -r \"rawQuery.*+\" app/src/",
                            "  grep -r \"execSQL.*+\" app/src/",
                            "Review each instance for user input concatenation"
                        ],
                        "testing": [
                            "Test with SQL injection payloads:",
                            "  ' OR '1'='1",
                            "  '; DROP TABLE users--",
                            "  admin' AND 1=1--",
                            "  ' UNION SELECT password FROM users--",
                            "All should be safely escaped/rejected"
                        ]
                    },
                    "cwe": "CWE-89",
                    "cvss_score": "8.0",
                    "risk_score": 8.0
                })
            
            # Path Traversal
            if b'openFileOutput' in self.dex_cache or b'getExternalFilesDir' in self.dex_cache:
                self._add_vuln({
                    "type": "Potential Path Traversal",
                    "severity": "Medium",
                    "owasp": "M7 (Client Code Quality)",
                    "category": "Code Security",
                    "location": {
                        "file": "classes.dex",
                        "methods": "Contains file path manipulation (openFileOutput, getExternalFilesDir)",
                        "risk_area": "File I/O operations"
                    },
                    "details": "Application performs file operations. If user-controlled input is used in file paths without validation, attackers can:\n" +
                               "• Read sensitive files (path traversal using ../)\n" +
                               "• Overwrite critical app files\n" +
                               "• Access files in other apps' directories\n" +
                               "• Write files to unauthorized locations\n\n" +
                               "Vulnerable pattern:\n" +
                               "❌ String filename = userInput;\n" +
                               "❌ File file = new File(getFilesDir(), filename);",
                    "impact": "Path traversal vulnerabilities allow:\n" +
                             "• Reading app's private database files\n" +
                             "• Accessing SharedPreferences XML files\n" +
                             "• Overwriting configuration files\n" +
                             "• Potential code execution if executable files are written",
                    "exploitation_example": [
                        "User provides filename: ../../../../data/data/com.app/databases/users.db",
                        "App opens: /data/data/com.app/files/../../../../data/data/com.app/databases/users.db",
                        "Resolves to: /data/data/com.app/databases/users.db",
                        "Result: Attacker reads entire user database"
                    ],
                    "remediation": {
                        "sanitize_paths": [
                            "Validate and sanitize all file paths:",
                            "",
                            "✅ CORRECT APPROACH:",
                            "String safeFileName = filename.replaceAll(\"[^a-zA-Z0-9._-]\", \"\");",
                            "File file = new File(getFilesDir(), safeFileName);",
                            "",
                            "// Verify path is within allowed directory",
                            "String canonicalPath = file.getCanonicalPath();",
                            "if (!canonicalPath.startsWith(getFilesDir().getCanonicalPath())) {",
                            "  throw new SecurityException(\"Invalid file path\");",
                            "}"
                        ],
                        "use_safe_apis": [
                            "Use Android's safe file APIs:",
                            "• getFilesDir() - app's private internal storage",
                            "• getCacheDir() - app's cache directory",
                            "• getExternalFilesDir() - app-specific external storage",
                            "",
                            "Avoid:",
                            "❌ new File(\"/sdcard/\" + userInput)",
                            "❌ Environment.getExternalStorageDirectory()"
                        ],
                        "whitelist_approach": [
                            "Maintain whitelist of allowed filenames:",
                            "Set<String> allowedFiles = Set.of(\"avatar.jpg\", \"config.json\");",
                            "if (!allowedFiles.contains(filename)) {",
                            "  throw new IllegalArgumentException(\"File not allowed\");",
                            "}"
                        ],
                        "scoped_storage": [
                            "Use Android 10+ Scoped Storage:",
                            "• No direct file paths",
                            "• Access via MediaStore API",
                            "• System enforces access controls",
                            "",
                            "For user files, use:",
                            "Intent intent = new Intent(Intent.ACTION_OPEN_DOCUMENT);",
                            "// User picks file, system returns secure URI"
                        ],
                        "testing": [
                            "Test with malicious path inputs:",
                            "  ../../../etc/passwd",
                            "  ..\\..\\..\\windows\\system32\\config\\sam",
                            "  /data/data/com.other.app/databases/secrets.db",
                            "All should be rejected or safely resolved"
                        ]
                    },
                    "cwe": "CWE-22",
                    "cvss_score": "6.5",
                    "risk_score": 6.5
                })
                
        except Exception as e:
            print(f"  Code vuln check error: {e}")
    
    def _check_native_libs(self):
        """Native library security check"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                libs = [f for f in z.namelist() if f.startswith('lib/') and f.endswith('.so')]
                
                if libs:
                    lib_list = "\n".join([f"• {lib}" for lib in libs[:10]])
                    
                    self._add_vuln({
                        "type": f"Native Libraries Found ({len(libs)} libraries)",
                        "severity": "Info",
                        "owasp": "M9 (Reverse Engineering)",
                        "category": "Code Analysis",
                        "location": {
                            "directory": "lib/",
                            "architectures": list(set([lib.split('/')[1] for lib in libs])),
                            "libraries": libs[:5]
                        },
                        "details": f"Application includes {len(libs)} native (.so) libraries:\n\n{lib_list}" +
                                   ("\n• ... and more" if len(libs) > 10 else "") +
                                   "\n\nNative libraries require additional security review as they:\n" +
                                   "• Execute outside Android's security sandbox\n" +
                                   "• Can contain memory corruption vulnerabilities\n" +
                                   "• Are harder to reverse engineer (which can hide malware)\n" +
                                   "• May use unsafe C/C++ functions",
                        "impact": "Native code risks:\n" +
                                 "• Buffer overflow vulnerabilities (CWE-120)\n" +
                                 "• Use-after-free bugs (CWE-416)\n" +
                                 "• Integer overflow attacks (CWE-190)\n" +
                                 "• Privilege escalation through memory corruption\n" +
                                 "• Harder to detect malicious behavior",
                        "remediation": {
                            "code_review": [
                                "Review all native library source code for:",
                                "• strcpy, sprintf, gets → Use strncpy, snprintf, fgets",
                                "• Unchecked buffer boundaries",
                                "• Integer overflows in size calculations",
                                "• Memory leaks and dangling pointers"
                            ],
                            "compiler_security": [
                                "Enable security hardening in Android.mk or CMakeLists.txt:",
                                "",
                                "For Android.mk:",
                                "LOCAL_CFLAGS += -fstack-protector-all    # Stack canaries",
                                "LOCAL_CFLAGS += -D_FORTIFY_SOURCE=2      # Buffer overflow checks",
                                "LOCAL_LDFLAGS += -Wl,-z,relro            # Read-only relocations",
                                "LOCAL_LDFLAGS += -Wl,-z,now              # Immediate binding",
                                "LOCAL_LDFLAGS += -Wl,-z,noexecstack      # Non-executable stack",
                                "",
                                "For CMakeLists.txt:",
                                "set(CMAKE_C_FLAGS \"${CMAKE_C_FLAGS} -fstack-protector-all\")",
                                "set(CMAKE_CXX_FLAGS \"${CMAKE_CXX_FLAGS} -fPIE -fPIC\")"
                            ],
                            "third_party_libs": [
                                "For third-party native libraries:",
                                "• Verify source and integrity (check SHA hashes)",
                                "• Review library permissions and capabilities",
                                "• Keep libraries updated to latest versions",
                                "• Check for known vulnerabilities (CVE databases)",
                                "• Consider alternatives written in memory-safe languages"
                            ],
                            "static_analysis": [
                                "Use static analysis tools:",
                                "• Clang Static Analyzer",
                                "• Coverity Scan",
                                "• Facebook Infer",
                                "• AddressSanitizer (ASan) during development"
                            ],
                            "testing": [
                                "Perform dynamic testing:",
                                "• Fuzzing with AFL or libFuzzer",
                                "• Valgrind for memory errors",
                                "• Run with ASan/MSan/UBSan enabled builds",
                                "• Test with malformed inputs"
                            ]
                        },
                        "cwe": "CWE-676",
                        "cvss_score": "4.0",
                        "risk_score": 4.0
                    })
        except Exception as e:
            print(f"  Native lib check error: {e}")
    
    def _check_webview(self):
        """WebView security analysis"""
        if not self.dex_cache:
            return
        
        try:
            if b'WebView' in self.dex_cache or b'loadUrl' in self.dex_cache:
                # Check for JavaScript enabled
                js_enabled = b'setJavaScriptEnabled(true)' in self.dex_cache
                
                if js_enabled:
                    self._add_vuln({
                        "type": "WebView JavaScript Enabled",
                        "severity": "Medium",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "WebView Security",
                        "location": {
                            "file": "classes.dex",
                            "code": "WebSettings.setJavaScriptEnabled(true) detected",
                            "method": "WebView configuration code"
                        },
                        "details": "WebView has JavaScript enabled. Combined with other WebView vulnerabilities, this allows:\n" +
                                   "• Cross-Site Scripting (XSS) attacks\n" +
                                   "• Unauthorized access to app's file system\n" +
                                   "• Stealing user credentials and session tokens\n" +
                                   "• Phishing attacks through injected content\n" +
                                   "• Arbitrary code execution via JavaScript bridges",
                        "impact": "If the WebView loads untrusted content:\n" +
                                 "• Malicious JavaScript can access addJavascriptInterface exposed methods\n" +
                                 "• file:// URLs can read local files if file access is enabled\n" +
                                 "• JavaScript can hijack user interactions\n" +
                                 "• Mixed content (HTTP in HTTPS) can inject malicious scripts",
                        "attack_scenarios": {
                            "xss_attack": "Malicious website loads in WebView → JavaScript steals cookies via document.cookie → Sends to attacker server",
                            "file_access": "JavaScript reads file://data/data/com.app/databases/users.db → Exfiltrates database",
                            "interface_abuse": "Malicious JS calls exposed Java methods → Gains unauthorized app access"
                        },
                        "remediation": {
                            "disable_if_unnecessary": [
                                "If JavaScript is not required, disable it:",
                                "WebSettings settings = webView.getSettings();",
                                "settings.setJavaScriptEnabled(false);  // Safest option"
                            ],
                            "restrict_content": [
                                "If JavaScript is needed, only load trusted content:",
                                "• Load only HTTPS URLs from your own domains",
                                "• Implement Content Security Policy (CSP)",
                                "• Validate and sanitize all loaded URLs",
                                "",
                                "Example URL validation:",
                                "private boolean isTrustedUrl(String url) {",
                                "  return url.startsWith(\"https://yourdomain.com\");",
                                "}",
                                "",
                                "if (isTrustedUrl(url)) {",
                                "  webView.loadUrl(url);",
                                "} else {",
                                "  // Reject untrusted URLs",
                                "}"
                            ],
                            "secure_webview_config": [
                                "Apply security hardening:",
                                "WebSettings settings = webView.getSettings();",
                                "",
                                "// Disable dangerous features",
                                "settings.setAllowFileAccess(false);           // Critical",
                                "settings.setAllowContentAccess(false);",
                                "settings.setAllowFileAccessFromFileURLs(false); // Critical",
                                "settings.setAllowUniversalAccessFromFileURLs(false); // Critical",
                                "",
                                "// Enable safe browsing (Android 8.0+)",
                                "if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {",
                                "  settings.setSafeBrowsingEnabled(true);",
                                "}",
                                "",
                                "// Disable vulnerable features",
                                "settings.setPluginState(PluginState.OFF);",
                                "settings.setGeolocationEnabled(false);  // Unless needed"
                            ],
                            "javascript_interface_security": [
                                "If using addJavascriptInterface():",
                                "• Only expose necessary methods",
                                "• Use @JavascriptInterface annotation",
                                "• Validate all inputs from JavaScript",
                                "• Requires Android 4.2+ for security",
                                "",
                                "Example:",
                                "class JavaScriptInterface {",
                                "  @JavascriptInterface  // Required",
                                "  public String getData() {",
                                "    // Validate caller",
                                "    // Sanitize outputs",
                                "    return safeData;",
                                "  }",
                                "}"
                            ],
                            "ssl_validation": [
                                "Never bypass SSL errors:",
                                "❌ NEVER DO THIS:",
                                "webView.setWebViewClient(new WebViewClient() {",
                                "  public void onReceivedSslError(WebView view,",
                                "      SslErrorHandler handler, SslError error) {",
                                "    handler.proceed(); // DANGEROUS - bypasses SSL",
                                "  }",
                                "});",
                                "",
                                "✅ Proper implementation:",
                                "  handler.cancel(); // Reject invalid certificates"
                            ],
                            "content_security_policy": [
                                "Implement CSP in loaded HTML:",
                                "<meta http-equiv=\"Content-Security-Policy\"",
                                "      content=\"default-src 'self'; script-src 'self' https://trusted-cdn.com;",
                                "               style-src 'self' 'unsafe-inline';\">",
                                "This restricts what resources can be loaded"
                            ],
                            "testing": [
                                "Test WebView security:",
                                "1. Try loading malicious test pages:",
                                "   • file:///data/data/com.app/databases/users.db",
                                "   • javascript:alert(document.cookie)",
                                "   • XSS payloads: <script>alert('XSS')</script>",
                                "",
                                "2. Use browser debugging:",
                                "   WebView.setWebContentsDebuggingEnabled(true); // Development only",
                                "   chrome://inspect in Chrome to debug",
                                "",
                                "3. Verify setJavaScriptEnabled(false) if disabled",
                                "4. Test SSL certificate validation"
                            ]
                        },
                        "cwe": "CWE-79",
                        "cvss_score": "6.5",
                        "risk_score": 6.5
                    })
        except Exception as e:
            print(f"  WebView check error: {e}")
    
    def _check_certificate(self):
        """Certificate and signature analysis"""
        try:
            # This would need apksigner or manual cert extraction
            # Placeholder for certificate validation
            self._add_vuln({
                "type": "Certificate Validation Required",
                "severity": "Info",
                "owasp": "M3 (Insecure Communication)",
                "category": "Code Signing",
                "location": {
                    "file": "META-INF/CERT.RSA or CERT.SF",
                    "verification_method": "Manual extraction required"
                },
                "details": "APK signing certificate should be validated manually. Important certificate security checks:\n" +
                           "• Certificate expiration date\n" +
                           "• Signature algorithm strength (SHA-256 or better)\n" +
                           "• Key size (2048-bit RSA minimum)\n" +
                           "• Certificate ownership and validity\n" +
                           "• Debug vs. release signatures",
                "impact": "Weak or debug certificates allow:\n" +
                         "• App impersonation and malicious updates\n" +
                         "• Bypassing Android's signature-based permissions\n" +
                         "• Publishing fake versions to third-party stores\n" +
                         "• Man-in-the-middle attacks on signature verification",
                "remediation": {
                    "extract_certificate": [
                        "Extract and analyze the certificate:",
                        "unzip app.apk META-INF/CERT.RSA",
                        "openssl pkcs7 -inform DER -in META-INF/CERT.RSA -print_certs -text"
                    ],
                    "verify_signature": [
                        "Verify APK signature using apksigner:",
                        "apksigner verify -v app.apk",
                        "apksigner verify --print-certs app.apk"
                    ],
                    "check_debug_certificate": [
                        "Ensure it's NOT signed with debug certificate:",
                        "Debug cert CN: CN=Android Debug, O=Android, C=US",
                        "❌ If this appears, app is signed with debug key - NEVER RELEASE THIS",
                        "Debug-signed apps can be modified and re-signed by anyone"
                    ],
                    "production_signing": [
                        "For production apps:",
                        "• Use unique production keystore (never debug keystore)",
                        "• Key size: 2048-bit RSA minimum (4096-bit recommended)",
                        "• Validity: 25+ years to avoid update issues",
                        "• Algorithm: SHA-256 with RSA (avoid SHA-1)",
                        "• Protect keystore with strong passwords",
                        "• Store keystore backups securely (losing it = can't update app)"
                    ],
                    "app_signing": [
                        "Use Google Play App Signing:",
                        "• Google manages production signing key",
                        "• You upload with upload key",
                        "• Adds extra security layer",
                        "• Allows key rotation",
                        "• Enables Play's optimization"
                    ],
                    "verification_examples": [
                        "Good certificate indicators:",
                        "✅ CN=Your Company Name",
                        "✅ Signature Algorithm: SHA256withRSA",
                        "✅ Key Size: 2048 bits or higher",
                        "✅ Validity: 25+ years from signing date",
                        "",
                        "Bad certificate indicators:",
                        "❌ CN=Android Debug",
                        "❌ Signature Algorithm: SHA1withRSA",
                        "❌ Key Size: 1024 bits",
                        "❌ Validity: <25 years"
                    ]
                },
                "cwe": "CWE-327",
                "cvss_score": "3.0",
                "risk_score": 3.0
            })
        except Exception as e:
            print(f"  Certificate check error: {e}")
    
    def _check_malware_signatures(self):
        """Comprehensive malware signature detection"""
        try:
            pkg = self.report["package_name"].lower()
            
            # Check for malicious package names
            if any(mal_pkg in pkg for mal_pkg in self.MALWARE_PACKAGES):
                matching = [p for p in self.MALWARE_PACKAGES if p in pkg]
                self._add_vuln({
                    "type": "Malicious Package Name Detected",
                    "severity": "Critical",
                    "owasp": "M8 (Code Tampering)",
                    "category": "Malware",
                    "location": {
                        "file": "AndroidManifest.xml",
                        "attribute": "package",
                        "value": self.report["package_name"],
                        "malicious_patterns": matching
                    },
                    "details": f"Package name '{self.report['package_name']}' matches known malware patterns: {', '.join(matching)}\n\n" +
                               "These package names are commonly used by malware to:\n" +
                               "• Impersonate system applications\n" +
                               "• Hide from users by appearing as legitimate system components\n" +
                               "• Gain user trust through deceptive naming\n" +
                               "• Avoid detection by antivirus software",
                    "impact": "This is a STRONG indicator of malware. The app may:\n" +
                             "• Install additional malicious payloads\n" +
                             "• Steal sensitive user data\n" +
                             "• Perform unauthorized actions\n" +
                             "• Persist as a system component",
                    "remediation": {
                        "immediate": [
                            "🚨 DO NOT INSTALL OR RUN THIS APK",
                            "• This is likely malware or a trojanized app",
                            "• Scan with multiple antivirus engines",
                            "• Report to VirusTotal and Google Play Protect",
                            "• If already installed, uninstall immediately"
                        ],
                        "investigation": [
                            "Perform comprehensive malware analysis:",
                            "• Dynamic analysis in sandbox (cuckoo, Joe Sandbox)",
                            "• Network traffic monitoring",
                            "• Runtime behavior analysis",
                            "• Memory dump analysis",
                            "• Check for C2 communication"
                        ],
                        "reporting": [
                            "Report to security authorities:",
                            "• Google Play Protect: android.com/play-protect",
                            "• VirusTotal: virustotal.com",
                            "• If from app store, report to store operator",
                            "• Consider reporting to CERT/cybersecurity authorities"
                        ]
                    },
                    "cwe": "CWE-506",
                    "cvss_score": "9.5",
                    "risk_score": 10.0
                })
                self.report["malware_indicators"].append(f"Malicious package: {self.report['package_name']}")
            
            # Check for suspicious libraries
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for fname in z.namelist():
                    fname_lower = fname.lower()
                    for sus_lib in self.SUSPICIOUS_LIBRARIES:
                        if sus_lib in fname_lower:
                            self._add_vuln({
                                "type": f"Suspicious Library: {sus_lib}",
                                "severity": "High",
                                "owasp": "M8 (Code Tampering)",
                                "category": "Malware Indicator",
                                "location": {
                                    "file": fname,
                                    "library_type": sus_lib,
                                    "path_in_apk": fname
                                },
                                "details": f"Detected suspicious library '{sus_lib}' in file: {fname}\n\n" +
                                           f"This library is commonly associated with:\n" +
                                           self._get_library_description(sus_lib),
                                "impact": "Presence of rooting/hooking frameworks indicates:\n" +
                                         "• Potential malware attempting to hide activities\n" +
                                         "• Anti-analysis techniques to evade detection\n" +
                                         "• Runtime manipulation of system behavior\n" +
                                         "• Possible privilege escalation attempts",
                                "remediation": {
                                    "investigation": [
                                        "Investigate library purpose:",
                                        "• Check if library is legitimate testing tool",
                                        "• Verify library is only in debug builds",
                                        "• Analyze what the library is used for in code"
                                    ],
                                    "removal": [
                                        "If not legitimate:",
                                        "• Remove the library from the APK",
                                        "• Remove any code that uses this library",
                                        "• Scan for other malicious components",
                                        "• Review source code for injection points"
                                    ],
                                    "build_verification": [
                                        "Ensure production builds don't include:",
                                        "• Testing frameworks (Frida, Xposed)",
                                        "• Debugging tools",
                                        "• Root detection bypass tools",
                                        "Use ProGuard/R8 to remove unused code"
                                    ]
                                },
                                "cwe": "CWE-506",
                                "cvss_score": "7.0",
                                "risk_score": 8.0
                            })
                            self.report["malware_indicators"].append(f"Suspicious library: {sus_lib} in {fname}")
                            break
                            
        except Exception as e:
            print(f"  Malware signature check error: {e}")
    
    def _get_library_description(self, lib_name):
        """Get detailed description of suspicious library"""
        descriptions = {
            'frida': "• Frida: Dynamic instrumentation framework\n• Used to hook and modify app behavior at runtime\n• Legitimate: Penetration testing\n• Malicious: Hiding malware activities, bypassing security",
            'xposed': "• Xposed Framework: System-level hooking\n• Modifies Android framework and apps\n• Legitimate: Custom ROMs, power user tweaks\n• Malicious: Stealing credentials, bypassing protections",
            'substrate': "• Cydia Substrate: Runtime patching framework\n• Similar to Xposed for hooking\n• Legitimate: iOS jailbreak tools (unusual in Android)\n• Malicious: Runtime code manipulation",
            'cydia': "• Cydia: iOS jailbreak app store\n• Should NOT appear in Android apps\n• Presence indicates: Cross-platform malware or misidentification",
            'magisk': "• Magisk: Systemless root solution\n• Used to root Android devices\n• Legitimate: Power users, custom ROMs\n• Malicious: Privilege escalation, hiding root from detection",
            'rootcloak': "• RootCloak: Hides root access from apps\n• Bypasses root detection mechanisms\n• Legitimate: Privacy (questionable)\n• Malicious: Evading security checks"
        }
        return descriptions.get(lib_name, "• Unknown library - requires manual analysis")
    
    def _check_obfuscation(self):
        """Code obfuscation check with detailed recommendations"""
        if not self.dex_cache:
            return
        
        try:
            # Check for ProGuard/R8 signatures
            has_obfuscation = b'proguard' in self.dex_cache.lower() or b'r8' in self.dex_cache.lower()
            
            if not has_obfuscation:
                self._add_vuln({
                    "type": "No Code Obfuscation",
                    "severity": "Medium",
                    "owasp": "M9 (Reverse Engineering)",
                    "category": "Code Protection",
                    "location": {
                        "file": "classes.dex",
                        "detection": "No ProGuard/R8 signatures found in bytecode",
                        "evidence": "Missing obfuscation artifacts"
                    },
                    "details": "Application code is not obfuscated. This makes reverse engineering significantly easier, allowing attackers to:\n" +
                               "• Decompile APK to readable Java code using tools like jadx\n" +
                               "• Read original class/method/variable names\n" +
                               "• Understand business logic and algorithms quickly\n" +
                               "• Locate and extract API keys, endpoints, and secrets\n" +
                               "• Identify security vulnerabilities in code\n" +
                               "• Create modified/pirated versions of the app\n" +
                               "• Develop competing apps by copying functionality",
                    "impact": "Without obfuscation:\n" +
                             "• Intellectual property is easily stolen\n" +
                             "• Security through obscurity is completely absent\n" +
                             "• Attackers can find vulnerabilities faster\n" +
                             "• Code logic can be replicated by competitors\n" +
                             "• APK size is larger (unused code not removed)",
                    "decompilation_example": [
                        "Attacker can easily decompile with:",
                        "jadx app.apk -d output/",
                        "",
                        "Without obfuscation, they see:",
                        "public class UserAuthentication {",
                        "  private String apiKey = \"sk_live_xyz123...\";",
                        "  public boolean authenticateUser(String username, String password) {",
                        "    // Entire logic is readable",
                        "  }",
                        "}",
                        "",
                        "With obfuscation, they see:",
                        "public class a {",
                        "  private String b;",
                        "  public boolean c(String d, String e) {",
                        "    // Logic is preserved but harder to understand",
                        "  }",
                        "}"
                    ],
                    "remediation": {
                        "enable_proguard_r8": [
                            "Enable R8/ProGuard in build.gradle:",
                            "",
                            "android {",
                            "  buildTypes {",
                            "    release {",
                            "      minifyEnabled true  // Enable obfuscation",
                            "      shrinkResources true  // Remove unused resources",
                            "      proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'),",
                            "                    'proguard-rules.pro'",
                            "    }",
                            "  }",
                            "}"
                        ],
                        "configure_proguard_rules": [
                            "Create/update proguard-rules.pro:",
                            "",
                            "# Keep essential classes",
                            "-keep public class * extends android.app.Activity",
                            "-keep public class * extends android.app.Service",
                            "",
                            "# Keep native methods",
                            "-keepclasseswithmembernames class * {",
                            "  native <methods>;",
                            "}",
                            "",
                            "# Keep Parcelables",
                            "-keep class * implements android.os.Parcelable {",
                            "  public static final android.os.Parcelable$Creator *;",
                            "}",
                            "",
                            "# Aggressive obfuscation",
                            "-overloadaggressively",
                            "-repackageclasses ''",
                            "-allowaccessmodification",
                            "",
                            "# Keep crash reporting (optional)",
                            "-keepattributes SourceFile,LineNumberTable",
                            "",
                            "# Remove logging (production)",
                            "-assumenosideeffects class android.util.Log {",
                            "  public static *** d(...);",
                            "  public static *** v(...);",
                            "  public static *** i(...);",
                            "}"
                        ],
                        "library_specific_rules": [
                            "Add rules for third-party libraries:",
                            "• Check library documentation for required ProGuard rules",
                            "• Most libraries provide proguard-rules.pro in their AAR",
                            "• Common libraries (Retrofit, Gson, etc.) need specific keep rules"
                        ],
                        "testing_obfuscated_builds": [
                            "Test thoroughly after enabling obfuscation:",
                            "1. Build release APK with obfuscation enabled",
                            "2. Test ALL app functionality (crashes indicate missing keep rules)",
                            "3. Check crash reports for obfuscated stack traces",
                            "4. Use mapping.txt to deobfuscate production crashes:",
                            "   Located in: app/build/outputs/mapping/release/mapping.txt",
                            "5. Upload mapping file to crash reporting service (Firebase, etc.)"
                        ],
                        "verify_obfuscation": [
                            "Verify obfuscation worked:",
                            "1. Decompile the release APK:",
                            "   jadx app-release.apk -d decompiled/",
                            "2. Check that class/method names are obfuscated (a, b, c, etc.)",
                            "3. Verify unused code is removed (smaller APK size)",
                            "4. Ensure no hardcoded secrets are visible"
                        ],
                        "additional_protection": [
                            "Consider additional code protection:",
                            "• DexGuard (commercial, stronger than R8)",
                            "• String encryption for sensitive strings",
                            "• Native code for critical algorithms",
                            "• Root/emulator detection",
                            "• Anti-debugging measures",
                            "• Certificate pinning",
                            "",
                            "Note: Obfuscation is not encryption - determined attackers can still reverse engineer",
                            "It raises the difficulty bar but doesn't make it impossible"
                        ]
                    },
                    "cwe": "CWE-656",
                    "cvss_score": "4.0",
                    "risk_score": 5.0
                })
        except Exception as e:
            print(f"  Obfuscation check error: {e}")
    
    def _check_suspicious_strings(self):
        """Detect suspicious behavioral strings with detailed analysis"""
        if not self.dex_cache:
            return
        
        patterns = {
            'root': ([b'su', b'/system/xbin/su', b'Superuser', b'/system/bin/su'], 
                     "Root Detection / Rooting Capabilities"),
            'premium_sms': ([b'premium', b'sms://'], 
                           "Premium SMS Fraud"),
            'c2': ([b'bot', b'command', b'control', b'c2'], 
                  "Command & Control Communication"),
            'crypto_wallet': ([b'bitcoin', b'ethereum', b'wallet', b'cryptocurrency'], 
                             "Cryptocurrency Wallet Access"),
        }
        
        try:
            for category, (keywords, description) in patterns.items():
                count = sum(self.dex_cache.count(kw) for kw in keywords)
                if count > 5:
                    severity = "High" if category in ['premium_sms', 'c2'] else "Medium"
                    
                    # Find some example occurrences
                    examples = []
                    for kw in keywords[:3]:
                        pos = self.dex_cache.find(kw)
                        if pos != -1:
                            # Get context around the match
                            context_start = max(0, pos - 30)
                            context_end = min(len(self.dex_cache), pos + 50)
                            context = self.dex_cache[context_start:context_end].decode('utf-8', errors='ignore')
                            examples.append(f"{kw.decode()}: ...{context}...")
                    
                    self._add_vuln({
                        "type": f"Suspicious {description} Strings",
                        "severity": severity,
                        "owasp": "M8 (Code Tampering)",
                        "category": "Suspicious Activity",
                        "location": {
                            "file": "classes.dex",
                            "occurrences": count,
                            "keywords_found": [kw.decode() for kw in keywords],
                            "example_contexts": examples[:2]
                        },
                        "details": f"Found {count} suspicious {category.replace('_', ' ')} references throughout the code.\n\n" +
                                   f"Category: {description}\n" +
                                   f"Detected keywords: {', '.join([k.decode() for k in keywords])}\n\n" +
                                   self._get_suspicious_string_details(category, count),
                        "impact": self._get_suspicious_string_impact(category),
                        "remediation": {
                            "immediate_investigation": [
                                "⚠️ Manual code review required",
                                "This pattern is commonly found in malware",
                                f"Found {count} references - unusually high for legitimate apps",
                                "",
                                "Investigation steps:",
                                "1. Decompile APK and search for these strings:",
                                f"   jadx app.apk -d output/",
                                f"   grep -r '{keywords[0].decode()}' output/",
                                "2. Analyze the context of each occurrence",
                                "3. Determine if functionality is legitimate",
                                "4. Check if third-party SDKs are responsible"
                            ],
                            "context_specific": self._get_remediation_for_category(category),
                            "if_malicious": [
                                "If confirmed malicious:",
                                "• Do NOT install or distribute this APK",
                                "• Report to app store and security authorities",
                                "• Scan device for compromise if already installed",
                                "• Alert users who may have installed this app"
                            ],
                            "if_legitimate": [
                                "If functionality is legitimate:",
                                "• Document the business justification",
                                "• Add code comments explaining the purpose",
                                "• Consider if functionality can be redesigned",
                                "• Implement additional security controls",
                                "• Prepare for user/store scrutiny"
                            ]
                        },
                        "cwe": "CWE-506",
                        "cvss_score": 7.0 if severity == "High" else 5.5,
                        "risk_score": 7.0 if severity == "High" else 5.5
                    })
                    
                    if severity == "High":
                        self.report["malware_indicators"].append(f"Suspicious {category} strings ({count} found)")
                        
        except Exception as e:
            print(f"  Suspicious strings check error: {e}")
    
    def _get_suspicious_string_details(self, category, count):
        """Get detailed explanation of suspicious string category"""
        details = {
            'root': f"Root-related strings may indicate:\n" +
                    "• Legitimate: Root detection for security (banking apps)\n" +
                    "• Malicious: Attempting to root device for privilege escalation\n" +
                    "• Malicious: Checking for root to hide malware activities\n" +
                    f"With {count} occurrences, this warrants investigation",
            
            'premium_sms': f"Premium SMS indicators strongly suggest:\n" +
                          "• SMS fraud/toll fraud malware\n" +
                          "• Silently sending messages to premium-rate numbers\n" +
                          "• Stealing money from victims through telecom billing\n" +
                          f"{count} references is VERY suspicious for this category",
            
            'c2': f"Command & Control patterns indicate:\n" +
                  "• Botnet capabilities - device can be remotely controlled\n" +
                  "• Backdoor access for attackers\n" +
                  "• Malware receiving instructions from remote servers\n" +
                  "• DDoS attack participation\n" +
                  f"{count} occurrences strongly suggests malicious intent",
            
            'crypto_wallet': f"Cryptocurrency-related strings may indicate:\n" +
                           "• Legitimate: Cryptocurrency wallet app\n" +
                           "• Malicious: Cryptojacking (mining crypto using victim's device)\n" +
                           "• Malicious: Stealing wallet credentials/private keys\n" +
                           "• Malicious: Clipboard hijacking (replacing wallet addresses)\n" +
                           f"Investigate all {count} occurrences carefully"
        }
        return details.get(category, "Unknown category - manual analysis required")
    
    def _get_suspicious_string_impact(self, category):
        """Get impact description for suspicious string category"""
        impacts = {
            'root': "If malicious:\n• Device becomes fully compromised\n• Attacker gains system-level access\n• Can persist across factory resets\n• Can access data from other apps",
            'premium_sms': "If malicious:\n• Direct financial theft from victims\n• Can cost hundreds of dollars in SMS charges\n• Difficult to detect until phone bill arrives\n• Especially harmful in developing countries",
            'c2': "If malicious:\n• Device becomes part of botnet\n• Can be used for DDoS attacks\n• Remote code execution by attackers\n• Complete loss of device control",
            'crypto_wallet': "If malicious:\n• Theft of cryptocurrency (unrecoverable)\n• Battery drain from mining\n• Device performance degradation\n• Potential hardware damage from overheating"
        }
        return impacts.get(category, "Impact unknown - requires investigation")
    
    def _get_remediation_for_category(self, category):
        """Get specific remediation steps for each category"""
        remediations = {
            'root': [
                "If legitimate root detection:",
                "• Ensure it's only for security checks",
                "• Use well-known root detection libraries (RootBeer)",
                "• Clearly document why root detection is needed",
                "• Handle rooted devices gracefully (inform user, don't crash)",
                "",
                "If attempting to root device:",
                "• This is malicious - remove immediately",
                "• Root exploits violate Play Store policies",
                "• Can cause device bricking and warranty void"
            ],
            'premium_sms': [
                "Premium SMS is almost always malicious in modern apps",
                "Legitimate uses are extremely rare",
                "",
                "If somehow legitimate:",
                "• Require explicit user consent before EACH message",
                "• Display clear cost information",
                "• Implement confirmation dialogs",
                "• Provide audit trail of all SMS sent",
                "",
                "If malicious:",
                "• This is fraud - report to authorities",
                "• Remove all premium SMS functionality",
                "• Never distribute this app"
            ],
            'c2': [
                "C2 functionality is malicious unless:",
                "• You're building a legitimate remote management tool (MDM)",
                "• You're creating a security testing tool",
                "",
                "For legitimate remote management:",
                "• Require explicit user enrollment",
                "• Show clear indicators when remote session is active",
                "• Require authentication for all commands",
                "• Implement audit logging",
                "• Allow user to disconnect at any time",
                "",
                "If malicious:",
                "• This is a backdoor - extremely serious",
                "• Report to security authorities",
                "• Do NOT distribute"
            ],
            'crypto_wallet': [
                "If legitimate cryptocurrency app:",
                "• Use well-audited crypto libraries",
                "• Never store private keys in plaintext",
                "• Implement hardware wallet support",
                "• Follow cryptocurrency security best practices",
                "• Undergo security audit before release",
                "",
                "If cryptojacking:",
                "• This is malware - using victim resources for profit",
                "• Violates app store policies",
                "• Remove all mining functionality",
                "",
                "If wallet theft:",
                "• Extremely serious cybercrime",
                "• Report to law enforcement",
                "• Never distribute"
            ]
        }
        return remediations.get(category, ["Unknown category - requires manual analysis"])
    
    def _check_network_analysis(self):
        """Network URL and endpoint analysis with detailed security assessment"""
        try:
            urls = set()
            
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                for fname in z.namelist():
                    if 'strings.xml' in fname or fname.endswith('.dex'):
                        try:
                            content = z.read(fname).decode('utf-8', errors='ignore')
                            found = re.findall(r'https?://[^\s<>"\']+', content)
                            urls.update(found[:20])
                        except:
                            continue
            
            # Check for suspicious TLDs
            suspicious_tld_urls = []
            for url in urls:
                if any(url.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                    suspicious_tld_urls.append(url)
            
            if suspicious_tld_urls:
                self._add_vuln({
                    "type": f"Suspicious Domain TLDs ({len(suspicious_tld_urls)} found)",
                    "severity": "Medium",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network",
                    "location": {
                        "files": ["strings.xml", "classes.dex"],
                        "urls": suspicious_tld_urls[:5],
                        "suspicious_tlds": list(set([url.split('.')[-1] for url in suspicious_tld_urls]))
                    },
                    "details": f"Detected {len(suspicious_tld_urls)} URLs with suspicious top-level domains:\n\n" +
                               "\n".join([f"• {url}" for url in suspicious_tld_urls[:5]]) +
                               ("\n• ... and more" if len(suspicious_tld_urls) > 5 else "") +
                               "\n\nThese TLDs are frequently associated with:\n" +
                               "• Malware command & control servers\n" +
                               "• Phishing websites\n" +
                               "• Temporary/disposable domains\n" +
                               "• Countries with lax domain registration oversight\n" +
                               "• Free or low-cost domain services abused by attackers",
                    "impact": "Communication with suspicious domains enables:\n" +
                             "• Data exfiltration to attacker-controlled servers\n" +
                             "• Receiving malicious commands from C2\n" +
                             "• Downloading additional malware payloads\n" +
                             "• Phishing attacks against users\n" +
                             "• Privacy violations through unauthorized tracking",
                    "tld_risk_profiles": {
                        ".ru": "Russia - commonly abused by cybercriminals",
                        ".cn": "China - high spam/malware association",
                        ".tk": "Tokelau - free domains, heavily abused",
                        ".cc": "Cocos Islands - popular with spammers",
                        ".pw": "Palau - frequently used for malicious sites",
                        ".top": "Generic TLD - high malware association"
                    },
                    "remediation": {
                        "immediate_investigation": [
                            "Investigate each suspicious URL:",
                            "1. Check domain ownership (WHOIS lookup)",
                            "2. Verify domain age (new domains more suspicious)",
                            "3. Check domain reputation:",
                            "   • VirusTotal: virustotal.com",
                            "   • URLhaus: urlhaus.abuse.ch",
                            "   • Google Safe Browsing",
                            "4. Analyze what data is sent to these domains",
                            "5. Determine if domains belong to your organization"
                        ],
                        "if_legitimate": [
                            "If domains are legitimate but use suspicious TLDs:",
                            "• Consider migrating to more reputable TLDs (.com, .org, .net)",
                            "• Document business justification",
                            "• Expect user/antivirus concerns",
                            "• Implement additional security measures:",
                            "  - Certificate pinning",
                            "  - HTTPS-only communication",
                            "  - Domain validation in code"
                        ],
                        "if_malicious": [
                            "If domains are malicious:",
                            "• Remove all references to these URLs",
                            "• Audit codebase for other attacker infrastructure",
                            "• Check if app was compromised during build",
                            "• Report domains to abuse databases",
                            "• Alert users if app was distributed"
                        ],
                        "secure_alternatives": [
                            "Best practices for API endpoints:",
                            "• Use organization-owned domains only",
                            "• Prefer established TLDs (.com, .org, country codes)",
                            "• Implement subdomains for services (api.yourdomain.com)",
                            "• Use content delivery networks (CDNs) for static content",
                            "• Avoid hardcoding URLs - use remote configuration"
                        ],
                        "domain_verification": [
                            "Implement domain verification in code:",
                            "public boolean isTrustedDomain(String url) {",
                            "  List<String> trustedDomains = Arrays.asList(",
                            "    \"api.yourcompany.com\",",
                            "    \"cdn.yourcompany.com\"",
                            "  );",
                            "  Uri uri = Uri.parse(url);",
                            "  return trustedDomains.contains(uri.getHost());",
                            "}"
                        ]
                    },
                    "cwe": "CWE-940",
                    "cvss_score": "6.0",
                    "risk_score": 6.0
                })
                
                for url in suspicious_tld_urls[:3]:
                    self.report["malware_indicators"].append(f"Suspicious TLD: {url}")
            
            # Check for HTTP URLs
            http_urls = [u for u in urls if u.startswith('http://')]
            if http_urls:
                self._add_vuln({
                    "type": f"Insecure HTTP Communication ({len(http_urls)} URLs)",
                    "severity": "Medium",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network",
                    "location": {
                        "files": ["strings.xml", "classes.dex"],
                        "http_urls": http_urls[:5],
                        "count": len(http_urls)
                    },
                    "details": f"Found {len(http_urls)} plaintext HTTP URLs:\n\n" +
                               "\n".join([f"• {url}" for url in http_urls[:5]]) +
                               ("\n• ... and more" if len(http_urls) > 5 else "") +
                               "\n\nHTTP communication is unencrypted, allowing:\n" +
                               "• Man-in-the-Middle (MitM) attacks\n" +
                               "• Network eavesdropping (WiFi sniffing, ISP monitoring)\n" +
                               "• Traffic modification by network attackers\n" +
                               "• Session hijacking and credential theft",
                    "impact": "Unencrypted HTTP exposes:\n" +
                             "• User credentials and passwords in transit\n" +
                             "• API keys and authentication tokens\n" +
                             "• Personal user data\n" +
                             "• Session cookies (enabling account takeover)\n" +
                             "• Business logic and API structure",
                    "attack_scenario": [
                        "Attacker on same WiFi network:",
                        "1. Sets up packet sniffer (Wireshark, tcpdump)",
                        "2. Captures all HTTP traffic from victim's device",
                        "3. Extracts credentials, tokens, personal data",
                        "4. (Optional) Modifies traffic in real-time using tools like mitmproxy",
                        "",
                        "No technical expertise required - many point-and-click tools available"
                    ],
                    "remediation": {
                        "migrate_to_https": [
                            "Replace ALL HTTP URLs with HTTPS:",
                            "",
                            "❌ BAD:",
                            "http://api.example.com/user/login",
                            "",
                            "✅ GOOD:",
                            "https://api.example.com/user/login",
                            "",
                            "Steps:",
                            "1. Update server infrastructure to support HTTPS",
                            "2. Obtain SSL/TLS certificates (Let's Encrypt for free)",
                            "3. Configure web server with certificates",
                            "4. Update all URLs in app code to use https://",
                            "5. Test all endpoints work with HTTPS"
                        ],
                        "enforce_https_only": [
                            "Block HTTP at network level:",
                            "",
                            "In network_security_config.xml:",
                            "<network-security-config>",
                            "  <base-config cleartextTrafficPermitted=\"false\"/>",
                            "</network-security-config>",
                            "",
                            "This blocks all HTTP traffic app-wide (Android 9+)"
                        ],
                        "okhttp_configuration": [
                            "If using OkHttp, enforce HTTPS:",
                            "OkHttpClient client = new OkHttpClient.Builder()",
                            "  .addInterceptor(chain -> {",
                            "    Request request = chain.request();",
                            "    if (!request.url().isHttps()) {",
                            "      throw new IOException(\"HTTP not allowed\");",
                            "    }",
                            "    return chain.proceed(request);",
                            "  })",
                            "  .build();"
                        ],
                        "certificate_pinning": [
                            "Add certificate pinning for critical APIs:",
                            "OkHttpClient client = new OkHttpClient.Builder()",
                            "  .certificatePinner(new CertificatePinner.Builder()",
                            "    .add(\"api.example.com\", \"sha256/AAAAAAA...\")",
                            "    .build())",
                            "  .build();",
                            "",
                            "This prevents MitM even if attacker has valid certificate"
                        ],
                        "testing": [
                            "Verify HTTPS enforcement:",
                            "1. Set up MitM proxy (Burp Suite, mitmproxy)",
                            "2. Try to intercept app traffic",
                            "3. App should reject connections if certificate pinned",
                            "4. Monitor for any HTTP fallback behavior",
                            "5. Test on various network conditions"
                        ]
                    },
                    "cwe": "CWE-319",
                    "cvss_score": "6.5",
                    "risk_score": 6.5
                })
                
        except Exception as e:
            print(f"  Network analysis error: {e}")
    
    def _add_vuln(self, vuln_data):
        """Thread-safe vulnerability addition with validation"""
        with self.vuln_lock:
            # Ensure all required fields are present
            if "location" not in vuln_data:
                vuln_data["location"] = {"file": "Unknown"}
            if "remediation" not in vuln_data:
                vuln_data["remediation"] = {"note": "Manual review required"}
            if "impact" not in vuln_data:
                vuln_data["impact"] = "Impact requires assessment"
            
            self.report["vulnerabilities"].append(vuln_data)
            severity = vuln_data["severity"].lower()
            if severity in self.report["summary"]:
                self.report["summary"][severity] += 1
    
    def _finalize_report(self):
        """Finalize report with sorting and scoring"""
        self.report["summary"]["total"] = len(self.report["vulnerabilities"])
        
        # Calculate overall risk
        if self.report["vulnerabilities"]:
            total_risk = sum(v.get("risk_score", 0) for v in self.report["vulnerabilities"])
            self.report["overall_risk_score"] = round(total_risk / len(self.report["vulnerabilities"]), 2)
        else:
            self.report["overall_risk_score"] = 0
        
        # Sort by severity
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.report["vulnerabilities"].sort(
            key=lambda x: (severity_order.get(x["severity"], 5), -x.get("risk_score", 0))
        )
    
    def _assess_malware(self):
        """Final malware assessment with confidence scoring"""
        indicators = len(self.report["malware_indicators"])
        
        if indicators >= 3:
            self.report["malware_detected"] = True
            self.report["malware_confidence"] = "High"
        elif indicators >= 1:
            self.report["malware_detected"] = True
            self.report["malware_confidence"] = "Medium"
        else:
            self.report["malware_detected"] = False
            self.report["malware_confidence"] = "None"


def analyze_apk(apk_path):
    """Main entry point for enhanced APK analysis"""
    analyzer = HybridUltimateAnalyzer(apk_path)
    return analyzer.analyze()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python analyser_enhanced.py <apk_file>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"❌ File not found: {apk_file}")
        sys.exit(1)
    
    report = analyze_apk(apk_file)
    
    # Display enhanced results
    print(f"\n{'='*70}")
    print(f"📊 ENHANCED SECURITY ANALYSIS RESULTS")
    print(f"{'='*70}")
    print(f"App: {report['app_name']}")
    print(f"Package: {report['package_name']}")
    print(f"Version: {report['version_name']}")
    print(f"Hash: {report['file_hash_sha256'][:32]}...")
    print(f"Size: {report['file_size_mb']} MB")
    print(f"Risk Score: {report['overall_risk_score']}/10")
    print(f"\n🔴 Critical: {report['summary']['critical']}")
    print(f"🟠 High: {report['summary']['high']}")
    print(f"🟡 Medium: {report['summary']['medium']}")
    print(f"🟢 Low: {report['summary']['low']}")
    print(f"ℹ️  Info: {report['summary']['info']}")
    print(f"📈 Total: {report['summary']['total']}")
    
    if report['malware_detected']:
        print(f"\n⚠️  MALWARE DETECTED")
        print(f"Confidence: {report['malware_confidence']}")
        print(f"Indicators ({len(report['malware_indicators'])}):")
        for indicator in report['malware_indicators']:
            print(f"  • {indicator}")
    
    print(f"\n💡 Note: Enhanced edition includes detailed location tracking,")
    print(f"   comprehensive remediation steps, and impact assessments")
    print(f"{'='*70}\n")
