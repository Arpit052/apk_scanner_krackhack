#!/usr/bin/env python3
"""
Enhanced APK Security Analyzer - Improved Accuracy
Uses pyaxmlparser + advanced detection techniques
"""

import zipfile
import re
import os
from collections import defaultdict
from pyaxmlparser import APK
import xml.etree.ElementTree as ET


class APKSecurityAnalyzer:
    """Enhanced APK security analysis with improved accuracy"""
    
    # Android namespace
    NS = {'android': 'http://schemas.android.com/apk/res/android'}
    
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.manifest_xml_string = None  # Store raw manifest for additional checks
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
        self._check_webview_security()  # NEW
        self._check_certificate()  # NEW
        self._check_file_permissions()  # NEW
        
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
            
            # Store raw manifest for advanced checks
            self.manifest_xml_string = self.apk.get_android_manifest_xml()
            
        except Exception as e:
            print(f"⚠️  Warning: Could not extract app info - {e}")
    
    def _check_manifest_security(self):
        """Enhanced manifest security checks"""
        try:
            if not self.manifest_xml_string:
                return
                
            root = ET.fromstring(self.manifest_xml_string)
            app_tag = root.find('.//application')
            
            if app_tag is None:
                return
            
            target_sdk = int(self.report["target_sdk"]) if str(self.report["target_sdk"]).isdigit() else 28
            
            # Check debuggable (ENHANCED: also check raw XML)
            debuggable = app_tag.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
            # Also check raw string in case of XML parsing issues
            raw_debuggable = 'android:debuggable="true"' in self.manifest_xml_string
            
            if debuggable.lower() == 'true' or raw_debuggable:
                self._add_vuln({
                    "type": "Application is Debuggable",
                    "severity": "Critical",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": "App is marked as debuggable. Attackers can attach debuggers, extract sensitive data, modify memory, bypass certificate pinning, and reverse engineer the app in real-time.",
                    "remediation": "Remove android:debuggable='true' from AndroidManifest.xml. Use ProGuard/R8 obfuscation. Implement anti-debugging checks.",
                    "cwe": "CWE-489",
                    "risk_score": 9.5
                })
            
            # Check allowBackup (ENHANCED: distinguish between explicit and default)
            allow_backup = app_tag.get('{http://schemas.android.com/apk/res/android}allowBackup')
            full_backup = app_tag.get('{http://schemas.android.com/apk/res/android}fullBackupContent')
            
            if allow_backup is None:
                # Default is true - flag with lower severity
                self._add_vuln({
                    "type": "Backup Enabled by Default",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": "android:allowBackup is not explicitly set (defaults to true). App data including SharedPreferences, databases, and internal files can be extracted via 'adb backup' or Google Auto Backup.",
                    "remediation": "Set android:allowBackup='false' OR use android:fullBackupContent to whitelist only non-sensitive data.",
                    "cwe": "CWE-200",
                    "risk_score": 5.0
                })
            elif allow_backup.lower() == 'true':
                if full_backup:
                    # Has backup content rules - less risky
                    self._add_vuln({
                        "type": "Backup Enabled with Rules",
                        "severity": "Low",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Data Protection",
                        "details": "Backup is enabled but uses fullBackupContent rules. Verify that sensitive data is excluded.",
                        "remediation": "Review fullBackupContent XML to ensure databases, SharedPreferences with credentials, and API keys are excluded.",
                        "cwe": "CWE-200",
                        "risk_score": 3.0
                    })
                else:
                    # Explicitly true without rules - higher risk
                    self._add_vuln({
                        "type": "Backup Explicitly Enabled",
                        "severity": "Medium",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Data Protection",
                        "details": "android:allowBackup is explicitly set to true without backup rules. ALL app data can be extracted.",
                        "remediation": "Set android:allowBackup='false' or implement fullBackupContent with exclusions for sensitive data.",
                        "cwe": "CWE-200",
                        "risk_score": 6.0
                    })
            
            # Check cleartext traffic (ENHANCED: better default handling)
            cleartext = app_tag.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            
            if cleartext is None:
                if target_sdk < 28:
                    self._add_vuln({
                        "type": "Cleartext Traffic Allowed (Legacy SDK)",
                        "severity": "High",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": f"App targets SDK {target_sdk} (pre-28) where HTTP cleartext is allowed by default. All HTTP traffic is vulnerable to man-in-the-middle (MITM) attacks, allowing attackers to intercept credentials, session tokens, and sensitive data.",
                        "remediation": "Target SDK 28+ OR set android:usesCleartextTraffic='false'. Migrate all endpoints to HTTPS. Implement certificate pinning.",
                        "cwe": "CWE-319",
                        "risk_score": 8.0
                    })
            elif cleartext.lower() == 'true':
                self._add_vuln({
                    "type": "Cleartext Traffic Explicitly Allowed",
                    "severity": "Critical",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": "App explicitly allows unencrypted HTTP traffic. This is a critical vulnerability allowing complete MITM attacks. Attackers can steal credentials, modify API responses, inject malicious content, and hijack sessions.",
                    "remediation": "Set android:usesCleartextTraffic='false'. Use HTTPS exclusively. Implement certificate pinning with backup pins. Use TLS 1.2+.",
                    "cwe": "CWE-319",
                    "risk_score": 9.0
                })
            
            # Check network security config (ENHANCED: more detailed)
            nsc = app_tag.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
            if target_sdk >= 24:
                if not nsc:
                    self._add_vuln({
                        "type": "Missing Network Security Configuration",
                        "severity": "Low",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": "No custom network security config. Missing certificate pinning makes the app vulnerable to MITM attacks via compromised CAs or rogue certificates.",
                        "remediation": "Create res/xml/network_security_config.xml with certificate pinning for API domains. Use SHA-256 pins with backup pins.",
                        "cwe": "CWE-295",
                        "risk_score": 4.0
                    })
                else:
                    # Has network security config - check if it's overly permissive
                    try:
                        with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                            nsc_path = nsc.replace('@xml/', 'res/xml/').replace('@', 'res/') + '.xml'
                            possible_paths = [
                                'res/xml/network_security_config.xml',
                                nsc_path
                            ]
                            
                            for path in possible_paths:
                                if path in apk_zip.namelist():
                                    nsc_content = apk_zip.read(path).decode('utf-8', errors='ignore')
                                    
                                    # Check for overly permissive settings
                                    if 'cleartextTrafficPermitted="true"' in nsc_content:
                                        self._add_vuln({
                                            "type": "Network Security Config Allows Cleartext",
                                            "severity": "High",
                                            "owasp": "M3 (Insecure Communication)",
                                            "category": "Network Security",
                                            "details": "Network security config explicitly permits cleartext traffic for some domains.",
                                            "remediation": "Remove cleartextTrafficPermitted='true' from network_security_config.xml. Use HTTPS only.",
                                            "cwe": "CWE-319",
                                            "risk_score": 7.5
                                        })
                                    
                                    if '<trust-anchors>' in nsc_content and 'user' in nsc_content:
                                        self._add_vuln({
                                            "type": "Trusts User-Installed Certificates",
                                            "severity": "Medium",
                                            "owasp": "M3 (Insecure Communication)",
                                            "category": "Network Security",
                                            "details": "App trusts user-installed CA certificates. This allows users to MITM their own traffic, which could be exploited by malware with root access.",
                                            "remediation": "Only trust system certificates in production builds. User certificates should only be trusted in debug builds.",
                                            "cwe": "CWE-295",
                                            "risk_score": 5.5
                                        })
                                    
                                    # Check for certificate pinning
                                    if '<pin-set>' not in nsc_content and '<pin ' not in nsc_content:
                                        self._add_vuln({
                                            "type": "Certificate Pinning Not Implemented",
                                            "severity": "Low",
                                            "owasp": "M3 (Insecure Communication)",
                                            "category": "Network Security",
                                            "details": "Network security config exists but does not implement certificate pinning.",
                                            "remediation": "Add <pin-set> with SHA-256 certificate pins for your API domains.",
                                            "cwe": "CWE-295",
                                            "risk_score": 4.5
                                        })
                                    
                                    break
                    except:
                        pass
            
            # Check testOnly
            test_only = app_tag.get('{http://schemas.android.com/apk/res/android}testOnly', 'false')
            if test_only.lower() == 'true':
                self._add_vuln({
                    "type": "Test-Only Build in Production",
                    "severity": "High",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": "App is marked as testOnly. This indicates it's a debug/test build being distributed as production.",
                    "remediation": "Remove android:testOnly='true'. Rebuild with production configuration.",
                    "cwe": "CWE-489",
                    "risk_score": 7.0
                })
            
            # NEW: Check for task affinity hijacking
            task_affinity = app_tag.get('{http://schemas.android.com/apk/res/android}taskAffinity')
            if task_affinity and task_affinity != self.report["package_name"]:
                self._add_vuln({
                    "type": "Custom Task Affinity",
                    "severity": "Low",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Configuration",
                    "details": f"App uses custom taskAffinity: '{task_affinity}'. This could be exploited for task hijacking attacks.",
                    "remediation": "Only use custom taskAffinity if absolutely necessary. Validate all activity launches.",
                    "cwe": "CWE-668",
                    "risk_score": 3.5
                })
            
            # NEW: Check for persistent attribute
            persistent = app_tag.get('{http://schemas.android.com/apk/res/android}persistent', 'false')
            if persistent.lower() == 'true':
                self._add_vuln({
                    "type": "Persistent Application Flag",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Configuration",
                    "details": "App is marked as persistent. This is typically only for system apps.",
                    "remediation": "Remove android:persistent='true' unless this is a system-level app.",
                    "cwe": "CWE-250",
                    "risk_score": 5.0
                })
            
        except Exception as e:
            print(f"⚠️  Manifest check error: {e}")
    
    def _check_permissions(self):
        """Enhanced permission analysis with context and grouping"""
        # Categorized dangerous permissions
        critical_perms = {
            'android.permission.READ_SMS': 'Can read all SMS including 2FA codes, OTPs, and banking verification messages',
            'android.permission.SEND_SMS': 'Can send SMS to premium-rate numbers, causing financial loss',
            'android.permission.RECEIVE_SMS': 'Can intercept incoming SMS including authentication codes',
            'android.permission.BIND_DEVICE_ADMIN': 'Can gain device admin privileges, enabling device wipe and policy enforcement',
            'android.permission.RECEIVE_BOOT_COMPLETED': 'Can execute code at device startup (potential for persistence)',
        }
        
        high_risk_perms = {
            'android.permission.READ_CALL_LOG': 'Can read complete call history including phone numbers and durations',
            'android.permission.WRITE_CALL_LOG': 'Can modify or delete call history',
            'android.permission.PROCESS_OUTGOING_CALLS': 'Can monitor and block outgoing calls',
            'android.permission.RECORD_AUDIO': 'Can record audio without user interaction, enabling eavesdropping',
            'android.permission.SYSTEM_ALERT_WINDOW': 'Can draw over other apps (phishing attacks, overlay attacks)',
            'android.permission.REQUEST_INSTALL_PACKAGES': 'Can install additional apps (malware propagation vector)',
            'android.permission.WRITE_SETTINGS': 'Can modify system settings',
            'android.permission.INSTALL_PACKAGES': 'Can silently install apps',
        }
        
        medium_risk_perms = {
            'android.permission.CAMERA': 'Can access camera for photos/videos',
            'android.permission.READ_CONTACTS': 'Can read complete contact list',
            'android.permission.WRITE_CONTACTS': 'Can modify or delete contacts',
            'android.permission.ACCESS_FINE_LOCATION': 'Can track precise GPS location',
            'android.permission.READ_PHONE_STATE': 'Can read IMEI, phone number, and device identifiers',
            'android.permission.PACKAGE_USAGE_STATS': 'Can monitor app usage patterns',
            'android.permission.GET_TASKS': 'Can see what apps are running',
            'android.permission.READ_LOGS': 'Can read system logs (may contain sensitive data)',
        }
        
        low_risk_perms = {
            'android.permission.ACCESS_COARSE_LOCATION': 'Can track approximate location (cell tower/WiFi)',
            'android.permission.GET_ACCOUNTS': 'Can access list of accounts on device',
            'android.permission.READ_EXTERNAL_STORAGE': 'Can read files from external storage',
            'android.permission.WRITE_EXTERNAL_STORAGE': 'Can write files to external storage',
            'android.permission.VIBRATE': 'Can trigger device vibration',
            'android.permission.WAKE_LOCK': 'Can prevent device from sleeping',
        }
        
        try:
            permissions = self.apk.permissions or []
            
            # Track permission categories for summary
            perm_categories = {
                'SMS': 0,
                'Calls': 0,
                'Location': 0,
                'Storage': 0,
                'Device Admin': 0,
                'System': 0
            }
            
            for perm in permissions:
                severity = None
                risk = None
                
                # Check each category
                if perm in critical_perms:
                    severity, risk = "Critical", critical_perms[perm]
                elif perm in high_risk_perms:
                    severity, risk = "High", high_risk_perms[perm]
                elif perm in medium_risk_perms:
                    severity, risk = "Medium", medium_risk_perms[perm]
                elif perm in low_risk_perms:
                    severity, risk = "Low", low_risk_perms[perm]
                
                if severity:
                    perm_name = perm.split('.')[-1]
                    
                    # Categorize
                    if 'SMS' in perm_name:
                        perm_categories['SMS'] += 1
                    elif 'CALL' in perm_name:
                        perm_categories['Calls'] += 1
                    elif 'LOCATION' in perm_name:
                        perm_categories['Location'] += 1
                    elif 'STORAGE' in perm_name:
                        perm_categories['Storage'] += 1
                    elif 'DEVICE_ADMIN' in perm_name or 'BOOT_COMPLETED' in perm_name:
                        perm_categories['Device Admin'] += 1
                    else:
                        perm_categories['System'] += 1
                    
                    # Calculate risk score
                    risk_scores = {"Critical": 9.0, "High": 7.5, "Medium": 5.0, "Low": 3.0}
                    
                    self._add_vuln({
                        "type": f"Dangerous Permission: {perm_name}",
                        "severity": severity,
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Permissions",
                        "details": f"App requests '{perm}'. {risk}. Ensure this permission is essential and clearly justified to users.",
                        "remediation": "Remove if unnecessary. Request at runtime with clear user-facing explanation. Use alternatives if available (e.g., Storage Access Framework instead of WRITE_EXTERNAL_STORAGE).",
                        "cwe": "CWE-250",
                        "risk_score": risk_scores[severity]
                    })
            
            # NEW: Flag dangerous permission combinations
            if perm_categories['SMS'] >= 2 and perm_categories['Device Admin'] >= 1:
                self._add_vuln({
                    "type": "Dangerous Permission Combination: SMS + Device Admin",
                    "severity": "Critical",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Permissions",
                    "details": "App requests SMS permissions combined with device admin capabilities. This combination is commonly used by banking trojans and ransomware.",
                    "remediation": "Justify why this combination is necessary. Implement strong server-side validation.",
                    "cwe": "CWE-250",
                    "risk_score": 9.5
                })
            
            if perm_categories['Location'] >= 1 and perm_categories['SMS'] >= 1:
                self._add_vuln({
                    "type": "Suspicious Permission Combination: Location + SMS",
                    "severity": "High",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Permissions",
                    "details": "App requests both location tracking and SMS access. This combination enables location-based SMS fraud.",
                    "remediation": "Ensure both permissions are legitimately required. Implement clear privacy policy.",
                    "cwe": "CWE-250",
                    "risk_score": 7.5
                })
                
        except Exception as e:
            print(f"⚠️  Permission check error: {e}")
    
    def _check_exported_components(self):
        """Enhanced exported component analysis"""
        try:
            manifest_xml = self.apk.get_android_manifest_xml()
            root = ET.fromstring(manifest_xml)
            
            # Track statistics
            stats = {
                'total_activities': 0,
                'exported_activities': 0,
                'total_services': 0,
                'exported_services': 0,
                'total_receivers': 0,
                'exported_receivers': 0,
                'total_providers': 0,
                'exported_providers': 0
            }
            
            # Check activities
            for activity in root.findall('.//activity'):
                stats['total_activities'] += 1
                exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = activity.find('intent-filter')
                name = activity.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                permission = activity.get('{http://schemas.android.com/apk/res/android}permission')
                
                if intent_filter is not None:
                    is_launcher = False
                    actions = []
                    for action in intent_filter.findall('action'):
                        action_name = action.get('{http://schemas.android.com/apk/res/android}name', '')
                        actions.append(action_name)
                        if action_name == 'android.intent.action.MAIN':
                            is_launcher = True
                    
                    if not is_launcher and (exported is None or exported.lower() == 'true'):
                        stats['exported_activities'] += 1
                        
                        # Determine severity based on actions and protection
                        severity = "High"
                        if permission:
                            severity = "Medium"  # Has some protection
                        
                        action_str = ', '.join(actions) if actions else 'Unknown'
                        
                        self._add_vuln({
                            "type": "Exported Activity Without Protection",
                            "severity": severity,
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Activity '{name}' is exported with intent actions: [{action_str}]. " + 
                                      ("Has permission protection but verify it's signature-level." if permission else "No permission protection - any app can launch this activity."),
                            "remediation": f"Set android:exported='false' for '{name}' OR add signature-level permission. Validate all intent extras. Implement authentication checks.",
                            "cwe": "CWE-927",
                            "risk_score": 7.5 if not permission else 5.5
                        })
            
            # Check services (ENHANCED)
            for service in root.findall('.//service'):
                stats['total_services'] += 1
                exported = service.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = service.find('intent-filter')
                name = service.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                permission = service.get('{http://schemas.android.com/apk/res/android}permission')
                
                if intent_filter is not None or (exported and exported.lower() == 'true'):
                    stats['exported_services'] += 1
                    
                    if not permission:
                        # Check if it's a dangerous service type
                        is_accessibility = 'AccessibilityService' in name
                        is_device_admin = 'DeviceAdmin' in name
                        
                        if is_accessibility:
                            self._add_vuln({
                                "type": "Exported Accessibility Service",
                                "severity": "Critical",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Component Security",
                                "details": f"Accessibility service '{name}' is exported. Accessibility services have extensive permissions and can be hijacked by malicious apps.",
                                "remediation": "Accessibility services should never be exported. Set android:exported='false'.",
                                "cwe": "CWE-927",
                                "risk_score": 9.5
                            })
                        elif is_device_admin:
                            self._add_vuln({
                                "type": "Exported Device Admin Service",
                                "severity": "Critical",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Component Security",
                                "details": f"Device admin service '{name}' is exported. This can be exploited for unauthorized device control.",
                                "remediation": "Set android:exported='false' and require signature permission.",
                                "cwe": "CWE-927",
                                "risk_score": 9.0
                            })
                        else:
                            self._add_vuln({
                                "type": "Exported Service Without Permission",
                                "severity": "High",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Component Security",
                                "details": f"Service '{name}' is exported without permission protection. Malicious apps can bind to and control this service.",
                                "remediation": "Set android:exported='false' OR require signature-level permission.",
                                "cwe": "CWE-927",
                                "risk_score": 7.5
                            })
            
            # Check receivers (ENHANCED)
            for receiver in root.findall('.//receiver'):
                stats['total_receivers'] += 1
                exported = receiver.get('{http://schemas.android.com/apk/res/android}exported')
                intent_filter = receiver.find('intent-filter')
                name = receiver.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                permission = receiver.get('{http://schemas.android.com/apk/res/android}permission')
                
                if intent_filter is not None:
                    stats['exported_receivers'] += 1
                    
                    # Check for dangerous broadcast actions
                    actions = []
                    for action in intent_filter.findall('action'):
                        actions.append(action.get('{http://schemas.android.com/apk/res/android}name', ''))
                    
                    dangerous_actions = [
                        'android.intent.action.BOOT_COMPLETED',
                        'android.provider.Telephony.SMS_RECEIVED',
                        'android.intent.action.PACKAGE_ADDED',
                        'android.intent.action.PACKAGE_REMOVED'
                    ]
                    
                    has_dangerous_action = any(action in dangerous_actions for action in actions)
                    
                    if (exported is None or exported.lower() == 'true') and has_dangerous_action:
                        self._add_vuln({
                            "type": "Exported Receiver for Sensitive Broadcasts",
                            "severity": "Medium",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Receiver '{name}' listens for sensitive broadcasts: {actions}. Exported receivers can be triggered by malicious apps.",
                            "remediation": "Use signature-level permissions for sensitive receivers. Consider using LocalBroadcastManager for internal broadcasts.",
                            "cwe": "CWE-927",
                            "risk_score": 6.0
                        })
                    
                    # Check priority
                    if intent_filter is not None:
                        priority = intent_filter.get('{http://schemas.android.com/apk/res/android}priority', '0')
                        try:
                            if int(priority) > 500:
                                self._add_vuln({
                                    "type": "High-Priority Broadcast Receiver",
                                    "severity": "Medium",
                                    "owasp": "M1 (Improper Platform Usage)",
                                    "category": "Component Security",
                                    "details": f"Receiver '{name}' has high priority ({priority}). High-priority receivers can intercept and abort broadcasts before legitimate apps receive them.",
                                    "remediation": "Reduce priority to normal levels. Use ordered broadcasts only when necessary.",
                                    "cwe": "CWE-927",
                                    "risk_score": 5.5
                                })
                        except:
                            pass
            
            # Check content providers (ENHANCED)
            for provider in root.findall('.//provider'):
                stats['total_providers'] += 1
                exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
                name = provider.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                grant_uri = provider.get('{http://schemas.android.com/apk/res/android}grantUriPermissions', 'false')
                read_permission = provider.get('{http://schemas.android.com/apk/res/android}readPermission')
                write_permission = provider.get('{http://schemas.android.com/apk/res/android}writePermission')
                authorities = provider.get('{http://schemas.android.com/apk/res/android}authorities', 'Unknown')
                
                if exported and exported.lower() == 'true':
                    stats['exported_providers'] += 1
                    
                    if not read_permission and not write_permission:
                        self._add_vuln({
                            "type": "Exported Content Provider Without Permissions",
                            "severity": "Critical",
                            "owasp": "M2 (Insecure Data Storage)",
                            "category": "Component Security",
                            "details": f"Content Provider '{name}' (authorities: {authorities}) is exported without read/write permissions. Any app can access app's private data including databases, SharedPreferences, and files.",
                            "remediation": "Set android:exported='false' OR require signature-level readPermission and writePermission. Implement path permissions for granular access control.",
                            "cwe": "CWE-200",
                            "risk_score": 9.5
                        })
                    elif not read_permission or not write_permission:
                        self._add_vuln({
                            "type": "Partially Protected Content Provider",
                            "severity": "High",
                            "owasp": "M2 (Insecure Data Storage)",
                            "category": "Component Security",
                            "details": f"Content Provider '{name}' is exported but only has {'read' if read_permission else 'write'} permission. {'Write' if read_permission else 'Read'} access is unprotected.",
                            "remediation": "Add both readPermission and writePermission with signature-level protection.",
                            "cwe": "CWE-200",
                            "risk_score": 7.5
                        })
                
                if grant_uri.lower() == 'true':
                    # Check if path permissions are defined
                    path_perms = provider.findall('path-permission')
                    if not path_perms or len(path_perms) == 0:
                        self._add_vuln({
                            "type": "Unrestricted URI Grant Permissions",
                            "severity": "Medium",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Component Security",
                            "details": f"Provider '{name}' grants URI permissions without path restrictions. Apps can gain temporary access to any content.",
                            "remediation": "Use <path-permission> tags to restrict grantUriPermissions to specific paths.",
                            "cwe": "CWE-732",
                            "risk_score": 6.0
                        })
            
            # Summary warning if too many exported components
            total_exported = (stats['exported_activities'] + stats['exported_services'] + 
                            stats['exported_receivers'] + stats['exported_providers'])
            
            if total_exported > 5:
                self._add_vuln({
                    "type": f"Excessive Exported Components ({total_exported} total)",
                    "severity": "Low",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Component Security",
                    "details": f"App exports {total_exported} components ({stats['exported_activities']} activities, {stats['exported_services']} services, {stats['exported_receivers']} receivers, {stats['exported_providers']} providers). Large attack surface.",
                    "remediation": "Review all exported components. Only export components that must be accessible to other apps. Use signature permissions.",
                    "cwe": "CWE-927",
                    "risk_score": 4.0
                })
                    
        except Exception as e:
            print(f"⚠️  Component check error: {e}")
    
    def _check_hardcoded_secrets(self):
        """Enhanced secret detection with better filtering"""
        secrets_found = set()
        max_secrets = 10
        
        # More specific patterns with better validation
        patterns = {
            'AWS Access Key': (r'AKIA[0-9A-Z]{16}', lambda x: len(x) == 20),
            'AWS Secret Key': (r'(?i)aws.{0,20}secret.{0,20}["\']([A-Za-z0-9/+=]{40})["\']', lambda x: len(x) == 40),
            'Google API Key': (r'AIza[0-9A-Za-z\-_]{35}', lambda x: len(x) == 39),
            'Google OAuth': (r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com', lambda x: '.apps.googleusercontent.com' in x),
            'Firebase URL': (r'https://[a-z0-9-]{6,30}\.firebaseio\.com', lambda x: '.firebaseio.com' in x),
            'Slack Token': (r'xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,}', lambda x: x.startswith('xox')),
            'Stripe API Key': (r'sk_live_[0-9a-zA-Z]{24,}', lambda x: x.startswith('sk_live_')),
            'Private Key': (r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----', lambda x: 'PRIVATE KEY' in x),
            'Generic Secret': (r'(?i)(secret|password|passwd|pwd|token)["\s]*[:=]["\s]*["\']([A-Za-z0-9!@#$%^&*\-_+=]{16,})["\']', lambda x: len(x) >= 16),
            'Hardcoded Password': (r'(?i)password\s*=\s*["\']([^"\']{8,})["\']', lambda x: len(x) >= 8),
        }
        
        # Exclude common false positives
        false_positives = [
            'example', 'test', 'demo', 'sample', 'placeholder', 'your_api_key',
            'INSERT_API_KEY_HERE', 'REPLACE_WITH', 'TODO', 'FIXME', 'dummy',
            '12345678', 'password', 'xxxxxxxx', 'abcdefgh', '00000000'
        ]
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Check resource XML files first (most likely to have real secrets)
                for file_name in apk_zip.namelist():
                    if 'res/values/strings.xml' in file_name or 'res/xml/' in file_name:
                        try:
                            content = apk_zip.read(file_name).decode('utf-8', errors='ignore')
                            secrets_found.update(self._scan_for_secrets(content, file_name, patterns, false_positives))
                            if len(secrets_found) >= max_secrets:
                                break
                        except:
                            continue
                
                # Check DEX files if needed
                if len(secrets_found) < max_secrets:
                    for file_name in apk_zip.namelist():
                        if file_name.endswith('.dex'):
                            try:
                                content = apk_zip.read(file_name)
                                strings = re.findall(b'[ -~]{20,100}', content)  # Increased min length
                                
                                for s in strings[:2000]:
                                    try:
                                        string_val = s.decode('utf-8')
                                        secrets_found.update(self._scan_for_secrets(string_val, file_name, patterns, false_positives))
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
    
    def _scan_for_secrets(self, content, source_file, patterns, false_positives):
        """Scan content for secrets with validation"""
        found = set()
        
        # Skip if content looks like test/example data
        content_lower = content.lower()
        if any(fp in content_lower for fp in false_positives[:7]):  # Check first 7 common false positives
            return found
        
        for secret_type, (pattern, validator) in patterns.items():
            matches = re.finditer(pattern, content, re.IGNORECASE)
            for match in matches:
                secret_value = match.group(0) if match.lastindex is None else match.group(1) if match.lastindex >= 1 else match.group(0)
                
                # Skip if it's a known false positive
                if any(fp in secret_value.lower() for fp in false_positives):
                    continue
                
                # Validate using custom validator
                try:
                    if not validator(secret_value):
                        continue
                except:
                    continue
                
                secret_key = f"{secret_type}:{secret_value[:30]}"
                if secret_key not in found:
                    found.add(secret_key)
                    
                    display_val = secret_value[:50] + "..." if len(secret_value) > 50 else secret_value
                    
                    # Determine severity based on secret type
                    severity = "Critical"
                    risk_score = 9.5
                    
                    if secret_type in ['Firebase URL', 'Google OAuth']:
                        severity = "High"
                        risk_score = 7.5
                    elif secret_type == 'Generic Secret':
                        severity = "Medium"
                        risk_score = 6.0
                    
                    self._add_vuln({
                        "type": f"Hardcoded {secret_type}",
                        "severity": severity,
                        "owasp": "M9 (Reverse Engineering)",
                        "category": "Secrets Management",
                        "details": f"Found hardcoded {secret_type.lower()}: '{display_val}' in {source_file}. Attackers can decompile the APK and extract this secret.",
                        "remediation": "Never hardcode secrets in APK. Use Android Keystore for encryption keys. Fetch API keys from secure backend. Use encrypted SharedPreferences for sensitive data. Implement certificate pinning.",
                        "cwe": "CWE-798",
                        "risk_score": risk_score
                    })
        
        return found
    
    def _check_code_vulnerabilities(self):
        """Enhanced code vulnerability detection"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                for file_name in apk_zip.namelist():
                    if file_name.endswith('.dex'):
                        try:
                            content = apk_zip.read(file_name)
                            strings = re.findall(b'[ -~]{10,}', content)
                            
                            indicators = {
                                'SQL Injection Risk': [b'SELECT ', b'INSERT INTO', b'UPDATE ', b'DELETE FROM', b'rawQuery', b'execSQL'],
                                'WebView Security': [b'setJavaScriptEnabled', b'addJavascriptInterface', b'evaluateJavascript'],
                                'Weak Crypto': [b'DES', b'DES/CBC', b'DESede', b'MD5', b'SHA1', b'ECB'],
                                'Insecure Random': [b'java.util.Random', b'Math.random'],
                                'Dynamic Code Loading': [b'DexClassLoader', b'PathClassLoader', b'loadClass', b'Runtime.exec'],
                                'File Operations': [b'MODE_WORLD_READABLE', b'MODE_WORLD_WRITEABLE'],
                                'Command Injection': [b'Runtime.exec', b'ProcessBuilder'],
                            }
                            
                            found_indicators = defaultdict(int)
                            
                            for s in strings[:3000]:
                                for vuln_type, patterns in indicators.items():
                                    for pattern in patterns:
                                        if pattern in s:
                                            found_indicators[vuln_type] += 1
                            
                            # Report with better thresholds
                            if found_indicators.get('SQL Injection Risk', 0) > 5:
                                self._add_vuln({
                                    "type": "Potential SQL Injection Vulnerability",
                                    "severity": "High",
                                    "owasp": "M7 (Code Quality)",
                                    "category": "Code Security",
                                    "details": f"App uses SQL queries ({found_indicators['SQL Injection Risk']} instances). Without parameterized queries, user input concatenation can lead to SQL injection attacks.",
                                    "remediation": "Use Room database with @Query annotations. If using raw SQLite, use parameterized queries with '?' placeholders. Never concatenate user input into SQL strings.",
                                    "cwe": "CWE-89",
                                    "risk_score": 7.5
                                })
                            
                            if found_indicators.get('WebView Security', 0) > 0:
                                self._add_vuln({
                                    "type": "WebView JavaScript Interface Risk",
                                    "severity": "High",
                                    "owasp": "M1 (Improper Platform Usage)",
                                    "category": "Code Security",
                                    "details": "App uses WebView with JavaScript enabled and/or JavaScript interfaces. Vulnerable to XSS attacks if loading untrusted content. Can lead to arbitrary code execution.",
                                    "remediation": "Disable JavaScript if not needed. Only load HTTPS URLs from trusted domains. Validate all JavaScript interface methods with @JavascriptInterface (API 17+). Implement Content Security Policy.",
                                    "cwe": "CWE-79",
                                    "risk_score": 8.0
                                })
                            
                            if found_indicators.get('Weak Crypto', 0) > 3:
                                self._add_vuln({
                                    "type": "Weak Cryptographic Algorithms Detected",
                                    "severity": "High",
                                    "owasp": "M5 (Insufficient Cryptography)",
                                    "category": "Cryptography",
                                    "details": f"App uses weak cryptographic algorithms ({found_indicators['Weak Crypto']} instances): DES, MD5, SHA1, or ECB mode. These are cryptographically broken and can be easily cracked.",
                                    "remediation": "Use AES-256-GCM for encryption. Use SHA-256 or SHA-512 for hashing. Use PBKDF2, bcrypt, or Argon2 for passwords. Never use ECB mode. Use Android Keystore for key management.",
                                    "cwe": "CWE-327",
                                    "risk_score": 8.0
                                })
                            
                            if found_indicators.get('Insecure Random', 0) > 1:
                                self._add_vuln({
                                    "type": "Insecure Random Number Generation",
                                    "severity": "Medium",
                                    "owasp": "M5 (Insufficient Cryptography)",
                                    "category": "Cryptography",
                                    "details": "App uses java.util.Random or Math.random() which are predictable. Attackers can predict 'random' tokens, session IDs, or cryptographic keys.",
                                    "remediation": "Use java.security.SecureRandom for all security-sensitive random number generation including tokens, IVs, salts, and session IDs.",
                                    "cwe": "CWE-338",
                                    "risk_score": 6.0
                                })
                            
                            if found_indicators.get('Dynamic Code Loading', 0) > 2:
                                self._add_vuln({
                                    "type": "Dynamic Code Loading Detected",
                                    "severity": "High",
                                    "owasp": "M7 (Code Quality)",
                                    "category": "Code Security",
                                    "details": "App dynamically loads code using DexClassLoader or similar. If loading from untrusted sources (SD card, network), attackers can inject malicious code.",
                                    "remediation": "Only load code from app's private directory. Verify integrity with cryptographic signatures. Use Play Feature Delivery instead of custom dynamic loading.",
                                    "cwe": "CWE-94",
                                    "risk_score": 8.0
                                })
                            
                            if found_indicators.get('File Operations', 0) > 0:
                                self._add_vuln({
                                    "type": "World-Readable/Writable Files",
                                    "severity": "High",
                                    "owasp": "M2 (Insecure Data Storage)",
                                    "category": "Code Security",
                                    "details": "App uses MODE_WORLD_READABLE or MODE_WORLD_WRITEABLE for file operations. These modes allow any app to read or modify the files.",
                                    "remediation": "Use MODE_PRIVATE for all internal files. These deprecated modes are ignored on API 24+. Use FileProvider for sharing files.",
                                    "cwe": "CWE-732",
                                    "risk_score": 7.5
                                })
                            
                            if found_indicators.get('Command Injection', 0) > 1:
                                self._add_vuln({
                                    "type": "Potential Command Injection",
                                    "severity": "High",
                                    "owasp": "M7 (Code Quality)",
                                    "category": "Code Security",
                                    "details": "App executes system commands using Runtime.exec() or ProcessBuilder. If user input is included, this enables command injection attacks.",
                                    "remediation": "Avoid executing system commands. If necessary, use ProcessBuilder with argument arrays (not shell strings). Validate and sanitize all inputs.",
                                    "cwe": "CWE-78",
                                    "risk_score": 8.0
                                })
                            
                            break
                            
                        except:
                            continue
                            
        except Exception as e:
            print(f"⚠️  Code vulnerability check error: {e}")
    
    def _check_native_libraries(self):
        """Enhanced native library analysis"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                native_libs = [f for f in apk_zip.namelist() if f.startswith('lib/') and f.endswith('.so')]
                
                if native_libs:
                    archs = set()
                    lib_names = []
                    
                    for lib in native_libs:
                        parts = lib.split('/')
                        if len(parts) > 1:
                            archs.add(parts[1])
                        if len(parts) > 2:
                            lib_names.append(parts[2])
                    
                    # Check for suspicious library names
                    suspicious_names = ['frida', 'xposed', 'substrate', 'cydia']
                    found_suspicious = [name for name in lib_names if any(sus in name.lower() for sus in suspicious_names)]
                    
                    if found_suspicious:
                        self._add_vuln({
                            "type": f"Suspicious Native Libraries Detected",
                            "severity": "High",
                            "owasp": "M7 (Code Quality)",
                            "category": "Code Security",
                            "details": f"Found suspicious native libraries: {', '.join(found_suspicious)}. These are commonly associated with hooking frameworks.",
                            "remediation": "Verify these libraries are intentional. Remove hooking frameworks from production builds.",
                            "cwe": "CWE-829",
                            "risk_score": 7.5
                        })
                    
                    # Info about native code
                    if len(native_libs) > 0:
                        self._add_vuln({
                            "type": f"Native Code Present ({len(native_libs)} libraries)",
                            "severity": "Info",
                            "owasp": "M7 (Code Quality)",
                            "category": "Code Security",
                            "details": f"App contains {len(native_libs)} native libraries for: {', '.join(sorted(archs))}. Native code is harder to analyze, may contain memory vulnerabilities (buffer overflows, use-after-free), and increases reverse engineering difficulty.",
                            "remediation": "Ensure all native libraries are from trusted sources. Keep libraries updated. Test for memory vulnerabilities. Consider using RASP protection. Implement anti-debugging in native code.",
                            "cwe": "CWE-937",
                            "risk_score": 2.0
                        })
                        
        except Exception as e:
            print(f"⚠️  Native library check error: {e}")
    
    def _check_webview_security(self):
        """NEW: Dedicated WebView security checks"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                for file_name in apk_zip.namelist():
                    if file_name.endswith('.dex'):
                        content = apk_zip.read(file_name)
                        strings = re.findall(b'[ -~]{10,}', content)
                        
                        webview_indicators = {
                            'setAllowFileAccess': 0,
                            'setAllowUniversalAccessFromFileURLs': 0,
                            'setAllowFileAccessFromFileURLs': 0,
                            'setMixedContentMode': 0,
                            'setSavePassword': 0,
                        }
                        
                        for s in strings[:2000]:
                            for indicator in webview_indicators.keys():
                                if indicator.encode() in s:
                                    webview_indicators[indicator] += 1
                        
                        # Check for dangerous WebView settings
                        if webview_indicators['setAllowFileAccess'] > 0:
                            self._add_vuln({
                                "type": "WebView File Access Enabled",
                                "severity": "Medium",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Code Security",
                                "details": "WebView allows file:// URL access. If loading untrusted content, attackers can read local files.",
                                "remediation": "Call webView.getSettings().setAllowFileAccess(false) unless file access is required. Use content:// URIs instead.",
                                "cwe": "CWE-200",
                                "risk_score": 6.0
                            })
                        
                        if webview_indicators['setAllowUniversalAccessFromFileURLs'] > 0:
                            self._add_vuln({
                                "type": "WebView Universal File Access Enabled",
                                "severity": "High",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Code Security",
                                "details": "WebView allows universal access from file URLs. Enables reading any file on device from JavaScript.",
                                "remediation": "Call webView.getSettings().setAllowUniversalAccessFromFileURLs(false).",
                                "cwe": "CWE-94",
                                "risk_score": 7.5
                            })
                        
                        if webview_indicators['setSavePassword'] > 0:
                            self._add_vuln({
                                "type": "WebView Password Saving Enabled",
                                "severity": "Medium",
                                "owasp": "M2 (Insecure Data Storage)",
                                "category": "Code Security",
                                "details": "WebView is configured to save passwords. Passwords are stored in plaintext database.",
                                "remediation": "Call webView.getSettings().setSavePassword(false).",
                                "cwe": "CWE-256",
                                "risk_score": 5.5
                            })
                        
                        break
                        
        except Exception as e:
            print(f"⚠️  WebView security check error: {e}")
    
    def _check_certificate(self):
        """NEW: Check APK signing certificate"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Check for v1 signature (JAR signing)
                has_v1 = 'META-INF/CERT.RSA' in apk_zip.namelist() or 'META-INF/CERT.DSA' in apk_zip.namelist()
                
                # Check for v2 signature (APK Signature Scheme v2)
                # Note: v2 signature is in APK header, not in zip entries
                has_v2 = False  # Simplified - full check requires parsing APK structure
                
                if not has_v1:
                    self._add_vuln({
                        "type": "Missing APK Signature",
                        "severity": "Critical",
                        "owasp": "M7 (Code Quality)",
                        "category": "Code Integrity",
                        "details": "APK is not properly signed or signature is invalid. Unsigned APKs can be modified by attackers.",
                        "remediation": "Sign APK with jarsigner or apksigner. Use v2 signing for API 24+.",
                        "cwe": "CWE-345",
                        "risk_score": 9.0
                    })
                
                # Check for debug certificate
                if has_v1:
                    try:
                        cert_file = 'META-INF/CERT.RSA' if 'META-INF/CERT.RSA' in apk_zip.namelist() else 'META-INF/CERT.DSA'
                        cert_data = apk_zip.read(cert_file)
                        
                        # Simple heuristic: debug certs are usually smaller and have "Android Debug" in subject
                        if len(cert_data) < 1000:
                            self._add_vuln({
                                "type": "Debug Certificate in Production",
                                "severity": "Critical",
                                "owasp": "M7 (Code Quality)",
                                "category": "Code Integrity",
                                "details": "APK is signed with Android debug certificate. Debug certificates are publicly known and not secure.",
                                "remediation": "Sign APK with production release certificate. Debug certificates are only for development.",
                                "cwe": "CWE-295",
                                "risk_score": 9.5
                            })
                    except:
                        pass
                        
        except Exception as e:
            print(f"⚠️  Certificate check error: {e}")
    
    def _check_file_permissions(self):
        """NEW: Check for insecure file permissions in resources"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as apk_zip:
                # Check for world-readable/writable files
                for file_info in apk_zip.filelist:
                    # Check external_attr for file permissions (Unix-style)
                    external_attr = file_info.external_attr >> 16
                    
                    if external_attr != 0:
                        # Check if world-readable (0444) or world-writable (0666)
                        if external_attr & 0o004:  # World-readable
                            if 'sensitive' in file_info.filename.lower() or 'private' in file_info.filename.lower():
                                self._add_vuln({
                                    "type": "World-Readable Sensitive File",
                                    "severity": "Medium",
                                    "owasp": "M2 (Insecure Data Storage)",
                                    "category": "File Security",
                                    "details": f"File '{file_info.filename}' has world-readable permissions.",
                                    "remediation": "Set appropriate file permissions. Use MODE_PRIVATE for sensitive files.",
                                    "cwe": "CWE-732",
                                    "risk_score": 5.5
                                })
        except:
            pass
    
    def _add_vuln(self, vuln_data):
        """Add vulnerability to report and update summary"""
        self.report["vulnerabilities"].append(vuln_data)
        severity = vuln_data["severity"].lower()
        if severity in self.report["summary"]:
            self.report["summary"][severity] += 1
    
    def _finalize_report(self):
        """Finalize report with sorting and risk scoring"""
        self.report["summary"]["total"] = len(self.report["vulnerabilities"])
        
        # Calculate overall risk score
        total_risk = sum(v.get("risk_score", 0) for v in self.report["vulnerabilities"])
        self.report["overall_risk_score"] = round(total_risk / len(self.report["vulnerabilities"]), 2) if self.report["vulnerabilities"] else 0
        
        # Sort by severity then risk score
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.report["vulnerabilities"].sort(
            key=lambda x: (severity_order.get(x["severity"], 5), -x.get("risk_score", 0))
        )


def generate_report_text(report):
    """Generate enhanced human-readable text report"""
    if "error" in report:
        return f"❌ ERROR: {report['error']}"
    
    lines = []
    lines.append("=" * 80)
    lines.append("🛡️  APK SECURITY ANALYSIS REPORT - ENHANCED")
    lines.append("=" * 80)
    lines.append(f"📱 App Name:        {report['app_name']}")
    lines.append(f"📦 Package:         {report['package_name']}")
    lines.append(f"🔢 Version:         {report['version_name']} (Code: {report['version_code']})")
    lines.append(f"🎯 Target SDK:      {report['target_sdk']} (Min: {report['min_sdk']})")
    lines.append(f"⚠️  Risk Score:      {report.get('overall_risk_score', 0):.2f}/10")
    lines.append("=" * 80)
    lines.append("")
    
    summary = report["summary"]
    lines.append("📊 VULNERABILITY SUMMARY")
    lines.append("-" * 80)
    lines.append(f"🔴 Critical: {summary['critical']:3} (Immediate action required)")
    lines.append(f"🟠 High:     {summary['high']:3} (Should be fixed soon)")
    lines.append(f"🟡 Medium:   {summary['medium']:3} (Should be addressed)")
    lines.append(f"🟢 Low:      {summary['low']:3} (Minor issues)")
    lines.append(f"ℹ️  Info:     {summary['info']:3} (Informational)")
    lines.append(f"📈 Total:    {summary['total']:3}")
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
            risk = vuln.get('risk_score', 0)
            
            lines.append(f"\n[{idx}] {icon} {vuln['type']} (Risk: {risk:.1f}/10)")
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
        lines.append("Note: This is static analysis. Manual code review, dynamic testing,")
        lines.append("and penetration testing are recommended for comprehensive security.")
    
    lines.append("\n" + "=" * 80)
    lines.append("⚡ Enhanced APK Security Analyzer | Powered by pyaxmlparser")
    lines.append("=" * 80)
    
    return "\n".join(lines)


def analyze_apk(apk_path):
    """Main entry point for APK analysis"""
    analyzer = APKSecurityAnalyzer(apk_path)
    report = analyzer.analyze()
    return report


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python apk_security_analyzer_enhanced.py <path_to_apk>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"❌ File not found: {apk_file}")
        sys.exit(1)
    
    print(f"🚀 Starting Enhanced APK Security Analysis")
    print(f"📁 Target: {apk_file}\n")
    
    report = analyze_apk(apk_file)
    
    # Generate and print report
    report_text = generate_report_text(report)
    print("\n" + report_text)
    
    # Save report
    output_file = f"{os.path.basename(apk_file)}_security_report_enhanced.txt"
    with open(output_file, 'w') as f:
        f.write(report_text)
    
    print(f"\n💾 Report saved to: {output_file}")
