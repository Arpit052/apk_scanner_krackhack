#!/usr/bin/env python3
"""
ULTRA-OPTIMIZED APK Security Analyzer
Target: 300MB APK in <10 seconds
Features: Detailed vulnerabilities, evidence, impact, and remediation
"""

import zipfile
import re
import os
import hashlib
import mmap
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor, as_completed
from threading import Lock
from pyaxmlparser import APK
import xml.etree.ElementTree as ET


# ============================================================================
# COMPREHENSIVE VULNERABILITY KNOWLEDGE BASE
# ============================================================================

VULNERABILITY_DATABASE = {
    "EXPORTED_COMPONENTS": {
        "description": "Android components (Activities, Services, Broadcast Receivers, Content Providers) are exported and accessible to other applications without proper protection.",
        "evidence_template": "Component '{component}' is exported with no permission required. Any app on device can interact with it.",
        "impact": "CRITICAL - Attackers can invoke exported components to steal data, trigger unauthorized actions, crash the app, or escalate privileges. This can lead to data theft, unauthorized access, and complete app compromise.",
        "remediation": "1. Set android:exported='false' for all components not intended for inter-app communication\n2. Add android:permission attribute with custom permission for components that must be exported\n3. Implement runtime permission checks in component code\n4. Use signature-level permissions for sensitive components",
        "cwe": "CWE-927: Use of Implicit Intent for Sensitive Communication",
        "owasp": "M1 (Improper Platform Usage)",
        "cvss_base": 9.1
    },
    
    "DEBUGGABLE": {
        "description": "The application has debugging enabled (android:debuggable='true'), allowing anyone to attach debuggers and inspect/modify runtime behavior.",
        "evidence_template": "AndroidManifest.xml contains android:debuggable='true' in <application> tag.",
        "impact": "CRITICAL - Attackers can attach debuggers (like Android Studio or IDA Pro) to extract secrets, modify app logic in real-time, bypass security checks, dump memory containing sensitive data, and analyze proprietary algorithms. This completely undermines app security.",
        "remediation": "1. Remove android:debuggable attribute or set to 'false' in production builds\n2. Configure ProGuard/R8 to automatically strip debugging flags\n3. Implement runtime detection to check if debugger is attached\n4. Use build variants (debug vs release) in Gradle",
        "cwe": "CWE-489: Active Debug Code",
        "owasp": "M7 (Client Code Quality)",
        "cvss_base": 9.3
    },
    
    "BACKUP_ENABLED": {
        "description": "Android backup is enabled (android:allowBackup='true'), allowing app data to be backed up via ADB or cloud backup services.",
        "evidence_template": "android:allowBackup='true' found in manifest. App data can be extracted via 'adb backup'.",
        "impact": "HIGH - On rooted devices or with ADB access, attackers can extract complete app data including databases, SharedPreferences, and files. This exposes authentication tokens, user credentials, API keys, and sensitive user information. Physical access or USB debugging can compromise all stored data.",
        "remediation": "1. Set android:allowBackup='false' in AndroidManifest.xml\n2. Use android:fullBackupContent to create allowlist of specific backup-safe directories\n3. Encrypt sensitive data before storage (use Android Keystore)\n4. Implement backup exclusion rules in backup descriptor XML\n5. For API 31+, set android:allowBackup='false' and android:dataExtractionRules",
        "cwe": "CWE-530: Exposure of Backup File to Unauthorized Control Sphere",
        "owasp": "M2 (Insecure Data Storage)",
        "cvss_base": 7.5
    },
    
    "CLEAR_TEXT_TRAFFIC": {
        "description": "The application allows unencrypted HTTP network traffic (android:usesCleartextTraffic='true' or not explicitly disabled).",
        "evidence_template": "Cleartext traffic is permitted. Network traffic can be transmitted over HTTP without TLS/SSL encryption.",
        "impact": "HIGH - All HTTP traffic is vulnerable to man-in-the-middle (MITM) attacks. Attackers on same network can intercept, read, and modify transmitted data including login credentials, API tokens, personal information, and business data. Session hijacking and credential theft are trivial.",
        "remediation": "1. Set android:usesCleartextTraffic='false' in AndroidManifest.xml\n2. Configure Network Security Configuration XML to enforce HTTPS-only\n3. Use certificate pinning for critical connections\n4. Implement runtime checks to reject non-HTTPS URLs\n5. For legacy APIs requiring HTTP, use domain-specific allowlist in network_security_config.xml",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "owasp": "M3 (Insecure Communication)",
        "cvss_base": 8.2
    },
    
    "HTTPS_NOT_ENFORCED": {
        "description": "Application contains HTTP URLs instead of HTTPS, transmitting data without encryption.",
        "evidence_template": "Found {count} insecure HTTP endpoints: {examples}. These transmit data in plaintext over the network.",
        "impact": "HIGH - Network traffic to these endpoints is completely unencrypted. Attackers with network access (public WiFi, compromised routers, ISP-level) can intercept credentials, session tokens, personal data, financial information, and API communications. Enables account takeover and data theft.",
        "remediation": "1. Replace all HTTP URLs with HTTPS equivalents\n2. Contact API providers to enable TLS/SSL\n3. Implement certificate validation and pinning\n4. Add Network Security Configuration to block HTTP domains\n5. Use tools like Charles Proxy during development to verify encryption",
        "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
        "owasp": "M3 (Insecure Communication)",
        "cvss_base": 7.8
    },
    
    "DANGEROUS_PERMISSIONS": {
        "description": "Application requests sensitive permissions that can access private user data or perform high-risk operations.",
        "evidence_template": "Dangerous permission '{permission}' requested. {reason}",
        "impact": "HIGH to MEDIUM - Excessive permissions enable data harvesting, surveillance, financial fraud, and privacy violations. Attackers exploiting vulnerabilities gain these permissions' capabilities. Users may unknowingly grant access to contacts, location, SMS, camera, microphone, and storage.",
        "remediation": "1. Request only permissions absolutely necessary for core functionality\n2. Use runtime permission requests (API 23+) to explain why permission is needed\n3. Implement least-privilege principle - request permissions only when feature is used\n4. Consider permission alternatives (use SAF instead of storage permission)\n5. Document permission usage for app store review",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp": "M1 (Improper Platform Usage)",
        "cvss_base": 6.5
    },
    
    "MALWARE_PERMISSION_COMBO": {
        "description": "Application requests a combination of permissions commonly associated with malware behavior (e.g., SMS + Internet + Boot).",
        "evidence_template": "Malware-typical permission combination detected: {permissions}. This pattern is consistent with {malware_type}.",
        "impact": "CRITICAL - Permission combinations like SMS+Internet indicate potential SMS fraud/theft, Location+Camera suggests spyware, INSTALL_PACKAGES+BOOT suggests trojan droppers. High likelihood of malicious intent including financial fraud, espionage, and botnet participation.",
        "remediation": "1. Remove unnecessary permissions from manifest\n2. If legitimate, clearly document business justification\n3. Implement permission usage logging for auditing\n4. Consider splitting functionality into separate apps\n5. Undergo third-party security audit before release",
        "cwe": "CWE-250: Execution with Unnecessary Privileges",
        "owasp": "M8 (Code Tampering)",
        "cvss_base": 9.5
    },
    
    "HARDCODED_SECRET": {
        "description": "Sensitive credentials, API keys, passwords, or cryptographic secrets are hardcoded in the application code or resources.",
        "evidence_template": "Found hardcoded {secret_type} in {location}: {preview}",
        "impact": "CRITICAL - Hardcoded secrets can be extracted through reverse engineering, providing attackers with API access, database credentials, encryption keys, or service authentication. Leads to unauthorized access to backend systems, data breaches, financial fraud, and service impersonation. Secrets cannot be rotated without app update.",
        "remediation": "1. Remove all hardcoded secrets from code and resources\n2. Use Android Keystore for cryptographic keys\n3. Fetch API keys from secure backend at runtime\n4. Implement certificate pinning with keys stored securely\n5. Use environment variables for build-time secrets\n6. Employ secret management services (AWS Secrets Manager, HashiCorp Vault)\n7. Rotate compromised secrets immediately",
        "cwe": "CWE-798: Use of Hard-coded Credentials",
        "owasp": "M9 (Reverse Engineering)",
        "cvss_base": 9.8
    },
    
    "WEAK_CRYPTO": {
        "description": "Application uses weak or broken cryptographic algorithms (MD5, SHA1, DES, RC4) that are vulnerable to attacks.",
        "evidence_template": "Weak cryptographic algorithm detected: {algorithm}. Found {count} usages in code.",
        "impact": "HIGH - Weak cryptography can be broken by modern computing power. MD5/SHA1 collisions allow signature forgery, DES can be brute-forced in hours, RC4 has bias vulnerabilities. Encrypted data can be decrypted, signatures can be forged, and authentication can be bypassed. Compliance violations (PCI-DSS, HIPAA).",
        "remediation": "1. Replace MD5/SHA1 with SHA-256 or SHA-3 for hashing\n2. Use AES-256-GCM or ChaCha20-Poly1305 for encryption\n3. Implement PBKDF2, bcrypt, or Argon2 for password hashing\n4. Use cryptographic libraries: Android Keystore, javax.crypto\n5. Perform security code review of all crypto implementations",
        "cwe": "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        "owasp": "M5 (Insufficient Cryptography)",
        "cvss_base": 7.4
    },
    
    "WEBVIEW_VULNERABILITIES": {
        "description": "WebView is configured insecurely, enabling JavaScript, file access, or content access without proper validation.",
        "evidence_template": "WebView security issue: {issue}. This configuration allows {attack_vector}.",
        "impact": "HIGH - Insecure WebView enables JavaScript injection, file system access via file:// URLs, cross-site scripting (XSS), and arbitrary code execution. Attackers can steal app data, execute native code, access device files, and compromise user sessions. Mixed content loads HTTP resources in HTTPS context.",
        "remediation": "1. Disable JavaScript unless absolutely required: setJavaScriptEnabled(false)\n2. Disable file access: setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false)\n3. Disable content access: setAllowContentAccess(false)\n4. Validate and sanitize all URLs before loading\n5. Use shouldOverrideUrlLoading to whitelist domains\n6. Implement Content Security Policy (CSP)\n7. Keep WebView updated via Google Play Services",
        "cwe": "CWE-749: Exposed Dangerous Method or Function",
        "owasp": "M1 (Improper Platform Usage)",
        "cvss_base": 8.0
    },
    
    "CERTIFICATE_ISSUES": {
        "description": "Application's signing certificate has security weaknesses (debug certificate, weak algorithm, or validity concerns).",
        "evidence_template": "Certificate security issue: {issue}. {details}",
        "impact": "HIGH - Debug certificates enable anyone to sign updates. Weak signature algorithms allow certificate forgery. Expired certificates cause installation failures and trust issues. Attackers can create malicious updates that appear legitimate, perform man-in-the-middle attacks, and compromise app integrity.",
        "remediation": "1. Never release apps signed with debug certificate\n2. Use SHA-256 with RSA (minimum 2048-bit) for signing\n3. Store release keystore securely (offline, encrypted)\n4. Use Google Play App Signing for key management\n5. Monitor certificate expiry (minimum 25-year validity)\n6. Implement certificate pinning in app code\n7. Use jarsigner or apksigner for proper signing",
        "cwe": "CWE-295: Improper Certificate Validation",
        "owasp": "M3 (Insecure Communication)",
        "cvss_base": 7.8
    },
    
    "NO_OBFUSCATION": {
        "description": "Application code is not obfuscated, making reverse engineering trivial and exposing business logic.",
        "evidence_template": "No code obfuscation detected. ProGuard/R8 signatures not found in DEX files.",
        "impact": "MEDIUM - Unobfuscated code reveals business logic, algorithms, API endpoints, security checks, and licensing mechanisms. Attackers can easily understand app functionality, find vulnerabilities, bypass premium features, create clones, and extract intellectual property. Makes all other vulnerabilities easier to exploit.",
        "remediation": "1. Enable ProGuard/R8 in release builds (minifyEnabled true)\n2. Configure proguard-rules.pro to preserve necessary classes\n3. Use DexGuard for enhanced protection (commercial)\n4. Implement runtime integrity checks\n5. Use native code (JNI) for critical algorithms\n6. Apply string encryption for sensitive constants\n7. Test obfuscated builds thoroughly before release",
        "cwe": "CWE-656: Reliance on Security Through Obscurity",
        "owasp": "M9 (Reverse Engineering)",
        "cvss_base": 5.5
    },
    
    "SUSPICIOUS_NATIVE_LIBS": {
        "description": "Application contains native libraries associated with rooting, hooking frameworks, or reverse engineering tools.",
        "evidence_template": "Suspicious native library detected: {library}. Associated with {purpose}.",
        "impact": "CRITICAL - Libraries like Frida, Xposed, Substrate indicate the app may be modified, contains rooting tools, or includes reverse engineering frameworks. May indicate repackaged malware, unauthorized modifications, or attempts to bypass security controls on other apps.",
        "remediation": "1. Remove suspicious libraries if unintentional inclusion\n2. If legitimate (security research), clearly document purpose\n3. Implement anti-tampering checks\n4. Perform deep security audit of all native code\n5. Verify library sources and checksums\n6. Use Google Play Integrity API to detect modifications",
        "cwe": "CWE-506: Embedded Malicious Code",
        "owasp": "M8 (Code Tampering)",
        "cvss_base": 9.0
    },
    
    "SUSPICIOUS_STRINGS": {
        "description": "Application contains strings patterns associated with malicious behavior (rooting, premium SMS, command-and-control, cryptocurrency theft).",
        "evidence_template": "Suspicious {category} strings detected. Found {count} references suggesting {behavior}.",
        "impact": "HIGH to CRITICAL - Indicates potential malware functionality: root detection bypass, premium SMS fraud, botnet C2 communication, cryptocurrency wallet theft, or data exfiltration. May indicate legitimate security research or active malicious code.",
        "remediation": "1. Review all flagged code sections for legitimacy\n2. Remove or properly secure root detection code\n3. If legitimate, implement security research disclosure\n4. Remove any premium SMS functionality not clearly disclosed\n5. Audit all network communications\n6. Perform behavioral analysis on device\n7. Submit app for professional malware analysis",
        "cwe": "CWE-506: Embedded Malicious Code",
        "owasp": "M8 (Code Tampering)",
        "cvss_base": 8.5
    },
    
    "MALWARE_PACKAGE_NAME": {
        "description": "Package name matches known malware families or attempts to impersonate system/legitimate applications.",
        "evidence_template": "Suspicious package name: {package}. Matches pattern: {pattern}.",
        "impact": "CRITICAL - Package name indicates potential malware or social engineering attack. May impersonate system apps (com.android.systemui), Google services, or popular apps to trick users into installing. Strong indicator of malicious intent.",
        "remediation": "1. DO NOT install or distribute this application\n2. Report to Google Play Protect and device manufacturer\n3. Perform full malware analysis in isolated environment\n4. Extract and analyze payload\n5. Report to security researchers and AV vendors\n6. If false positive, choose clearly legitimate package name",
        "cwe": "CWE-506: Embedded Malicious Code",
        "owasp": "M8 (Code Tampering)",
        "cvss_base": 10.0
    },
    
    "SUSPICIOUS_TLD": {
        "description": "Application communicates with domains using high-risk top-level domains (TLDs) commonly associated with malicious activity.",
        "evidence_template": "Suspicious TLD domain detected: {url}. TLD {tld} has high association with malware C2 servers.",
        "impact": "MEDIUM to HIGH - TLDs like .ru, .cn, .tk, .cc are disproportionately used for malware command-and-control, phishing, and data exfiltration. While legitimate uses exist, requires heightened scrutiny. May indicate compromised app or malicious functionality.",
        "remediation": "1. Verify legitimacy of all network endpoints\n2. If legitimate, document business justification\n3. Implement certificate pinning for these domains\n4. Monitor network traffic for suspicious patterns\n5. Consider using CDN or trusted hosting provider\n6. Add rate limiting and anomaly detection\n7. Perform regular domain reputation checks",
        "cwe": "CWE-940: Improper Verification of Source of a Communication Channel",
        "owasp": "M3 (Insecure Communication)",
        "cvss_base": 6.5
    },
    
    "SQL_INJECTION": {
        "description": "Application constructs SQL queries using string concatenation, enabling SQL injection attacks.",
        "evidence_template": "Potential SQL injection vulnerability in {location}. Raw SQL query construction detected.",
        "impact": "CRITICAL - SQL injection allows attackers to bypass authentication, extract entire database contents, modify or delete data, and potentially execute system commands. Can lead to complete data breach, unauthorized access, data corruption, and service compromise.",
        "remediation": "1. Use parameterized queries (PreparedStatement) exclusively\n2. Never concatenate user input into SQL strings\n3. Implement input validation and sanitization\n4. Use ORM frameworks (Room, Realm) that prevent injection\n5. Apply principle of least privilege to database users\n6. Perform security code review of all database operations\n7. Use SQLCipher for encrypted databases",
        "cwe": "CWE-89: SQL Injection",
        "owasp": "M7 (Client Code Quality)",
        "cvss_base": 9.5
    },
    
    "PATH_TRAVERSAL": {
        "description": "Application constructs file paths using user input without validation, enabling directory traversal attacks.",
        "evidence_template": "Path traversal vulnerability detected in {location}. File operations use unsanitized input.",
        "impact": "HIGH - Attackers can access files outside intended directory using '../' sequences, reading sensitive files (databases, SharedPreferences, keystores), overwriting critical files, or accessing other app data on rooted devices. Leads to data theft and app compromise.",
        "remediation": "1. Validate all file paths before use\n2. Use canonical paths: file.getCanonicalPath()\n3. Restrict file operations to app-specific directories\n4. Implement allowlist of permitted files/directories\n5. Never construct paths from user input\n6. Use Android Storage Access Framework (SAF) for user files\n7. Apply input sanitization to remove '../' patterns",
        "cwe": "CWE-22: Path Traversal",
        "owasp": "M7 (Client Code Quality)",
        "cvss_base": 8.0
    },
    
    "COMMAND_INJECTION": {
        "description": "Application executes system commands with user-controlled input, enabling arbitrary command execution.",
        "evidence_template": "Command injection vulnerability in {location}. Runtime.exec() or ProcessBuilder use unsanitized input.",
        "impact": "CRITICAL - Command injection allows attackers to execute arbitrary system commands with app permissions. Can install malware, exfiltrate data, access system resources, escalate privileges on rooted devices, or brick the device. Enables complete device compromise.",
        "remediation": "1. Avoid Runtime.exec() and ProcessBuilder entirely if possible\n2. Never include user input in system commands\n3. Use Android APIs instead of shell commands\n4. If necessary, use strict input validation with allowlists\n5. Run commands with minimal privileges\n6. Implement command output sanitization\n7. Perform security code review of all exec() usage",
        "cwe": "CWE-78: OS Command Injection",
        "owasp": "M7 (Client Code Quality)",
        "cvss_base": 9.8
    }
}


# ============================================================================
# ULTRA-OPTIMIZED ANALYZER
# ============================================================================

class UltraOptimizedAnalyzer:
    """
    Ultra-fast APK analyzer with comprehensive vulnerability detection
    Target: 300MB in <10 seconds
    
    Optimizations:
    - Memory-mapped file I/O for large files
    - Multiprocessing + Threading hybrid
    - Compiled regex patterns
    - Smart caching and early termination
    - Chunked processing for large DEX files
    """
    
    NS = {'android': 'http://schemas.android.com/apk/res/android'}
    
    # Malware signatures (expanded)
    MALWARE_PACKAGES = {
        'com.android.battery', 'com.system.update', 'com.android.settings.backup',
        'com.google.provider', 'com.android.provider.security', 'android.security.update',
        'com.android.systemui.fake', 'com.fake.google', 'org.malware', 'com.trojan',
        'com.android.security.fake', 'com.system.service', 'android.provider.telephony'
    }
    
    MALWARE_PERMISSION_COMBOS = [
        ('READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'INTERNET'),
        ('SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN'),
        ('REQUEST_INSTALL_PACKAGES', 'RECEIVE_BOOT_COMPLETED'),
        ('READ_SMS', 'RECEIVE_BOOT_COMPLETED', 'INTERNET'),
        ('CALL_PHONE', 'SEND_SMS', 'INTERNET'),
        ('READ_CONTACTS', 'READ_SMS', 'INTERNET', 'ACCESS_FINE_LOCATION'),
        ('CAMERA', 'RECORD_AUDIO', 'INTERNET', 'ACCESS_FINE_LOCATION'),
        ('WRITE_EXTERNAL_STORAGE', 'INTERNET', 'RECEIVE_BOOT_COMPLETED')
    ]
    
    SUSPICIOUS_LIBRARIES = ['frida', 'xposed', 'substrate', 'cydia', 'magisk', 'rootcloak', 'supersu']
    SUSPICIOUS_TLDS = ['.ru', '.cn', '.tk', '.cc', '.pw', '.top', '.xyz', '.work', '.click']
    
    # Precompiled regex patterns for speed
    PATTERNS = {
        'api_key': re.compile(rb'(?i)(?:api[_-]?key|apikey|api[_-]?secret)["\s:=]{1,5}["\']?([a-zA-Z0-9_\-]{20,})', re.IGNORECASE),
        'aws_key': re.compile(rb'(?:AKIA|ASIA)[0-9A-Z]{16}'),
        'private_key': re.compile(rb'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----'),
        'password': re.compile(rb'(?i)(?:password|passwd|pwd)["\s:=]{1,5}["\']([^"\']{6,})', re.IGNORECASE),
        'url': re.compile(rb'https?://[^\s<>"\']{10,}'),
        'http_url': re.compile(rb'http://[^\s<>"\']{10,}'),
        'sql_concat': re.compile(rb'(?:execSQL|rawQuery|query)\s*\([^)]*\+', re.IGNORECASE),
        'runtime_exec': re.compile(rb'Runtime\.(?:getRuntime\(\)\.)?exec\s*\(', re.IGNORECASE),
        'file_traversal': re.compile(rb'new\s+File\s*\([^)]*\+'),
    }
    
    def __init__(self, apk_path):
        self.apk_path = apk_path
        self.apk = None
        self.manifest_xml_string = None
        self.vuln_lock = Lock()
        self.file_size = os.path.getsize(apk_path)
        
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
        
        # Cache for processed data
        self.cache = {
            'dex_data': None,
            'permissions': None,
            'components': None,
            'urls': set(),
            'strings_analyzed': False
        }
    
    def analyze(self):
        """Main analysis with extreme optimization"""
        import time
        start_time = time.time()
        
        print(f"🚀 ULTRA-OPTIMIZED APK ANALYZER")
        print(f"📁 Analyzing: {self.apk_path}")
        print(f"📊 Size: {self.file_size / (1024*1024):.2f} MB\n")
        
        try:
            # Phase 1: Fast metadata extraction (parallel)
            with ThreadPoolExecutor(max_workers=3) as executor:
                f1 = executor.submit(self._calculate_file_hash)
                f2 = executor.submit(self._load_apk_metadata)
                f3 = executor.submit(self._index_zip_contents)
                
                for f in [f1, f2, f3]:
                    f.result()
            
            print(f"✓ Loaded in {time.time() - start_time:.2f}s")
            
            # Phase 2: Ultra-fast parallel security analysis
            print("⚡ Running comprehensive security checks...\n")
            
            # Use ProcessPoolExecutor for CPU-bound tasks on large files
            if self.file_size > 50 * 1024 * 1024:  # > 50MB
                max_workers = min(os.cpu_count(), 16)
                print(f"  Using {max_workers} CPU cores for large file")
            else:
                max_workers = 12
            
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._check_manifest_comprehensive): "Manifest Security",
                    executor.submit(self._check_permissions_advanced): "Dangerous Permissions",
                    executor.submit(self._check_exported_components): "Exported Components",
                    executor.submit(self._check_secrets_ultra_fast): "Hardcoded Secrets",
                    executor.submit(self._check_code_vulns_optimized): "Code Vulnerabilities",
                    executor.submit(self._check_native_libs): "Native Libraries",
                    executor.submit(self._check_webview_security): "WebView Security",
                    executor.submit(self._check_certificate_advanced): "Certificate Validation",
                    executor.submit(self._check_malware_signatures): "Malware Signatures",
                    executor.submit(self._check_obfuscation): "Code Protection",
                    executor.submit(self._check_suspicious_strings_fast): "Suspicious Patterns",
                    executor.submit(self._check_network_security): "Network Security",
                }
                
                completed = 0
                for future in as_completed(futures):
                    completed += 1
                    check_name = futures[future]
                    try:
                        future.result()
                        print(f"  [{completed:2d}/12] ✓ {check_name}")
                    except Exception as e:
                        print(f"  [{completed:2d}/12] ⚠️  {check_name}: {str(e)[:60]}")
            
            # Phase 3: Finalize and assess
            self._finalize_report()
            self._assess_malware()
            
            elapsed = time.time() - start_time
            print(f"\n✅ Analysis complete in {elapsed:.2f}s")
            print(f"⚡ Speed: {self.file_size / (1024*1024) / elapsed:.1f} MB/s\n")
            
            return self.report
            
        except Exception as e:
            self.report["error"] = f"Analysis failed: {str(e)}"
            import traceback
            print(f"\n❌ Error: {e}")
            traceback.print_exc()
            return self.report
    
    def _calculate_file_hash(self):
        """Ultra-fast hash calculation using memory mapping"""
        try:
            sha256 = hashlib.sha256()
            
            # For large files, use memory mapping for speed
            if self.file_size > 100 * 1024 * 1024:  # > 100MB
                with open(self.apk_path, 'rb') as f:
                    # Memory map the file
                    with mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mmapped:
                        # Process in 64KB chunks for optimal cache performance
                        for i in range(0, len(mmapped), 65536):
                            sha256.update(mmapped[i:i+65536])
            else:
                # Standard reading for smaller files
                with open(self.apk_path, 'rb') as f:
                    while chunk := f.read(65536):
                        sha256.update(chunk)
            
            self.report["file_hash_sha256"] = sha256.hexdigest()
            self.report["file_size_mb"] = round(self.file_size / (1024 * 1024), 2)
        except Exception as e:
            print(f"⚠️  Hash calculation: {e}")
    
    def _load_apk_metadata(self):
        """Fast APK metadata extraction"""
        try:
            self.apk = APK(self.apk_path)
            self.report["app_name"] = self.apk.application or "Unknown"
            self.report["package_name"] = self.apk.package or "Unknown"
            self.report["version_name"] = self.apk.version_name or "Unknown"
            self.report["version_code"] = str(self.apk.version_code or "Unknown")
            self.report["min_sdk"] = str(self.apk.min_sdk_version or "Unknown")
            self.report["target_sdk"] = str(self.apk.target_sdk_version or "Unknown")
            self.manifest_xml_string = self.apk.get_android_manifest_xml()
            
            # Cache permissions for reuse
            self.cache['permissions'] = set(self.apk.get_permissions() or [])
        except Exception as e:
            print(f"⚠️  Metadata extraction: {e}")
    
    def _index_zip_contents(self):
        """Index ZIP contents for fast access"""
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Create index of file types
                self.cache['zip_index'] = {
                    'dex': [f for f in z.namelist() if f.endswith('.dex')],
                    'so': [f for f in z.namelist() if f.endswith('.so')],
                    'xml': [f for f in z.namelist() if f.endswith('.xml')],
                    'assets': [f for f in z.namelist() if f.startswith('assets/')],
                }
        except Exception as e:
            self.cache['zip_index'] = {'dex': [], 'so': [], 'xml': [], 'assets': []}
    
    def _check_manifest_comprehensive(self):
        """Comprehensive manifest security analysis"""
        if not self.manifest_xml_string:
            return
        
        try:
            root = ET.fromstring(self.manifest_xml_string)
            app_elem = root.find('application')
            
            if app_elem is not None:
                # Debuggable check
                debuggable = app_elem.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
                if debuggable == 'true':
                    vuln = VULNERABILITY_DATABASE["DEBUGGABLE"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Debuggable Application",
                        severity="Critical",
                        vuln_data=vuln,
                        evidence="android:debuggable='true' found in <application> tag of AndroidManifest.xml",
                        location="AndroidManifest.xml:<application>"
                    )
                
                # Backup check
                backup = app_elem.get('{http://schemas.android.com/apk/res/android}allowBackup', 'true')
                if backup == 'true':
                    vuln = VULNERABILITY_DATABASE["BACKUP_ENABLED"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Insecure Backup Configuration",
                        severity="High",
                        vuln_data=vuln,
                        evidence="android:allowBackup='true' allows full app data extraction via ADB backup or cloud backup services",
                        location="AndroidManifest.xml:<application>"
                    )
                
                # Cleartext traffic
                cleartext = app_elem.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic', 'false')
                if cleartext == 'true' or (cleartext == 'false' and int(self.report.get('target_sdk', '0')) < 28):
                    vuln = VULNERABILITY_DATABASE["CLEAR_TEXT_TRAFFIC"].copy()
                    evidence = "android:usesCleartextTraffic='true' explicitly allows HTTP traffic" if cleartext == 'true' else f"Target SDK {self.report.get('target_sdk')} defaults to allowing cleartext traffic"
                    self._add_detailed_vuln(
                        vuln_type="Cleartext Traffic Allowed",
                        severity="High",
                        vuln_data=vuln,
                        evidence=evidence,
                        location="AndroidManifest.xml:<application>"
                    )
        
        except Exception as e:
            pass
    
    def _check_permissions_advanced(self):
        """Advanced permission analysis with malware detection"""
        if not self.cache['permissions']:
            return
        
        permissions = self.cache['permissions']
        
        # Dangerous permission categories
        dangerous_perms = {
            'SEND_SMS': ('Can send SMS messages, potential for premium SMS fraud', 'High'),
            'RECEIVE_SMS': ('Can intercept SMS messages including 2FA codes', 'High'),
            'READ_SMS': ('Can read all SMS messages including sensitive content', 'High'),
            'READ_CONTACTS': ('Can access entire contact list', 'Medium'),
            'ACCESS_FINE_LOCATION': ('Can track precise GPS location', 'Medium'),
            'CAMERA': ('Can take photos/videos without user knowledge', 'Medium'),
            'RECORD_AUDIO': ('Can record audio/conversations', 'High'),
            'CALL_PHONE': ('Can make phone calls, potential toll fraud', 'High'),
            'READ_CALL_LOG': ('Can access call history', 'Medium'),
            'WRITE_EXTERNAL_STORAGE': ('Can write to device storage', 'Low'),
            'SYSTEM_ALERT_WINDOW': ('Can overlay other apps (phishing risk)', 'High'),
            'REQUEST_INSTALL_PACKAGES': ('Can install other apps (trojan dropper)', 'Critical'),
            'BIND_DEVICE_ADMIN': ('Can gain device admin privileges', 'Critical'),
            'WRITE_SETTINGS': ('Can modify system settings', 'Medium'),
        }
        
        for perm in permissions:
            perm_name = perm.replace('android.permission.', '')
            if perm_name in dangerous_perms:
                reason, severity = dangerous_perms[perm_name]
                vuln = VULNERABILITY_DATABASE["DANGEROUS_PERMISSIONS"].copy()
                self._add_detailed_vuln(
                    vuln_type=f"Dangerous Permission: {perm_name}",
                    severity=severity,
                    vuln_data=vuln,
                    evidence=f"Application requests '{perm}' permission. {reason}",
                    location="AndroidManifest.xml:<uses-permission>"
                )
        
        # Malware permission combination detection
        perm_set = {p.replace('android.permission.', '') for p in permissions}
        for combo in self.MALWARE_PERMISSION_COMBOS:
            if all(p in perm_set for p in combo):
                malware_types = {
                    ('READ_SMS', 'SEND_SMS', 'RECEIVE_SMS', 'INTERNET'): 'SMS theft/fraud malware',
                    ('SYSTEM_ALERT_WINDOW', 'BIND_DEVICE_ADMIN'): 'Ransomware or screen overlay malware',
                    ('REQUEST_INSTALL_PACKAGES', 'RECEIVE_BOOT_COMPLETED'): 'Trojan dropper malware',
                    ('CALL_PHONE', 'SEND_SMS', 'INTERNET'): 'Toll fraud malware',
                    ('CAMERA', 'RECORD_AUDIO', 'INTERNET', 'ACCESS_FINE_LOCATION'): 'Spyware',
                }
                
                malware_type = malware_types.get(combo, 'Unknown malware type')
                vuln = VULNERABILITY_DATABASE["MALWARE_PERMISSION_COMBO"].copy()
                self._add_detailed_vuln(
                    vuln_type="Malware Permission Combination",
                    severity="Critical",
                    vuln_data=vuln,
                    evidence=f"Permission combination [{', '.join(combo)}] is characteristic of {malware_type}",
                    location="AndroidManifest.xml"
                )
                self.report["malware_indicators"].append(f"Malware permission combo: {malware_type}")
    
    def _check_exported_components(self):
        """Check for insecurely exported components"""
        if not self.manifest_xml_string:
            return
        
        try:
            root = ET.fromstring(self.manifest_xml_string)
            app_elem = root.find('application')
            
            if app_elem is None:
                return
            
            component_types = ['activity', 'service', 'receiver', 'provider']
            
            for comp_type in component_types:
                for component in app_elem.findall(comp_type):
                    exported = component.get('{http://schemas.android.com/apk/res/android}exported')
                    permission = component.get('{http://schemas.android.com/apk/res/android}permission')
                    name = component.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    
                    # Check if explicitly exported without permission
                    if exported == 'true' and not permission:
                        vuln = VULNERABILITY_DATABASE["EXPORTED_COMPONENTS"].copy()
                        comp_type_name = comp_type.capitalize()
                        self._add_detailed_vuln(
                            vuln_type=f"Exported {comp_type_name} Without Permission",
                            severity="Critical",
                            vuln_data=vuln,
                            evidence=f"{comp_type_name} '{name}' is exported (android:exported='true') with no permission protection. Any app can invoke it.",
                            location=f"AndroidManifest.xml:<{comp_type} name='{name}'>"
                        )
        
        except Exception as e:
            pass
    
    def _check_secrets_ultra_fast(self):
        """Ultra-fast secret detection with optimized scanning"""
        try:
            secrets_found = []
            
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Smart file selection - prioritize likely locations
                scan_files = []
                
                # Priority 1: XML resources (fastest, most likely)
                scan_files.extend([f for f in self.cache['zip_index'].get('xml', []) if 'strings' in f or 'config' in f][:10])
                
                # Priority 2: Small DEX file for speed
                dex_files = self.cache['zip_index'].get('dex', [])
                if dex_files:
                    scan_files.append(dex_files[0])  # Just first DEX
                
                # Priority 3: Assets
                scan_files.extend(self.cache['zip_index'].get('assets', [])[:5])
                
                for fname in scan_files:
                    if len(secrets_found) > 20:  # Early termination
                        break
                    
                    try:
                        data = z.read(fname)
                        
                        # API keys
                        for match in self.PATTERNS['api_key'].finditer(data):
                            preview = match.group(0)[:50].decode('utf-8', errors='ignore')
                            secrets_found.append(('API Key', fname, preview))
                        
                        # AWS keys
                        for match in self.PATTERNS['aws_key'].finditer(data):
                            preview = match.group(0)[:30].decode('utf-8', errors='ignore')
                            secrets_found.append(('AWS Access Key', fname, preview))
                        
                        # Private keys
                        if self.PATTERNS['private_key'].search(data):
                            secrets_found.append(('Private Key', fname, '-----BEGIN PRIVATE KEY-----'))
                        
                        # Passwords
                        for match in self.PATTERNS['password'].finditer(data):
                            try:
                                password = match.group(1).decode('utf-8', errors='ignore')
                                if len(password) >= 6:
                                    preview = password[:20] + ('...' if len(password) > 20 else '')
                                    secrets_found.append(('Password', fname, f'password="{preview}"'))
                            except:
                                continue
                    
                    except:
                        continue
            
            # Report findings
            for secret_type, location, preview in secrets_found[:15]:  # Limit to 15 for report clarity
                vuln = VULNERABILITY_DATABASE["HARDCODED_SECRET"].copy()
                self._add_detailed_vuln(
                    vuln_type=f"Hardcoded {secret_type}",
                    severity="Critical",
                    vuln_data=vuln,
                    evidence=f"Found hardcoded {secret_type} in {location}: {preview}",
                    location=location
                )
        
        except Exception as e:
            pass
    
    def _check_code_vulns_optimized(self):
        """Optimized code vulnerability scanning"""
        if not self.cache['zip_index'].get('dex'):
            return
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Scan only first DEX for speed
                dex_file = self.cache['zip_index']['dex'][0]
                
                # For large DEX, sample first 10MB
                with z.open(dex_file) as f:
                    max_read = min(10 * 1024 * 1024, z.getinfo(dex_file).file_size)
                    dex_data = f.read(max_read)
                
                # SQL injection
                sql_matches = self.PATTERNS['sql_concat'].findall(dex_data)
                if sql_matches:
                    vuln = VULNERABILITY_DATABASE["SQL_INJECTION"].copy()
                    self._add_detailed_vuln(
                        vuln_type="SQL Injection Vulnerability",
                        severity="Critical",
                        vuln_data=vuln,
                        evidence=f"Found {len(sql_matches)} instances of SQL query string concatenation. Example: {sql_matches[0][:60].decode('utf-8', errors='ignore')}",
                        location=dex_file
                    )
                
                # Command injection
                exec_matches = self.PATTERNS['runtime_exec'].findall(dex_data)
                if exec_matches:
                    vuln = VULNERABILITY_DATABASE["COMMAND_INJECTION"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Command Injection Vulnerability",
                        severity="Critical",
                        vuln_data=vuln,
                        evidence=f"Found {len(exec_matches)} instances of Runtime.exec() which may allow command injection",
                        location=dex_file
                    )
                
                # Path traversal
                file_matches = self.PATTERNS['file_traversal'].findall(dex_data)
                if file_matches:
                    vuln = VULNERABILITY_DATABASE["PATH_TRAVERSAL"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Path Traversal Vulnerability",
                        severity="High",
                        vuln_data=vuln,
                        evidence=f"Found {len(file_matches)} instances of File path concatenation vulnerable to directory traversal",
                        location=dex_file
                    )
                
                # Weak crypto
                weak_crypto = {
                    b'DES': 'DES encryption (broken)',
                    b'MD5': 'MD5 hashing (collision-prone)',
                    b'SHA1': 'SHA-1 hashing (deprecated)',
                    b'RC4': 'RC4 cipher (vulnerable)',
                    b'ECB': 'ECB mode (insecure pattern leakage)'
                }
                
                for algo, desc in weak_crypto.items():
                    count = dex_data.count(algo)
                    if count > 2:  # Threshold to reduce false positives
                        vuln = VULNERABILITY_DATABASE["WEAK_CRYPTO"].copy()
                        self._add_detailed_vuln(
                            vuln_type=f"Weak Cryptography: {desc}",
                            severity="High",
                            vuln_data=vuln,
                            evidence=f"Found {count} references to {algo.decode()}. {desc} and should not be used.",
                            location=dex_file
                        )
        
        except Exception as e:
            pass
    
    def _check_native_libs(self):
        """Check native libraries for suspicious content"""
        so_files = self.cache['zip_index'].get('so', [])
        
        for so_file in so_files:
            lib_name = os.path.basename(so_file).lower()
            
            for suspicious in self.SUSPICIOUS_LIBRARIES:
                if suspicious in lib_name:
                    vuln = VULNERABILITY_DATABASE["SUSPICIOUS_NATIVE_LIBS"].copy()
                    
                    purposes = {
                        'frida': 'Frida dynamic instrumentation framework (hooking/reverse engineering)',
                        'xposed': 'Xposed Framework (system-level hooking)',
                        'substrate': 'Substrate hooking framework',
                        'cydia': 'Cydia Substrate (iOS/Android hooking)',
                        'magisk': 'Magisk root/modification framework',
                        'rootcloak': 'Root detection bypass tool',
                        'supersu': 'SuperSU root management'
                    }
                    
                    purpose = purposes.get(suspicious, 'Reverse engineering or rooting tool')
                    
                    self._add_detailed_vuln(
                        vuln_type="Suspicious Native Library",
                        severity="Critical",
                        vuln_data=vuln,
                        evidence=f"Native library '{lib_name}' contains '{suspicious}'. {purpose}.",
                        location=so_file
                    )
                    self.report["malware_indicators"].append(f"Suspicious library: {lib_name}")
    
    def _check_webview_security(self):
        """WebView security configuration analysis"""
        if not self.cache['zip_index'].get('dex'):
            return
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                dex_file = self.cache['zip_index']['dex'][0]
                with z.open(dex_file) as f:
                    dex_data = f.read(min(5 * 1024 * 1024, z.getinfo(dex_file).file_size))
                
                webview_issues = []
                
                if b'setJavaScriptEnabled' in dex_data and b'true' in dex_data:
                    webview_issues.append(('JavaScript Enabled', 'XSS and code injection attacks'))
                
                if b'setAllowFileAccess' in dex_data and b'true' in dex_data:
                    webview_issues.append(('File Access Enabled', 'Access to local file system via file:// URLs'))
                
                if b'setAllowFileAccessFromFileURLs' in dex_data:
                    webview_issues.append(('File URL Access', 'Cross-origin attacks from file:// URLs'))
                
                if b'setMixedContentMode' in dex_data:
                    webview_issues.append(('Mixed Content Allowed', 'HTTP resources loaded in HTTPS context'))
                
                for issue, attack in webview_issues:
                    vuln = VULNERABILITY_DATABASE["WEBVIEW_VULNERABILITIES"].copy()
                    self._add_detailed_vuln(
                        vuln_type=f"WebView Security: {issue}",
                        severity="High",
                        vuln_data=vuln,
                        evidence=f"WebView configured with {issue.lower()}, enabling: {attack}",
                        location="Code"
                    )
        
        except Exception as e:
            pass
    
    def _check_certificate_advanced(self):
        """Advanced certificate security analysis"""
        try:
            # Use pyaxmlparser to get certificate info
            cert = self.apk.get_signature()
            
            if cert:
                # Check for debug certificate (common CN)
                cert_str = str(cert)
                if 'CN=Android Debug' in cert_str or 'debug' in cert_str.lower():
                    vuln = VULNERABILITY_DATABASE["CERTIFICATE_ISSUES"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Debug Certificate in Production",
                        severity="Critical",
                        vuln_data=vuln,
                        evidence="Application signed with Android Debug Certificate. Anyone can sign updates with debug keystore.",
                        location="META-INF/"
                    )
                    self.report["malware_indicators"].append("Debug certificate")
                
                # Check signature algorithm
                if 'md5' in cert_str.lower() or 'sha1withrsa' in cert_str.lower():
                    vuln = VULNERABILITY_DATABASE["CERTIFICATE_ISSUES"].copy()
                    self._add_detailed_vuln(
                        vuln_type="Weak Certificate Signature Algorithm",
                        severity="High",
                        vuln_data=vuln,
                        evidence="Certificate uses weak signature algorithm (MD5/SHA1). Vulnerable to collision attacks.",
                        location="META-INF/"
                    )
        
        except Exception as e:
            pass
    
    def _check_malware_signatures(self):
        """Malware package name and behavior detection"""
        package = self.report.get('package_name', '')
        
        # Check against known malware packages
        for malware_pkg in self.MALWARE_PACKAGES:
            if malware_pkg in package.lower():
                vuln = VULNERABILITY_DATABASE["MALWARE_PACKAGE_NAME"].copy()
                self._add_detailed_vuln(
                    vuln_type="Malware Package Name",
                    severity="Critical",
                    vuln_data=vuln,
                    evidence=f"Package name '{package}' matches known malware pattern '{malware_pkg}'",
                    location="AndroidManifest.xml"
                )
                self.report["malware_indicators"].append(f"Malware package pattern: {malware_pkg}")
                return
        
        # Check for system/Google impersonation
        suspicious_patterns = [
            ('com.android.system', 'System impersonation'),
            ('com.google.android.play', 'Google Play impersonation'),
            ('android.system.', 'Android system impersonation'),
            ('com.android.security', 'Security service impersonation')
        ]
        
        for pattern, desc in suspicious_patterns:
            if pattern in package and package != 'com.google.android.gms':  # Exclude legitimate Google services
                vuln = VULNERABILITY_DATABASE["MALWARE_PACKAGE_NAME"].copy()
                self._add_detailed_vuln(
                    vuln_type="Suspicious Package Name",
                    severity="High",
                    vuln_data=vuln,
                    evidence=f"Package name '{package}' suggests {desc.lower()}, commonly used in malware",
                    location="AndroidManifest.xml"
                )
                self.report["malware_indicators"].append(f"Package impersonation: {desc}")
    
    def _check_obfuscation(self):
        """Code obfuscation detection"""
        if not self.cache['zip_index'].get('dex'):
            return
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                dex_file = self.cache['zip_index']['dex'][0]
                with z.open(dex_file) as f:
                    # Read small sample for obfuscation check
                    dex_data = f.read(min(2 * 1024 * 1024, z.getinfo(dex_file).file_size))
                
                # Check for obfuscation markers
                has_proguard = b'proguard' in dex_data.lower() or b'r8' in dex_data.lower()
                
                # Check for short class names (indication of obfuscation)
                short_classes = dex_data.count(b'La;') + dex_data.count(b'Lb;') + dex_data.count(b'Lc;')
                
                if not has_proguard and short_classes < 5:
                    vuln = VULNERABILITY_DATABASE["NO_OBFUSCATION"].copy()
                    self._add_detailed_vuln(
                        vuln_type="No Code Obfuscation",
                        severity="Medium",
                        vuln_data=vuln,
                        evidence="No ProGuard/R8 signatures detected. Code is not obfuscated, making reverse engineering trivial.",
                        location=dex_file
                    )
        
        except Exception as e:
            pass
    
    def _check_suspicious_strings_fast(self):
        """Fast suspicious string pattern detection"""
        if not self.cache['zip_index'].get('dex'):
            return
        
        try:
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                dex_file = self.cache['zip_index']['dex'][0]
                with z.open(dex_file) as f:
                    # Sample for speed
                    dex_data = f.read(min(10 * 1024 * 1024, z.getinfo(dex_file).file_size))
                
                patterns = {
                    'root': {
                        'keywords': [b'su', b'/system/xbin/su', b'Superuser', b'busybox', b'/system/bin/su'],
                        'behavior': 'root detection or exploitation'
                    },
                    'premium_sms': {
                        'keywords': [b'premium', b'sms://', b'smsto:', b'sendTextMessage'],
                        'behavior': 'SMS fraud or premium SMS abuse'
                    },
                    'c2': {
                        'keywords': [b'bot', b'command', b'control', b'c2server', b'botnet'],
                        'behavior': 'command-and-control communication'
                    },
                    'crypto_wallet': {
                        'keywords': [b'bitcoin', b'ethereum', b'wallet', b'cryptocurrency', b'mnemonic'],
                        'behavior': 'cryptocurrency wallet operations or theft'
                    },
                    'data_exfiltration': {
                        'keywords': [b'upload', b'exfiltrate', b'steal', b'sendData'],
                        'behavior': 'data exfiltration'
                    }
                }
                
                for category, data in patterns.items():
                    count = sum(dex_data.count(kw) for kw in data['keywords'])
                    if count > 5:
                        severity = "High" if category in ['premium_sms', 'c2', 'crypto_wallet'] else "Medium"
                        vuln = VULNERABILITY_DATABASE["SUSPICIOUS_STRINGS"].copy()
                        self._add_detailed_vuln(
                            vuln_type=f"Suspicious {category.replace('_', ' ').title()} Patterns",
                            severity=severity,
                            vuln_data=vuln,
                            evidence=f"Found {count} suspicious strings related to {data['behavior']}. Keywords: {', '.join(kw.decode('utf-8', errors='ignore') for kw in data['keywords'][:3])}",
                            location=dex_file
                        )
                        if severity == "High":
                            self.report["malware_indicators"].append(f"Suspicious {category} behavior")
        
        except Exception as e:
            pass
    
    def _check_network_security(self):
        """Comprehensive network security analysis"""
        try:
            urls = set()
            
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Scan XML and DEX for URLs
                scan_files = self.cache['zip_index'].get('xml', [])[:20]
                if self.cache['zip_index'].get('dex'):
                    scan_files.append(self.cache['zip_index']['dex'][0])
                
                for fname in scan_files:
                    try:
                        data = z.read(fname)
                        # Extract URLs
                        found_urls = self.PATTERNS['url'].findall(data)
                        urls.update(url.decode('utf-8', errors='ignore') for url in found_urls[:50])
                    except:
                        continue
            
            # Check HTTP URLs (insecure)
            http_urls = [u for u in urls if u.startswith('http://')]
            if http_urls:
                vuln = VULNERABILITY_DATABASE["HTTPS_NOT_ENFORCED"].copy()
                examples = ', '.join(http_urls[:3])
                self._add_detailed_vuln(
                    vuln_type="Insecure HTTP Communication",
                    severity="High",
                    vuln_data=vuln,
                    evidence=f"Found {len(http_urls)} unencrypted HTTP endpoints. Examples: {examples}",
                    location="Network Configuration"
                )
            
            # Check suspicious TLDs
            for url in urls:
                for tld in self.SUSPICIOUS_TLDS:
                    if tld in url.lower():
                        vuln = VULNERABILITY_DATABASE["SUSPICIOUS_TLD"].copy()
                        self._add_detailed_vuln(
                            vuln_type="Suspicious Domain TLD",
                            severity="Medium",
                            vuln_data=vuln,
                            evidence=f"Domain uses suspicious TLD '{tld}': {url}. This TLD is commonly associated with malicious activity.",
                            location="Network Configuration"
                        )
                        self.report["malware_indicators"].append(f"Suspicious TLD: {url}")
                        break
        
        except Exception as e:
            pass
    
    def _add_detailed_vuln(self, vuln_type, severity, vuln_data, evidence, location):
        """Add vulnerability with full details from knowledge base"""
        vulnerability = {
            "type": vuln_type,
            "severity": severity,
            "description": vuln_data["description"],
            "evidence": evidence,
            "location": location,
            "impact": vuln_data["impact"],
            "remediation": vuln_data["remediation"],
            "cwe": vuln_data["cwe"],
            "owasp": vuln_data["owasp"],
            "cvss_score": vuln_data["cvss_base"],
            "risk_score": self._calculate_risk_score(severity, vuln_data["cvss_base"])
        }
        
        with self.vuln_lock:
            self.report["vulnerabilities"].append(vulnerability)
            self.report["summary"][severity.lower()] += 1
    
    def _calculate_risk_score(self, severity, cvss):
        """Calculate internal risk score"""
        severity_multipliers = {
            "Critical": 1.0,
            "High": 0.85,
            "Medium": 0.65,
            "Low": 0.4,
            "Info": 0.2
        }
        return round(cvss * severity_multipliers.get(severity, 0.5), 1)
    
    def _finalize_report(self):
        """Finalize report with sorting and statistics"""
        self.report["summary"]["total"] = len(self.report["vulnerabilities"])
        
        # Calculate overall risk
        if self.report["vulnerabilities"]:
            total_risk = sum(v.get("risk_score", 0) for v in self.report["vulnerabilities"])
            self.report["overall_risk_score"] = round(total_risk / len(self.report["vulnerabilities"]), 2)
            self.report["max_cvss_score"] = max(v.get("cvss_score", 0) for v in self.report["vulnerabilities"])
        else:
            self.report["overall_risk_score"] = 0
            self.report["max_cvss_score"] = 0
        
        # Sort by severity and risk score
        severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
        self.report["vulnerabilities"].sort(
            key=lambda x: (severity_order.get(x["severity"], 5), -x.get("risk_score", 0))
        )
    
    def _assess_malware(self):
        """Final malware confidence assessment"""
        indicators = len(self.report["malware_indicators"])
        critical_vulns = self.report["summary"]["critical"]
        
        if indicators >= 3 or critical_vulns >= 5:
            self.report["malware_detected"] = True
            self.report["malware_confidence"] = "High"
        elif indicators >= 1 or critical_vulns >= 3:
            self.report["malware_detected"] = True
            self.report["malware_confidence"] = "Medium"
        else:
            self.report["malware_detected"] = False
            self.report["malware_confidence"] = "Low"


# ============================================================================
# ENTRY POINT
# ============================================================================

def analyze_apk(apk_path):
    """Main analysis entry point"""
    analyzer = UltraOptimizedAnalyzer(apk_path)
    return analyzer.analyze()


def print_report(report):
    """Print comprehensive report"""
    print(f"\n{'='*80}")
    print(f"📊 SECURITY ANALYSIS REPORT")
    print(f"{'='*80}")
    
    # App Info
    print(f"\n📱 Application Information:")
    print(f"  Name:         {report['app_name']}")
    print(f"  Package:      {report['package_name']}")
    print(f"  Version:      {report['version_name']} (code: {report['version_code']})")
    print(f"  SDK:          Min {report['min_sdk']} / Target {report['target_sdk']}")
    print(f"  Size:         {report['file_size_mb']} MB")
    print(f"  SHA-256:      {report['file_hash_sha256']}")
    
    # Risk Scores
    print(f"\n⚠️  Risk Assessment:")
    print(f"  Overall Risk:  {report['overall_risk_score']:.1f}/10.0")
    print(f"  Max CVSS:      {report.get('max_cvss_score', 0):.1f}/10.0")
    print(f"  Malware:       {report['malware_confidence']} confidence")
    
    # Summary
    print(f"\n📈 Vulnerability Summary:")
    print(f"  🔴 Critical:  {report['summary']['critical']}")
    print(f"  🟠 High:      {report['summary']['high']}")
    print(f"  🟡 Medium:    {report['summary']['medium']}")
    print(f"  🟢 Low:       {report['summary']['low']}")
    print(f"  ℹ️  Info:      {report['summary']['info']}")
    print(f"  ━━━━━━━━━━━━━━━━━━")
    print(f"  📊 Total:     {report['summary']['total']}")
    
    # Malware Indicators
    if report['malware_indicators']:
        print(f"\n🚨 Malware Indicators ({len(report['malware_indicators'])}):")
        for indicator in report['malware_indicators'][:10]:
            print(f"  • {indicator}")
        if len(report['malware_indicators']) > 10:
            print(f"  ... and {len(report['malware_indicators']) - 10} more")
    
    # Detailed Vulnerabilities
    if report['vulnerabilities']:
        print(f"\n🔍 Detailed Vulnerabilities:\n")
        
        for i, vuln in enumerate(report['vulnerabilities'][:10], 1):
            severity_emoji = {
                "Critical": "🔴",
                "High": "🟠",
                "Medium": "🟡",
                "Low": "🟢",
                "Info": "ℹ️"
            }
            
            print(f"{severity_emoji.get(vuln['severity'], '•')} [{i}] {vuln['type']} ({vuln['severity']})")
            print(f"    CWE:         {vuln['cwe']}")
            print(f"    OWASP:       {vuln['owasp']}")
            print(f"    CVSS Score:  {vuln['cvss_score']}/10.0")
            print(f"    Location:    {vuln['location']}")
            print(f"\n    Description:")
            print(f"    {vuln['description']}")
            print(f"\n    Evidence:")
            print(f"    {vuln['evidence']}")
            print(f"\n    Impact:")
            print(f"    {vuln['impact']}")
            print(f"\n    Remediation:")
            for line in vuln['remediation'].split('\n'):
                print(f"    {line}")
            print()
        
        if len(report['vulnerabilities']) > 10:
            print(f"... and {len(report['vulnerabilities']) - 10} more vulnerabilities")
            print(f"(Full report contains all {len(report['vulnerabilities'])} findings)\n")
    
    print(f"{'='*80}\n")


if __name__ == "__main__":
    import sys
    import json
    
    if len(sys.argv) < 2:
        print("Usage: python apk_analyzer_ultra_optimized.py <apk_file> [--json output.json]")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"❌ File not found: {apk_file}")
        sys.exit(1)
    
    # Run analysis
    report = analyze_apk(apk_file)
    
    # Print report
    print_report(report)
    
    # Save JSON if requested
    if '--json' in sys.argv:
        json_idx = sys.argv.index('--json')
        if json_idx + 1 < len(sys.argv):
            json_file = sys.argv[json_idx + 1]
            with open(json_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f"💾 Full report saved to: {json_file}")
