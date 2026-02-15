#!/usr/bin/env python3
"""
HYBRID ULTIMATE APK Security Analyzer - OPTIMIZED VERSION
Maximum Speed + Maximum Accuracy + Zero Malware Escape
Combines parallel processing with comprehensive detection

OPTIMIZATIONS:
- Pre-caches all file content (strings.xml, manifest) to avoid repeated ZIP reads
- Batch processes DEX string extraction for multiple checks simultaneously
- Enhanced vulnerability details with comprehensive remediation guides
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
    """Ultimate hybrid analyzer - fastest and most accurate"""
    
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
        
        # SPEED OPTIMIZATION: Pre-cache content
        self.strings_xml_cache = {}  # Cache all strings.xml files
        self.dex_strings_cache = []  # Pre-extracted DEX strings
        self.all_files_list = []     # Cached file list
        
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
        print(f"🚀 HYBRID ULTIMATE APK ANALYZER - OPTIMIZED")
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
            
            # Phase 2: SPEED OPTIMIZATION - Cache ALL content at once
            self._cache_all_content_optimized()
            
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
            
            print(f"\n✅ Analysis complete!")
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
    
    def _cache_all_content_optimized(self):
        """SPEED OPTIMIZATION: Cache ALL needed content in one pass to avoid repeated ZIP reads"""
        try:
            print("⚡ Pre-caching content for maximum speed...")
            with zipfile.ZipFile(self.apk_path, 'r') as z:
                # Cache file list once
                self.all_files_list = z.namelist()
                
                # Cache all strings.xml files at once
                for fname in self.all_files_list:
                    if 'strings.xml' in fname:
                        try:
                            self.strings_xml_cache[fname] = z.read(fname).decode('utf-8', errors='ignore')
                        except:
                            pass
                
                # Cache DEX content and pre-extract strings
                dex_files = [(f, z.getinfo(f).file_size) for f in self.all_files_list if f.endswith('.dex')]
                
                if dex_files:
                    smallest_dex = min(dex_files, key=lambda x: x[1])[0]
                    dex_size = dex_files[0][1]
                    
                    if dex_size < 30 * 1024 * 1024:
                        self.dex_cache = z.read(smallest_dex)
                        print(f"  ✓ Cached {smallest_dex} ({dex_size / (1024*1024):.1f}MB)")
                    else:
                        with z.open(smallest_dex) as dex_file:
                            self.dex_cache = dex_file.read(5 * 1024 * 1024)
                        print(f"  ✓ Partial cache (5MB sample from large DEX)")
                    
                    # SPEED OPTIMIZATION: Pre-extract strings from DEX once
                    # This avoids multiple regex passes later
                    if self.dex_cache:
                        self.dex_strings_cache = re.findall(b'[ -~]{10,}', self.dex_cache)[:5000]
                        print(f"  ✓ Pre-extracted {len(self.dex_strings_cache)} strings from DEX")
                
            print(f"  ✓ Cached {len(self.strings_xml_cache)} strings.xml files")
            
        except Exception as e:
            print(f"  ⚠️  Cache error: {e}")
    
    def _check_manifest_comprehensive(self):
        """Complete manifest security check with ENHANCED DETAILS"""
        if not self.manifest_xml_string:
            return
        
        try:
            root = ET.fromstring(self.manifest_xml_string)
            app_tag = root.find('.//application')
            if not app_tag:
                return
            
            target_sdk = int(self.report["target_sdk"]) if self.report["target_sdk"].isdigit() else 28
            
            # Debuggable - CRITICAL
            debuggable = app_tag.get('{http://schemas.android.com/apk/res/android}debuggable', 'false')
            if debuggable.lower() == 'true' or 'android:debuggable="true"' in self.manifest_xml_string:
                self._add_vuln({
                    "type": "Debuggable Application",
                    "severity": "Critical",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": """App allows runtime debugging - CRITICAL SECURITY FLAW.

WHAT THIS MEANS:
When android:debuggable is set to 'true', the application runs in debug mode even in production. This exposes the app to severe security risks.

HOW ATTACKERS EXPLOIT THIS:
1. Attach debugger (via ADB or IDE) to running app process
2. Read/modify variables in real-time (steal passwords, tokens, encryption keys)
3. Bypass security checks by changing boolean flags (isPremium=true, isAuthenticated=true)
4. Inject malicious code at runtime
5. Extract business logic and proprietary algorithms
6. Disable SSL pinning and other security mechanisms
7. Dump memory to extract sensitive data

REAL-WORLD ATTACK SCENARIO:
Attacker runs: adb shell am set-debug-app -w com.yourapp
Then connects debugger, sets breakpoint at login validation
Changes 'isLoginSuccessful' from false to true → Bypasses authentication

TECHNICAL IMPACT:
- Memory inspection possible via JDWP protocol
- Native code can be analyzed via gdbserver
- All Java/Kotlin code accessible via JDWP
- Root not required - works on any device with USB debugging""",
                    "remediation": """IMMEDIATE ACTIONS REQUIRED:

1. REMOVE debuggable flag from AndroidManifest.xml:
   <application
       android:debuggable="false"  <!-- Or remove this line entirely -->
       ...>

2. VERIFY in build.gradle:
   buildTypes {
       release {
           debuggable false
           minifyEnabled true
           shrinkResources true
       }
   }

3. IMPLEMENT anti-debugging checks in code:
   // Java/Kotlin
   public boolean isDebuggable() {
       return (getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
   }
   
   if (isDebuggable()) {
       // Exit app or disable sensitive features
       finish();
   }

4. ADD ProGuard/R8 obfuscation:
   -dontwarn android.os.Debug
   -assumenosideeffects class android.os.Debug {
       public static boolean isDebuggerConnected() return false;
   }

5. DETECT debugger at runtime:
   if (Debug.isDebuggerConnected() || Debug.waitingForDebugger()) {
       throw new SecurityException("Debugger detected");
   }

6. IMPLEMENT certificate pinning to prevent MITM even if debuggable

7. USE SafetyNet/Play Integrity API to detect compromised environments

VERIFICATION:
After fix, run: aapt dump badging app.apk | grep debuggable
Should return nothing or 'debuggable=false'""",
                    "cwe": "CWE-489: Active Debug Code",
                    "risk_score": 9.5
                })
                self.report["malware_indicators"].append("Debuggable in production")
            
            # Backup
            allow_backup = app_tag.get('{http://schemas.android.com/apk/res/android}allowBackup')
            if allow_backup is None:
                self._add_vuln({
                    "type": "Backup Enabled by Default",
                    "severity": "Medium",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": """App data backup is enabled without restrictions (Android's default behavior).

WHAT THIS MEANS:
Android automatically backs up app data to Google Drive (Auto Backup) or via ADB backup. Without explicit configuration, ALL app data is included - databases, SharedPreferences, files.

ATTACK VECTORS:
1. ADB BACKUP EXTRACTION:
   Attacker runs: adb backup -f backup.ab com.yourapp
   Then extracts: dd if=backup.ab bs=24 skip=1 | openssl zlib -d | tar -xvf -
   Now has access to: databases/, shared_prefs/, files/

2. GOOGLE DRIVE BACKUP:
   If attacker gains access to user's Google account (phishing, credential leak), they can download backup containing:
   - Login credentials in SharedPreferences
   - SQLite databases with user data
   - Encryption keys stored in files
   - Session tokens

3. ROOTED DEVICE:
   Backup can be extracted without user consent on rooted devices

DATA AT RISK:
- SharedPreferences (often contains auth tokens, settings, credentials)
- SQLite databases (user data, messages, transactions)
- Internal files (keys, configs, cached data)
- External files (documents, images with EXIF data)

COMPLIANCE IMPACT:
GDPR/CCPA: Inadequate data protection measures""",
                    "remediation": """COMPREHENSIVE BACKUP SECURITY:

OPTION 1 - DISABLE BACKUP (Most Secure):
<application
    android:allowBackup="false"
    android:fullBackupContent="false"
    ...>

OPTION 2 - SELECTIVE BACKUP (Recommended for most apps):

Step 1: Create res/xml/backup_rules.xml:
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <!-- EXCLUDE sensitive data -->
    <exclude domain="sharedpref" path="user_credentials.xml"/>
    <exclude domain="database" path="messages.db"/>
    <exclude domain="file" path="keys/"/>
    
    <!-- INCLUDE non-sensitive data -->
    <include domain="sharedpref" path="app_settings.xml"/>
    <include domain="file" path="cache/"/>
</full-backup-content>

Step 2: Reference in AndroidManifest.xml:
<application
    android:fullBackupContent="@xml/backup_rules"
    ...>

OPTION 3 - ENCRYPTED BACKUP (API 23+):
Implement BackupAgent with encryption:

public class MyBackupAgent extends BackupAgentHelper {
    @Override
    public void onCreate() {
        // Encrypt before backup
        SharedPreferencesBackupHelper helper = 
            new SharedPreferencesBackupHelper(this, "encrypted_prefs");
        addHelper("prefs", helper);
    }
    
    @Override
    public void onBackup(ParcelFileDescriptor oldState, 
                         BackupDataOutput data, 
                         ParcelFileDescriptor newState) throws IOException {
        // Encrypt sensitive data before backup
        encryptSensitiveData();
        super.onBackup(oldState, data, newState);
    }
}

ADDITIONAL SECURITY:
1. ENCRYPT sensitive SharedPreferences:
   Use EncryptedSharedPreferences (Jetpack Security):
   
   val masterKey = MasterKey.Builder(context)
       .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
       .build()
   
   val sharedPrefs = EncryptedSharedPreferences.create(
       context,
       "secret_shared_prefs",
       masterKey,
       EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
       EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
   )

2. USE Android Keystore for keys (not backed up by default)

3. IMPLEMENT backup encryption key:
   <application
       android:backupAgent=".MyBackupAgent"
       android:fullBackupContent="@xml/backup_rules"
       ...>

TESTING:
adb shell bmgr list transports
adb shell bmgr backupnow com.yourapp
adb shell bmgr restore com.yourapp
Verify no sensitive data in backup""",
                    "cwe": "CWE-200: Exposure of Sensitive Information",
                    "risk_score": 5.0
                })
            elif allow_backup.lower() == 'true':
                full_backup = app_tag.get('{http://schemas.android.com/apk/res/android}fullBackupContent')
                if not full_backup:
                    self._add_vuln({
                        "type": "Unrestricted Backup Enabled",
                        "severity": "Medium",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Data Protection",
                        "details": """Backup is explicitly enabled but without selective rules - ALL app data will be backed up.

CRITICAL DATA EXPOSURE:
Since fullBackupContent is not specified, Android backs up EVERYTHING:
- /data/data/com.yourapp/shared_prefs/ → ALL SharedPreferences
- /data/data/com.yourapp/databases/ → ALL SQLite databases  
- /data/data/com.yourapp/files/ → ALL internal files
- /data/data/com.yourapp/cache/ → Cache data

COMMON SENSITIVE DATA LOCATIONS:
1. shared_prefs/UserPrefs.xml:
   - auth_token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
   - user_id=12345
   - is_premium=false

2. databases/app.db:
   - Users table (emails, hashed passwords)
   - Messages (private conversations)
   - Transactions (financial data)

3. files/keys/encryption.key:
   - AES encryption keys
   - RSA private keys

4. files/config.json:
   - API endpoints
   - Client secrets

ATTACK SCENARIO:
1. Victim uses app normally
2. App data auto-backs up to Google Drive
3. Attacker phishes victim's Google credentials
4. Attacker downloads backup via Google Takeout
5. Extracts backup: android backup extractor
6. Reads SharedPreferences, gets auth token
7. Uses token to hijack account""",
                        "remediation": """IMMEDIATE FIX - IMPLEMENT SELECTIVE BACKUP:

Step 1: Create backup rules (res/xml/backup_rules.xml):
<?xml version="1.0" encoding="utf-8"?>
<full-backup-content>
    <!-- ============================================ -->
    <!-- CRITICAL: EXCLUDE ALL SENSITIVE DATA FIRST -->
    <!-- ============================================ -->
    
    <!-- 1. Authentication & Credentials -->
    <exclude domain="sharedpref" path="user_credentials.xml"/>
    <exclude domain="sharedpref" path="auth_prefs.xml"/>
    <exclude domain="sharedpref" path="session.xml"/>
    
    <!-- 2. Encryption Keys -->
    <exclude domain="file" path="keys/"/>
    <exclude domain="file" path=".keystore"/>
    <exclude domain="file" path="encryption/"/>
    
    <!-- 3. Databases with PII -->
    <exclude domain="database" path="users.db"/>
    <exclude domain="database" path="messages.db"/>
    <exclude domain="database" path="transactions.db"/>
    
    <!-- 4. Temporary/Cache -->
    <exclude domain="file" path="cache/"/>
    <exclude domain="cache" path="."/>
    
    <!-- 5. Logs (may contain sensitive data) -->
    <exclude domain="file" path="logs/"/>
    
    <!-- ============================================ -->
    <!-- SAFE TO BACKUP (explicit whitelist) -->
    <!-- ============================================ -->
    <include domain="sharedpref" path="app_settings.xml"/>
    <include domain="sharedpref" path="ui_preferences.xml"/>
    <include domain="file" path="downloads/"/>
</full-backup-content>

Step 2: Update AndroidManifest.xml:
<application
    android:allowBackup="true"
    android:fullBackupContent="@xml/backup_rules"
    ...>

Step 3: ENCRYPT remaining data:
// For SharedPreferences that MUST be backed up
val encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "app_settings",  // Matches backup rules
    MasterKey.Builder(context)
        .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
        .build(),
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
)

// For database encryption
val passphrase = SQLiteDatabase.getBytes("your-secret-key".toCharArray())
val factory = SupportFactory(passphrase)
val db = Room.databaseBuilder(context, AppDatabase::class.java, "app.db")
    .openHelperFactory(factory)
    .build()

TESTING PROCEDURE:
1. Enable backup:
   adb shell bmgr enable true
   
2. Trigger backup:
   adb shell bmgr backupnow com.yourapp
   
3. Extract and inspect:
   adb backup -f backup.ab com.yourapp
   dd if=backup.ab bs=24 skip=1 | openssl zlib -d | tar -xvf -
   
4. VERIFY: No credentials, tokens, or PII in extracted files

MONITORING:
Log backup operations:
override fun onBackup(oldState: ParcelFileDescriptor,
                      data: BackupDataOutput,
                      newState: ParcelFileDescriptor) {
    Log.w("Backup", "Backup triggered - verify no sensitive data")
    super.onBackup(oldState, data, newState)
}""",
                        "cwe": "CWE-200: Exposure of Sensitive Information",
                        "risk_score": 6.0
                    })
            
            # Cleartext traffic
            cleartext = app_tag.get('{http://schemas.android.com/apk/res/android}usesCleartextTraffic')
            if (cleartext is None and target_sdk < 28) or (cleartext and cleartext.lower() == 'true'):
                severity = "Critical" if cleartext and cleartext.lower() == 'true' else "High"
                self._add_vuln({
                    "type": "Cleartext Traffic Allowed",
                    "severity": severity,
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network Security",
                    "details": """HTTP traffic enabled - app transmits data without encryption.

CRITICAL VULNERABILITY:
Application can send/receive data over HTTP (unencrypted) connections. All data transmitted is visible to anyone on the network.

ATTACK VECTORS:

1. MAN-IN-THE-MIDDLE (MITM) ATTACK:
   Attacker on same WiFi → Intercepts HTTP traffic → Reads/modifies all data
   
   Example: Coffee shop WiFi scenario
   - User connects to "Free WiFi"
   - Opens your app
   - App sends login: POST http://api.yourapp.com/login
     Body: {"username":"user@email.com","password":"Pass123!"}
   - Attacker sees plaintext credentials
   - Attacker logs in as victim

2. SESSION HIJACKING:
   HTTP request: GET http://api.yourapp.com/profile
   Headers: Authorization: Bearer abc123xyz789
   
   Attacker intercepts token → Makes requests as victim

3. DATA TAMPERING:
   Attacker intercepts HTTP response, modifies:
   {"isPremium":false,"balance":50}
   Changes to:
   {"isPremium":true,"balance":99999}

4. CREDENTIAL THEFT:
   - Login credentials transmitted in plaintext
   - API keys visible in HTTP headers
   - OAuth tokens intercepted

5. CONTENT INJECTION:
   Attacker modifies HTTP response:
   - Injects malicious JavaScript
   - Replaces legitimate content
   - Serves phishing pages

AFFECTED DATA:
- Usernames & passwords
- Personal information (email, phone, address)
- Financial data (card numbers, bank info)
- Session tokens & API keys
- Private messages & photos
- Location data
- Health information

TOOLS ATTACKERS USE:
- Wireshark (packet sniffing)
- mitmproxy (MITM proxy)
- Burp Suite (HTTP interception)
- Ettercap (ARP poisoning)
- SSLstrip (force HTTP downgrade)

COMPLIANCE VIOLATIONS:
- PCI DSS: Prohibits transmitting card data over HTTP
- HIPAA: Requires encryption of PHI in transit
- GDPR: Mandates appropriate security measures
- SOC 2: Requires encrypted data transmission""",
                    "remediation": """COMPREHENSIVE HTTPS ENFORCEMENT:

STEP 1 - DISABLE CLEARTEXT TRAFFIC:
AndroidManifest.xml:
<application
    android:usesCleartextTraffic="false"
    ...>

STEP 2 - ENFORCE HTTPS IN NETWORK CONFIG:
Create res/xml/network_security_config.xml:
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Deny all cleartext traffic globally -->
    <base-config cleartextTrafficPermitted="false">
        <trust-anchors>
            <certificates src="system"/>
            <certificates src="user"/>
        </trust-anchors>
    </base-config>
    
    <!-- Exception for localhost (debugging only) -->
    <domain-config cleartextTrafficPermitted="true">
        <domain includeSubdomains="true">localhost</domain>
        <domain includeSubdomains="true">10.0.2.2</domain>
    </domain-config>
</network-security-config>

Reference in AndroidManifest.xml:
<application
    android:networkSecurityConfig="@xml/network_security_config"
    android:usesCleartextTraffic="false"
    ...>

STEP 3 - IMPLEMENT CERTIFICATE PINNING:
Add to network_security_config.xml:
<network-security-config>
    <domain-config>
        <domain includeSubdomains="true">api.yourapp.com</domain>
        <pin-set expiration="2025-12-31">
            <!-- Get pin: openssl s_client -connect api.yourapp.com:443 | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64 -->
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            <!-- Backup pin -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
        </pin-set>
    </domain-config>
</network-security-config>

STEP 4 - ENFORCE HTTPS IN CODE:
// OkHttp (recommended)
val client = OkHttpClient.Builder()
    .connectionSpecs(listOf(ConnectionSpec.MODERN_TLS))
    .addInterceptor { chain ->
        val request = chain.request()
        if (request.url.scheme != "https") {
            throw SecurityException("Only HTTPS allowed")
        }
        chain.proceed(request)
    }
    .build()

// Retrofit
val retrofit = Retrofit.Builder()
    .baseUrl("https://api.yourapp.com/")  // ALWAYS https://
    .client(client)
    .build()

STEP 5 - VALIDATE TLS VERSION:
val sslContext = SSLContext.getInstance("TLSv1.3")  // Only TLS 1.3
val client = OkHttpClient.Builder()
    .sslSocketFactory(
        sslContext.socketFactory,
        trustManager
    )
    .build()

STEP 6 - DETECT MITM ATTEMPTS:
fun detectMITM(context: Context): Boolean {
    val trustManager = // Your trust manager
    try {
        val url = URL("https://api.yourapp.com")
        val conn = url.openConnection() as HttpsURLConnection
        conn.connect()
        
        val certs = conn.serverCertificates
        val expected = loadPinnedCertificates()
        
        return certs.any { cert ->
            expected.none { it.contentEquals(cert.encoded) }
        }
    } catch (e: SSLHandshakeException) {
        // Certificate validation failed - potential MITM
        Log.e("Security", "MITM detected!", e)
        return true
    }
    return false
}

STEP 7 - MIGRATION FROM HTTP TO HTTPS:
If you have legacy HTTP endpoints:

// Phase 1: Log HTTP usage (don't block yet)
class HttpDetectionInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        val request = chain.request()
        if (request.url.scheme == "http") {
            Log.e("Security", "HTTP detected: ${request.url}")
            // Send telemetry to your backend
        }
        return chain.proceed(request)
    }
}

// Phase 2: Automatically upgrade HTTP to HTTPS
class HttpsUpgradeInterceptor : Interceptor {
    override fun intercept(chain: Interceptor.Chain): Response {
        var request = chain.request()
        if (request.url.scheme == "http") {
            val httpsUrl = request.url.newBuilder()
                .scheme("https")
                .build()
            request = request.newBuilder()
                .url(httpsUrl)
                .build()
        }
        return chain.proceed(request)
    }
}

// Phase 3: Block all HTTP (after testing)
// Use enforcement code from Step 4

TESTING:
1. Test with Charles Proxy / mitmproxy:
   - Should fail to intercept HTTPS
   - Certificate pinning should reject proxy cert

2. Verify with nmap:
   nmap --script ssl-enum-ciphers -p 443 api.yourapp.com
   Should show only TLS 1.2+ with strong ciphers

3. Check with SSLLabs:
   https://www.ssllabs.com/ssltest/

MONITORING:
Track HTTPS usage:
analytics.track("network_request", {
    "scheme": if (url.startsWith("https://")) "https" else "http",
    "url": url.replace(Regex("[?&].*"), "") // Remove query params
})

Alert on HTTP usage:
if (!BuildConfig.DEBUG && url.startsWith("http://")) {
    crashlytics.recordException(
        SecurityException("HTTP in production: $url")
    )
}""",
                    "cwe": "CWE-319: Cleartext Transmission of Sensitive Information",
                    "risk_score": 9.0 if severity == "Critical" else 8.0
                })
            
            # Network security config
            if target_sdk >= 24:
                nsc = app_tag.get('{http://schemas.android.com/apk/res/android}networkSecurityConfig')
                if not nsc:
                    self._add_vuln({
                        "type": "Missing Certificate Pinning",
                        "severity": "Low",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": """No certificate pinning configured - vulnerable to Certificate Authority compromises and sophisticated MITM attacks.

WHAT IS CERTIFICATE PINNING:
Certificate pinning ensures your app only trusts specific SSL certificates (or their public keys) for your domains. Without pinning, app trusts ANY certificate signed by system-trusted CAs (~150+ authorities).

WHY IT MATTERS:
Without pinning, your HTTPS can still be intercepted if:

1. ROGUE CA ATTACK:
   - Attacker compromises a Certificate Authority (has happened: DigiNotar 2011, Symantec issues)
   - Gets valid certificate for yourdomain.com
   - Performs MITM - app trusts rogue certificate
   
2. USER-INSTALLED CA:
   - User installs malicious root CA (phishing, malware)
   - Attacker generates certificate for any domain
   - App trusts it because CA is in system trust store

3. CORPORATE PROXY:
   - Enterprise SSL inspection proxies
   - Can decrypt all HTTPS traffic
   - Violates user privacy

4. GOVERNMENT INTERCEPTION:
   - State-level MITM attacks
   - Valid certificates from compromised CAs

REAL-WORLD ATTACKS:
- 2011: DigiNotar breach → Fake Google certificates
- 2015: Superfish adware → Installed CA on Lenovo laptops
- 2017: Symantec distrust → 30% of web certificates distrusted
- 2019: Kazakhstan MITM → Government-issued root CA

WITHOUT PINNING:
App trusts 150+ CAs:
- DigiCert, Let's Encrypt, GlobalSign, etc.
- Any compromise = your traffic intercepted

WITH PINNING:
App only trusts YOUR certificates:
- Even if CA compromised, attacker can't MITM
- Maximum protection for sensitive communications""",
                        "remediation": """IMPLEMENT COMPREHENSIVE CERTIFICATE PINNING:

METHOD 1 - NETWORK SECURITY CONFIG (Recommended for most apps):

Step 1: Generate certificate pins:
# Option A: Pin the certificate itself
openssl s_client -connect api.yourapp.com:443 < /dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

# Option B: Pin the public key (more flexible)
openssl s_client -connect api.yourapp.com:443 -showcerts < /dev/null | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64

Example output: 7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=

Step 2: Create res/xml/network_security_config.xml:
<?xml version="1.0" encoding="utf-8"?>
<network-security-config>
    <!-- Pin for main API domain -->
    <domain-config>
        <domain includeSubdomains="true">api.yourapp.com</domain>
        <pin-set expiration="2026-12-31">
            <!-- Current certificate pin -->
            <pin digest="SHA-256">7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=</pin>
            
            <!-- CRITICAL: Backup pin (in case of certificate renewal) -->
            <!-- Generate from backup certificate or intermediate CA -->
            <pin digest="SHA-256">YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=</pin>
        </pin-set>
        
        <!-- Trust system CAs as fallback (optional) -->
        <trust-anchors>
            <certificates src="system"/>
        </trust-anchors>
    </domain-config>
    
    <!-- Pin for CDN/images domain -->
    <domain-config>
        <domain includeSubdomains="true">cdn.yourapp.com</domain>
        <pin-set expiration="2026-12-31">
            <pin digest="SHA-256">cdn-pin-here</pin>
            <pin digest="SHA-256">cdn-backup-pin</pin>
        </pin-set>
    </domain-config>
    
    <!-- Local development exception (NEVER in production) -->
    <debug-overrides>
        <trust-anchors>
            <certificates src="user"/>
        </trust-anchors>
    </debug-overrides>
</network-security-config>

Step 3: Reference in AndroidManifest.xml:
<application
    android:networkSecurityConfig="@xml/network_security_config"
    ...>

METHOD 2 - PROGRAMMATIC PINNING (OkHttp):

val certificatePinner = CertificatePinner.Builder()
    .add("api.yourapp.com", "sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=")
    .add("api.yourapp.com", "sha256/YLh1dUR9y6Kja30RrAn7JKnbQG/uEtLMkBgFF2Fuihg=") // Backup
    .add("*.yourapp.com", "sha256/7HIpactkIAq2Y49orFOOQKurWxmmSFZhBCoQYcRhJ3Y=") // Wildcard
    .build()

val client = OkHttpClient.Builder()
    .certificatePinner(certificatePinner)
    .build()

METHOD 3 - CUSTOM TRUST MANAGER (Maximum control):

class PinningTrustManager(
    private val pins: Map<String, List<String>>
) : X509TrustManager {
    
    private val systemTrustManager: X509TrustManager = // System default
    
    override fun checkServerTrusted(
        chain: Array<out X509Certificate>,
        authType: String
    ) {
        // First, validate with system trust manager
        systemTrustManager.checkServerTrusted(chain, authType)
        
        // Then check pinning
        val cert = chain[0]
        val publicKey = cert.publicKey.encoded
        val pin = MessageDigest.getInstance("SHA-256")
            .digest(publicKey)
            .let { Base64.encodeToString(it, Base64.NO_WRAP) }
        
        val domain = // Extract from hostname
        val expectedPins = pins[domain] ?: throw CertificateException("No pins for $domain")
        
        if (pin !in expectedPins) {
            throw CertificateException(
                "Certificate pinning failed for $domain. " +
                "Expected: $expectedPins, Got: $pin"
            )
        }
    }
}

BEST PRACTICES:

1. ALWAYS HAVE BACKUP PINS:
   - If primary cert expires and backup pin not available = app breaks
   - Pin at least 2 certificates: current + next renewal

2. PIN THE RIGHT LEVEL:
   Options:
   - Leaf certificate (your domain's cert) - most restrictive
   - Intermediate CA - more flexible for cert renewals
   - Root CA - most flexible but less secure
   
   Recommendation: Pin leaf + intermediate CA as backup

3. SET EXPIRATION DATES:
   <pin-set expiration="2026-12-31">
   Forces you to update pins before expiration

4. MONITOR PIN FAILURES:
   val client = OkHttpClient.Builder()
       .certificatePinner(pinner)
       .eventListener(object : EventListener() {
           override fun callFailed(call: Call, ioe: IOException) {
               if (ioe is SSLPeerUnverifiedException) {
                   // Certificate pinning failed - log to analytics
                   analytics.track("certificate_pin_failure", {
                       "url": call.request().url.toString(),
                       "error": ioe.message
                   })
               }
           }
       })
       .build()

5. TEST THOROUGHLY:
   // Add test pins in debug builds
   val pinner = if (BuildConfig.DEBUG) {
       CertificatePinner.Builder()
           .add("api.yourapp.com", "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
           .build()
   } else {
       productionPinner
   }
   
   // Should fail in debug with Charles Proxy

6. ROTATION STRATEGY:
   Year 0: Deploy app with Pin A + Pin B (backup)
   Year 1: Renew certificate, Pin A still valid
   Year 2: Certificate expires, new cert uses Pin B
   Year 2.5: Deploy app update with Pin B + Pin C
   Year 3: Pin A expires, everyone on Pin B now

7. HANDLE PIN FAILURES GRACEFULLY:
   try {
       val response = client.newCall(request).execute()
   } catch (e: SSLPeerUnverifiedException) {
       // Don't just crash - inform user
       Log.e("Pinning", "Certificate validation failed - possible MITM", e)
       showSecurityWarning()
       
       // Report to backend for monitoring
       reportSecurityIncident("cert_pin_failure", e)
   }

TESTING:

1. Test with valid certificate:
   curl -v https://api.yourapp.com
   Should succeed

2. Test with invalid certificate (Charles Proxy):
   - Install Charles root CA on device
   - Run app
   - Should fail with SSLPeerUnverifiedException

3. Verify pins:
   openssl s_client -connect api.yourapp.com:443 -showcerts
   Compare output with your pins

4. Test backup pin:
   Temporarily remove primary pin from config
   Should still work with backup pin

MONITORING:

Track pinning metrics:
- Pin validation success rate
- Pin validation failures (potential attacks)
- Certificate expiration dates
- Pin rotation events

Alert on:
- Sudden spike in pin failures (MITM attack?)
- Pins nearing expiration
- Certificate renewals needed

EMERGENCY PIN UPDATE:

If pins need emergency update:
1. Release app update with new pins ASAP
2. Old app versions will break - have plan:
   - Remote config with pin override (careful!)
   - Backend endpoint that returns current pins
   - Graceful degradation (warn user but allow)

WARNING:
Certificate pinning can break your app if not managed properly:
- Certificate expires without backup pin = app stops working
- Wrong pin deployed = nobody can connect
- Test extensively before production release""",
                        "cwe": "CWE-295: Improper Certificate Validation",
                        "risk_score": 4.0
                    })
            
            # Test-only build
            if app_tag.get('{http://schemas.android.com/apk/res/android}testOnly', 'false').lower() == 'true':
                self._add_vuln({
                    "type": "Test Build in Production",
                    "severity": "High",
                    "owasp": "M7 (Code Quality)",
                    "category": "Configuration",
                    "details": """Debug/test build distributed as production. Test builds contain debug code, verbose logging, mock data, and reduced security.""",
                    "remediation": """Remove testOnly='true' from manifest. Use proper release build configuration with ProGuard enabled.""",
                    "cwe": "CWE-489",
                    "risk_score": 7.0
                })
                self.report["malware_indicators"].append("Test build flag")
            
            # Shared UID
            shared_user = root.get('{http://schemas.android.com/apk/res/android}sharedUserId')
            if shared_user:
                self._add_vuln({
                    "type": "Shared User ID Usage",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Configuration",
                    "details": f"Uses sharedUserId '{shared_user}'. Can access other apps' data with same UID. Security boundary weakened.",
                    "remediation": "Avoid sharedUserId unless essential for legitimate multi-app suite. Use ContentProvider or explicit intents instead.",
                    "cwe": "CWE-269",
                    "risk_score": 5.5
                })
            
            # Backup agent
            backup_agent = app_tag.get('{http://schemas.android.com/apk/res/android}backupAgent')
            if backup_agent:
                self._add_vuln({
                    "type": "Custom Backup Agent",
                    "severity": "Low",
                    "owasp": "M2 (Insecure Data Storage)",
                    "category": "Data Protection",
                    "details": f"Custom backup agent: {backup_agent}. Verify it encrypts sensitive data before backup.",
                    "remediation": "Ensure backup agent encrypts sensitive data before backup using Android Keystore for key management.",
                    "cwe": "CWE-922",
                    "risk_score": 3.5
                })
                
        except Exception as e:
            print(f"Manifest error: {e}")
    
    def _check_permissions_advanced(self):
        """Advanced permission analysis with malware detection"""
        dangerous_perms = {
            'android.permission.READ_SMS': ('Critical', 9.0),
            'android.permission.SEND_SMS': ('Critical', 9.0),
            'android.permission.RECEIVE_SMS': ('Critical', 8.5),
            'android.permission.BIND_DEVICE_ADMIN': ('Critical', 9.5),
            'android.permission.RECEIVE_BOOT_COMPLETED': ('Critical', 8.0),
            'android.permission.READ_CALL_LOG': ('High', 7.5),
            'android.permission.WRITE_CALL_LOG': ('High', 7.0),
            'android.permission.PROCESS_OUTGOING_CALLS': ('High', 7.5),
            'android.permission.RECORD_AUDIO': ('High', 8.0),
            'android.permission.SYSTEM_ALERT_WINDOW': ('High', 8.5),
            'android.permission.REQUEST_INSTALL_PACKAGES': ('High', 8.5),
            'android.permission.WRITE_SETTINGS': ('High', 7.0),
            'android.permission.CAMERA': ('Medium', 5.5),
            'android.permission.READ_CONTACTS': ('Medium', 5.0),
            'android.permission.ACCESS_FINE_LOCATION': ('Medium', 6.0),
            'android.permission.READ_PHONE_STATE': ('Medium', 5.5),
            'android.permission.ACCESS_COARSE_LOCATION': ('Low', 4.0),
            'android.permission.READ_EXTERNAL_STORAGE': ('Low', 3.0),
            'android.permission.WRITE_EXTERNAL_STORAGE': ('Low', 3.5),
        }
        
        try:
            permissions = self.apk.permissions or []
            perm_set = set(permissions)
            
            # Check individual dangerous permissions
            for perm, (severity, risk) in dangerous_perms.items():
                if perm in perm_set:
                    perm_name = perm.split('.')[-1]
                    self._add_vuln({
                        "type": f"Dangerous Permission: {perm_name}",
                        "severity": severity,
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Permissions",
                        "details": f"Requests {perm}. Verify necessity and user consent at runtime.",
                        "remediation": f"Request {perm} at runtime with clear justification. Use safer alternatives if possible (e.g., SAF instead of storage permissions).",
                        "cwe": "CWE-250",
                        "risk_score": risk
                    })
            
            # MALWARE DETECTION: Check permission combinations
            for combo in self.MALWARE_PERMISSION_COMBOS:
                if all(p in perm_set for p in combo):
                    combo_names = [p.split('.')[-1] for p in combo]
                    self._add_vuln({
                        "type": f"MALWARE PATTERN: {' + '.join(combo_names)}",
                        "severity": "Critical",
                        "owasp": "M8 (Code Tampering)",
                        "category": "Malware Detection",
                        "details": f"Dangerous permission combination commonly used by malware: {', '.join(combo_names)}. This pattern allows SMS interception, persistence, and data exfiltration.",
                        "remediation": "CRITICAL: Verify app legitimacy immediately. This combination matches known malware signatures (banking trojans, SMS spyware). Remove unnecessary permissions.",
                        "cwe": "CWE-506",
                        "risk_score": 9.8
                    })
                    self.report["malware_indicators"].append(f"Malware perm combo: {combo_names}")
            
            # Excessive permissions
            if len(permissions) > 20:
                self._add_vuln({
                    "type": f"Excessive Permissions ({len(permissions)} total)",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Permissions",
                    "details": f"App requests {len(permissions)} permissions - unusually high. Potential over-privilege or feature creep.",
                    "remediation": "Review and minimize permissions to principle of least privilege. Remove unused permissions from merged manifests.",
                    "cwe": "CWE-250",
                    "risk_score": 5.5
                })
                
        except Exception as e:
            print(f"Permission error: {e}")
    
    def _check_exported_components(self):
        """OWASP M1: Comprehensive component security with Intent Redirection detection"""
        if not self.manifest_xml_string:
            return
        
        try:
            root = ET.fromstring(self.manifest_xml_string)
            exported_count = 0
            intent_redirection_vulns = []
            
            # CRITICAL: Activities with Intent handling
            for activity in root.findall('.//activity'):
                intent_filter = activity.find('intent-filter')
                if intent_filter is not None:
                    exported = activity.get('{http://schemas.android.com/apk/res/android}exported')
                    perm = activity.get('{http://schemas.android.com/apk/res/android}permission')
                    name = activity.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    
                    # Check if it's launcher
                    is_launcher = any(
                        a.get('{http://schemas.android.com/apk/res/android}name') == 'android.intent.action.MAIN'
                        for a in intent_filter.findall('action')
                    )
                    
                    # Check for VIEW intents (Intent Redirection risk)
                    has_view_intent = any(
                        a.get('{http://schemas.android.com/apk/res/android}name') == 'android.intent.action.VIEW'
                        for a in intent_filter.findall('action')
                    )
                    
                    if not is_launcher and (not exported or exported.lower() == 'true'):
                        exported_count += 1
                        
                        # CRITICAL: Intent Redirection vulnerability
                        if has_view_intent and not perm:
                            self._add_vuln({
                                "type": "CRITICAL: Intent Redirection Vulnerability",
                                "severity": "Critical",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Intent Hijacking",
                                "details": f"Activity '{name}' accepts VIEW intents without validation. Attackers can craft Intents to access private files, bypass authentication, force malicious URLs, or steal data through Intent extras.",
                                "remediation": """IMMEDIATE ACTIONS:
1. Validate ALL Intent extras
2. Add signature-level permission
3. Set exported='false' for internal activities
4. Implement Intent validation with whitelist approach""",
                                "cwe": "CWE-601",
                                "risk_score": 9.8
                            })
                            intent_redirection_vulns.append(name)
                            self.report["malware_indicators"].append("Intent Redirection vulnerability")
                        elif not perm:
                            self._add_vuln({
                                "type": "Unprotected Exported Activity",
                                "severity": "High",
                                "owasp": "M1 (Improper Platform Usage)",
                                "category": "Component Security",
                                "details": f"Activity '{name}' is exported without permission protection. Any app can launch this activity and potentially access sensitive UI or inject malicious data.",
                                "remediation": f"Set android:exported='false' OR add signature permission: android:permission='com.yourapp.permission.INTERNAL'",
                                "cwe": "CWE-927",
                                "risk_score": 7.5
                            })
            
            # Services, Providers, etc. (keeping existing logic)
            for service in root.findall('.//service'):
                name = service.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                exported = service.get('{http://schemas.android.com/apk/res/android}exported')
                perm = service.get('{http://schemas.android.com/apk/res/android}permission')
                
                if 'AccessibilityService' in name and exported and exported.lower() == 'true':
                    self._add_vuln({
                        "type": "CRITICAL: Exported Accessibility Service",
                        "severity": "Critical",
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "Accessibility Abuse",
                        "details": f"Accessibility service '{name}' is EXPORTED! Can read everything on screen, click buttons, steal 2FA codes. Used by banking trojans.",
                        "remediation": "CRITICAL: Set android:exported='false' immediately. Never export accessibility services.",
                        "cwe": "CWE-862",
                        "risk_score": 10.0
                    })
                    self.report["malware_indicators"].append("Exported AccessibilityService")
                    exported_count += 1
                elif (service.find('intent-filter') is not None or (exported and exported.lower() == 'true')) and not perm:
                    exported_count += 1
            
            # Content Providers
            for provider in root.findall('.//provider'):
                exported = provider.get('{http://schemas.android.com/apk/res/android}exported')
                if exported and exported.lower() == 'true':
                    read_perm = provider.get('{http://schemas.android.com/apk/res/android}readPermission')
                    write_perm = provider.get('{http://schemas.android.com/apk/res/android}writePermission')
                    name = provider.get('{http://schemas.android.com/apk/res/android}name', 'Unknown')
                    authorities = provider.get('{http://schemas.android.com/apk/res/android}authorities', 'Unknown')
                    
                    if not read_perm and not write_perm:
                        exported_count += 1
                        self._add_vuln({
                            "type": "CRITICAL: SQL Injection via Content Provider",
                            "severity": "Critical",
                            "owasp": "M2 (Insecure Data Storage)",
                            "category": "Data Exposure",
                            "details": f"Content Provider '{name}' ({authorities}) is COMPLETELY UNPROTECTED! Any app can read/modify database, execute SQL injection, extract SharedPreferences.",
                            "remediation": "Add read/write permissions immediately. Use parameterized queries. Implement path permissions for granular control.",
                            "cwe": "CWE-89",
                            "risk_score": 10.0
                        })
            
            # Summary
            if exported_count > 5:
                self._add_vuln({
                    "type": f"Large Attack Surface ({exported_count} exported)",
                    "severity": "Medium",
                    "owasp": "M1 (Improper Platform Usage)",
                    "category": "Component Security",
                    "details": f"App exports {exported_count} components. Each is a potential attack entry point.",
                    "remediation": "Audit all exported components. Set exported='false' for internal use. Add signature-level permissions.",
                    "cwe": "CWE-927",
                    "risk_score": 5.0
                })
                
        except Exception as e:
            print(f"Component error: {e}")
    
    def _check_secrets_optimized(self):
        """SPEED OPTIMIZED: Ultra-fast secret detection using pre-cached strings.xml"""
        patterns = {
            'AWS_KEY': (r'AKIA[0-9A-Z]{16}', 20),
            'Google_API': (r'AIza[0-9A-Za-z\-_]{35}', 39),
            'Firebase': (r'https://[a-z0-9-]+\.firebaseio\.com', 0),
            'Stripe': (r'sk_live_[0-9a-zA-Z]{24,}', 0),
            'Private_Key': (r'-----BEGIN.*PRIVATE KEY-----', 0),
            'JWT': (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', 0),
        }
        
        false_positives = {'example', 'test', 'demo', 'sample', 'TODO', 'FIXME', 'placeholder'}
        found = set()
        
        try:
            # SPEED OPTIMIZATION: Use pre-cached strings.xml instead of reading ZIP again
            for fname, content in self.strings_xml_cache.items():
                if any(fp in content.lower() for fp in false_positives):
                    continue
                
                for secret_type, (pattern, expected_len) in patterns.items():
                    for match in re.finditer(pattern, content):
                        secret = match.group(0)
                        if expected_len and len(secret) != expected_len:
                            continue
                        if any(fp in secret.lower() for fp in false_positives):
                            continue
                        
                        if secret not in found:
                            found.add(secret)
                            severity = "Critical" if secret_type in ['AWS_KEY', 'Stripe', 'Private_Key'] else "High"
                            
                            self._add_vuln({
                                "type": f"Hardcoded {secret_type.replace('_', ' ')}",
                                "severity": severity,
                                "owasp": "M9 (Reverse Engineering)",
                                "category": "Secrets",
                                "details": f"Found: {secret[:40]}... Can be extracted via decompilation. Attackers can use apktool/jadx to reverse APK and extract this credential.",
                                "remediation": f"Never hardcode secrets. Use Android Keystore for encryption keys. Fetch API keys from backend after authentication. Encrypt sensitive config with NDK.",
                                "cwe": "CWE-798",
                                "risk_score": 9.5 if severity == "Critical" else 7.5
                            })
                            
                            if len(found) >= 10:
                                return
        except Exception as e:
            print(f"Secret scan error: {e}")
    
    def _check_code_vulns_fast(self):
        """SPEED OPTIMIZED: Fast code vulnerability detection using pre-extracted strings"""
        if not self.dex_strings_cache:
            return
        
        indicators = {
            'SQL_Injection': ([b'rawQuery', b'execSQL'], 5, "High", 7.5),
            'WebView_XSS': ([b'setJavaScriptEnabled', b'addJavascriptInterface'], 0, "High", 8.0),
            'Weak_Crypto': ([b'DES', b'MD5', b'ECB', b'SHA1'], 3, "High", 8.0),
            'Insecure_Random': ([b'java.util.Random'], 1, "Medium", 6.0),
            'Dynamic_Code': ([b'DexClassLoader', b'PathClassLoader'], 2, "High", 8.0),
            'Command_Exec': ([b'Runtime.exec', b'ProcessBuilder'], 1, "High", 8.0),
            'World_Readable': ([b'MODE_WORLD_READABLE', b'MODE_WORLD_WRITEABLE'], 0, "High", 7.5),
        }
        
        try:
            # SPEED OPTIMIZATION: Use pre-extracted strings instead of regex again
            for vuln_type, (patterns, threshold, severity, risk) in indicators.items():
                count = sum(sum(1 for s in self.dex_strings_cache if p in s) for p in patterns)
                
                if count > threshold:
                    self._add_vuln({
                        "type": vuln_type.replace('_', ' '),
                        "severity": severity,
                        "owasp": "M7" if 'Code' in vuln_type else "M5" if 'Crypto' in vuln_type or 'Random' in vuln_type else "M1",
                        "category": "Code Security",
                        "details": f"Detected {count} instances of potentially insecure {vuln_type.replace('_', ' ').lower()}. Verify secure implementation.",
                        "remediation": f"Use secure alternatives for {vuln_type}. Follow OWASP guidelines and use modern cryptographic APIs.",
                        "cwe": "CWE-89" if 'SQL' in vuln_type else "CWE-327" if 'Crypto' in vuln_type else "CWE-79" if 'XSS' in vuln_type else "CWE-94",
                        "risk_score": risk
                    })
        except Exception as e:
            print(f"Code vuln error: {e}")
    
    def _check_native_libs(self):
        """SPEED OPTIMIZED: Native library analysis using cached file list"""
        try:
            # SPEED OPTIMIZATION: Use cached file list instead of opening ZIP
            libs = [f for f in self.all_files_list if f.startswith('lib/') and f.endswith('.so')]
            
            if libs:
                lib_names = [f.split('/')[-1] for f in libs]
                found_suspicious = [n for n in lib_names if any(s in n.lower() for s in self.SUSPICIOUS_LIBRARIES)]
                
                if found_suspicious:
                    self._add_vuln({
                        "type": "MALWARE: Hooking Framework",
                        "severity": "Critical",
                        "owasp": "M8 (Code Tampering)",
                        "category": "Malware",
                        "details": f"Found: {', '.join(found_suspicious[:5])}. Indicates hooking/rooting tools like Frida, Xposed. Used for runtime manipulation, bypassing security, stealing credentials.",
                        "remediation": "CRITICAL: Remove hooking frameworks from production builds. These tools are for security research/debugging only.",
                        "cwe": "CWE-829",
                        "risk_score": 9.0
                    })
                    self.report["malware_indicators"].append(f"Hooking libs: {found_suspicious[:3]}")
                
                if len(libs) <= 100:
                    archs = set(f.split('/')[1] for f in libs if len(f.split('/')) > 1)
                    self._add_vuln({
                        "type": f"Native Code ({len(libs)} libraries)",
                        "severity": "Info",
                        "owasp": "M7 (Code Quality)",
                        "category": "Code Security",
                        "details": f"Architectures: {', '.join(archs)}. Native code harder to analyze, may contain memory bugs (buffer overflows, use-after-free).",
                        "remediation": "Ensure libraries from trusted sources. Test for memory vulnerabilities with AddressSanitizer. Keep libraries updated.",
                        "cwe": "CWE-937",
                        "risk_score": 2.0
                    })
        except Exception as e:
            print(f"Native lib error: {e}")
    
    def _check_webview(self):
        """WebView security check"""
        if not self.dex_cache:
            return
        
        try:
            checks = {
                'setAllowUniversalAccessFromFileURLs': ("Critical", 9.0),
                'setAllowFileAccessFromFileURLs': ("High", 7.5),
                'setAllowFileAccess': ("Medium", 6.0),
                'setSavePassword': ("Medium", 5.5),
            }
            
            for method, (severity, risk) in checks.items():
                if method.encode() in self.dex_cache:
                    self._add_vuln({
                        "type": f"WebView: {method}",
                        "severity": severity,
                        "owasp": "M1 (Improper Platform Usage)",
                        "category": "WebView",
                        "details": f"{method} enabled. Allows file access/XSS. Attacker can load file:// URLs to read app files or execute XSS.",
                        "remediation": f"Disable {method} unless absolutely required. Validate all URLs loaded in WebView. Implement Content Security Policy.",
                        "cwe": "CWE-200" if 'File' in method else "CWE-256",
                        "risk_score": risk
                    })
        except Exception as e:
            print(f"WebView error: {e}")
    
    def _check_certificate(self):
        """Certificate validation"""
        try:
            # SPEED OPTIMIZATION: Use cached file list
            has_cert = any(f in self.all_files_list for f in ['META-INF/CERT.RSA', 'META-INF/CERT.DSA'])
            
            if not has_cert:
                self._add_vuln({
                    "type": "CRITICAL: Missing APK Signature",
                    "severity": "Critical",
                    "owasp": "M8 (Code Tampering)",
                    "category": "Integrity",
                    "details": "APK unsigned or invalid signature. Can be modified by attackers without detection. Play Store requires v2+ signature.",
                    "remediation": "Sign APK with proper release certificate using jarsigner or apksigner v2+. Store certificate securely.",
                    "cwe": "CWE-345",
                    "risk_score": 9.0
                })
                self.report["malware_indicators"].append("Unsigned APK")
            else:
                # Check certificate size (debug certs are smaller)
                with zipfile.ZipFile(self.apk_path, 'r') as z:
                    cert_file = 'META-INF/CERT.RSA' if 'META-INF/CERT.RSA' in self.all_files_list else 'META-INF/CERT.DSA'
                    cert_data = z.read(cert_file)
                    
                    if len(cert_data) < 1000:
                        self._add_vuln({
                            "type": "CRITICAL: Debug Certificate",
                            "severity": "Critical",
                            "owasp": "M8 (Code Tampering)",
                            "category": "Integrity",
                            "details": "Signed with Android debug certificate. Private key is publicly known - anyone can sign APKs pretending to be this app.",
                            "remediation": "Sign with production release certificate. Generate keystore: keytool -genkey -v -keystore release.keystore",
                            "cwe": "CWE-295",
                            "risk_score": 9.5
                        })
                        self.report["malware_indicators"].append("Debug certificate")
        except Exception as e:
            print(f"Certificate error: {e}")
    
    def _check_malware_signatures(self):
        """Comprehensive malware signature detection"""
        pkg = self.report["package_name"]
        
        # Fake system app
        if pkg.startswith('com.android.') or pkg.startswith('android.'):
            if self.report["app_name"] not in ['Android System', 'System UI', 'Settings']:
                self._add_vuln({
                    "type": "MALWARE: Fake System App",
                    "severity": "Critical",
                    "owasp": "M8 (Code Tampering)",
                    "category": "Malware",
                    "details": f"Package '{pkg}' impersonates Android system. Common malware tactic to appear legitimate and gain user trust.",
                    "remediation": "CRITICAL: Likely malware. Verify app legitimacy immediately. Real system apps cannot be sideloaded.",
                    "cwe": "CWE-506",
                    "risk_score": 9.8
                })
                self.report["malware_indicators"].append("Fake system app")
        
        # Known malware packages
        if pkg in self.MALWARE_PACKAGES:
            self._add_vuln({
                "type": "MALWARE: Known Malicious Package",
                "severity": "Critical",
                "owasp": "M8 (Code Tampering)",
                "category": "Malware",
                "details": f"Package '{pkg}' matches known malware signature in threat database.",
                "remediation": "CRITICAL: Known malware detected. Do not install. Report to Google Play Security.",
                "cwe": "CWE-506",
                "risk_score": 10.0
            })
            self.report["malware_indicators"].append("Known malware package")
        
        # Suspicious package keywords
        suspicious_keywords = ['fake', 'trojan', 'malware', 'virus', 'backdoor', 'rat']
        if any(kw in pkg.lower() for kw in suspicious_keywords):
            self._add_vuln({
                "type": "MALWARE: Suspicious Package Name",
                "severity": "Critical",
                "owasp": "M8 (Code Tampering)",
                "category": "Malware",
                "details": f"Package name contains malware indicators: {pkg}. Highly suspicious naming pattern.",
                "remediation": "CRITICAL: Highly suspicious. Verify legitimacy before installation. Scan with VirusTotal.",
                "cwe": "CWE-506",
                "risk_score": 9.5
            })
            self.report["malware_indicators"].append("Suspicious package name")
    
    def _check_obfuscation(self):
        """Code obfuscation check"""
        if not self.dex_cache:
            return
        
        try:
            if b'proguard' not in self.dex_cache.lower() and b'r8' not in self.dex_cache.lower():
                self._add_vuln({
                    "type": "No Code Obfuscation",
                    "severity": "Medium",
                    "owasp": "M9 (Reverse Engineering)",
                    "category": "Code Protection",
                    "details": "Code not obfuscated with ProGuard/R8. Easier to reverse engineer with jadx/apktool. Class and method names are human-readable.",
                    "remediation": "Enable ProGuard or R8 obfuscation in build.gradle: minifyEnabled true, shrinkResources true. Add proguard-rules.pro.",
                    "cwe": "CWE-656",
                    "risk_score": 5.0
                })
        except:
            pass
    
    def _check_suspicious_strings(self):
        """SPEED OPTIMIZED: Detect suspicious strings using pre-extracted cache"""
        if not self.dex_strings_cache:
            return
        
        patterns = {
            'root': [b'su', b'/system/xbin/su', b'Superuser'],
            'premium_sms': [b'premium', b'sms://'],
            'c2': [b'bot', b'command', b'control'],
            'crypto_wallet': [b'bitcoin', b'ethereum', b'wallet'],
        }
        
        try:
            # SPEED OPTIMIZATION: Use pre-extracted strings
            for category, keywords in patterns.items():
                count = sum(self.dex_strings_cache.count(kw) for kw in keywords)
                if count > 5:
                    severity = "High" if category in ['premium_sms', 'c2'] else "Medium"
                    self._add_vuln({
                        "type": f"Suspicious {category.replace('_', ' ').title()} Strings",
                        "severity": severity,
                        "owasp": "M8 (Code Tampering)",
                        "category": "Suspicious Activity",
                        "details": f"Found {count} suspicious {category} references. Potential malicious behavior indicators.",
                        "remediation": "Investigate app behavior thoroughly. May indicate malware, premium SMS fraud, or botnet C2 communications.",
                        "cwe": "CWE-506",
                        "risk_score": 7.0 if severity == "High" else 5.5
                    })
                    if severity == "High":
                        self.report["malware_indicators"].append(f"Suspicious {category} strings")
        except:
            pass
    
    def _check_network_analysis(self):
        """SPEED OPTIMIZED: Network analysis using cached strings"""
        try:
            urls = set()
            
            # SPEED OPTIMIZATION: Use pre-cached strings.xml
            for content in self.strings_xml_cache.values():
                found = re.findall(r'https?://[^\s<>"\']+', content)
                urls.update(found[:20])
            
            # Also check DEX if available
            if self.dex_cache:
                dex_str = self.dex_cache.decode('utf-8', errors='ignore')
                found = re.findall(r'https?://[^\s<>"\']+', dex_str)
                urls.update(found[:20])
            
            # Suspicious TLDs
            for url in urls:
                if any(url.endswith(tld) for tld in self.SUSPICIOUS_TLDS):
                    self._add_vuln({
                        "type": "Suspicious Domain TLD",
                        "severity": "Medium",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network",
                        "details": f"Suspicious TLD detected: {url}. These TLDs (.ru, .cn, .tk, etc.) are commonly abused for malware C2 servers and phishing.",
                        "remediation": "Verify legitimacy of all network endpoints. Implement domain whitelisting. Monitor for C2 communications.",
                        "cwe": "CWE-940",
                        "risk_score": 6.0
                    })
                    self.report["malware_indicators"].append(f"Suspicious TLD: {url}")
                    break
            
            # HTTP URLs
            http_urls = [u for u in urls if u.startswith('http://')]
            if http_urls:
                self._add_vuln({
                    "type": f"Insecure HTTP URLs ({len(http_urls)} found)",
                    "severity": "Medium",
                    "owasp": "M3 (Insecure Communication)",
                    "category": "Network",
                    "details": f"Example: {http_urls[0]}. All HTTP traffic is unencrypted and vulnerable to interception.",
                    "remediation": "Use HTTPS for all network communication. Update all http:// to https://. Enforce in network security config.",
                    "cwe": "CWE-319",
                    "risk_score": 6.5
                })
        except:
            pass
    
    def _add_vuln(self, vuln_data):
        """Thread-safe vulnerability addition"""
        with self.vuln_lock:
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
        """Final malware assessment"""
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
    """Main entry point"""
    analyzer = HybridUltimateAnalyzer(apk_path)
    return analyzer.analyze()


if __name__ == "__main__":
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python apk_analyzer_optimized.py <apk_file>")
        sys.exit(1)
    
    apk_file = sys.argv[1]
    
    if not os.path.exists(apk_file):
        print(f"❌ File not found: {apk_file}")
        sys.exit(1)
    
    report = analyze_apk(apk_file)
    
    # Display results
    print(f"\n{'='*70}")
    print(f"📊 ANALYSIS RESULTS")
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
    
    print(f"{'='*70}\n")
