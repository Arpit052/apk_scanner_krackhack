"""Bytecode-level rules (WebView, TLS, crypto, storage, IPC, privacy, capabilities)."""

from __future__ import annotations

import re
from typing import Dict, List

from .context import Finding, ScanContext, java
from .dex import ApiSpec, CallSite, method_is_trivial
from .knowledge import SECURITY_CONTROL_APIS

W = "Landroid/webkit/WebSettings;"
WV = "Landroid/webkit/WebView;"

SPECS = [
    # WebView
    ApiSpec("wv_js", W, "setJavaScriptEnabled"),
    ApiSpec("wv_file", W, "setAllowFileAccess"),
    ApiSpec("wv_file_from_file", W, "setAllowFileAccessFromFileURLs"),
    ApiSpec("wv_universal", W, "setAllowUniversalAccessFromFileURLs"),
    ApiSpec("wv_content", W, "setAllowContentAccess"),
    ApiSpec("wv_mixed", W, "setMixedContentMode"),
    ApiSpec("wv_savepw", W, "setSavePassword"),
    ApiSpec("wv_debug", WV, "setWebContentsDebuggingEnabled", static=True),
    ApiSpec("wv_jsi", "*", "addJavascriptInterface", "Ljava/lang/Object;Ljava/lang/String;"),
    ApiSpec("wv_load", "*", "loadUrl", "Ljava/lang/String;"),
    ApiSpec("wv_ssl_proceed", "Landroid/webkit/SslErrorHandler;", "proceed"),
    # TLS
    ApiSpec("ssl_allow_all_hv", "Ljavax/net/ssl/HttpsURLConnection;", "setDefaultHostnameVerifier", static=True),
    ApiSpec("ssl_set_hv", "*", "setHostnameVerifier"),
    ApiSpec("ssl_ctx_init", "Ljavax/net/ssl/SSLContext;", "init"),
    ApiSpec("ssl_ctx_get", "Ljavax/net/ssl/SSLContext;", "getInstance", static=True),
    # crypto
    ApiSpec("cipher", "Ljavax/crypto/Cipher;", "getInstance", static=True),
    ApiSpec("digest", "Ljava/security/MessageDigest;", "getInstance", static=True),
    ApiSpec("secret_key", "Ljavax/crypto/spec/SecretKeySpec;", "<init>"),
    ApiSpec("iv_spec", "Ljavax/crypto/spec/IvParameterSpec;", "<init>"),
    ApiSpec("pbe_spec", "Ljavax/crypto/spec/PBEKeySpec;", "<init>"),
    ApiSpec("random", "Ljava/util/Random;", "<init>"),
    ApiSpec("math_random", "Ljava/lang/Math;", "random", static=True),
    ApiSpec("securerandom_seed", "Ljava/security/SecureRandom;", "<init>", "[B"),
    ApiSpec("securerandom_setseed", "Ljava/security/SecureRandom;", "setSeed"),
    ApiSpec("keygen", "Ljavax/crypto/KeyGenerator;", "getInstance", static=True),
    # storage
    ApiSpec("prefs", "*", "getSharedPreferences", "Ljava/lang/String;I"),
    ApiSpec("file_out", "*", "openFileOutput", "Ljava/lang/String;I"),
    ApiSpec("open_db", "*", "openOrCreateDatabase", None),
    ApiSpec("get_dir", "*", "getDir", "Ljava/lang/String;I"),
    ApiSpec("ext_dir", "Landroid/os/Environment;", "getExternalStorageDirectory", static=True),
    ApiSpec("ext_pub_dir", "Landroid/os/Environment;", "getExternalStoragePublicDirectory", static=True),
    ApiSpec("file_readable", "Ljava/io/File;", "setReadable"),
    ApiSpec("file_writable", "Ljava/io/File;", "setWritable"),
    ApiSpec("temp_file", "Ljava/io/File;", "createTempFile", static=True),
    # SQL
    ApiSpec("raw_query", "Landroid/database/sqlite/SQLiteDatabase;", "rawQuery"),
    ApiSpec("exec_sql", "Landroid/database/sqlite/SQLiteDatabase;", "execSQL"),
    # IPC
    ApiSpec("get_parcelable_extra", "Landroid/content/Intent;", "getParcelableExtra"),
    ApiSpec("parse_uri", "Landroid/content/Intent;", "parseUri", static=True),
    ApiSpec("start_activity", "*", "startActivity", "Landroid/content/Intent;"),
    ApiSpec("start_activity_fr", "*", "startActivityForResult", "Landroid/content/Intent;I"),
    ApiSpec("start_service", "*", "startService", "Landroid/content/Intent;"),
    ApiSpec("send_broadcast", "*", "sendBroadcast", "Landroid/content/Intent;"),
    ApiSpec("set_result", "Landroid/app/Activity;", "setResult", "ILandroid/content/Intent;"),
    ApiSpec("get_data", "Landroid/content/Intent;", "getData"),
    ApiSpec("get_string_extra", "Landroid/content/Intent;", "getStringExtra"),
    ApiSpec("get_query_param", "Landroid/net/Uri;", "getQueryParameter"),
    ApiSpec("pending_activity", "Landroid/app/PendingIntent;", "getActivity", static=True),
    ApiSpec("pending_broadcast", "Landroid/app/PendingIntent;", "getBroadcast", static=True),
    ApiSpec("pending_service", "Landroid/app/PendingIntent;", "getService", static=True),
    ApiSpec("sticky_broadcast", "*", "sendStickyBroadcast", None),
    ApiSpec("register_receiver", "*", "registerReceiver", "Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;"),
    # logging / leaks
    ApiSpec("log_d", "Landroid/util/Log;", "d", static=True),
    ApiSpec("log_v", "Landroid/util/Log;", "v", static=True),
    ApiSpec("log_i", "Landroid/util/Log;", "i", static=True),
    ApiSpec("clipboard", "Landroid/content/ClipboardManager;", "setPrimaryClip"),
    ApiSpec("win_add_flags", "Landroid/view/Window;", "addFlags"),
    ApiSpec("win_set_flags", "Landroid/view/Window;", "setFlags"),
    ApiSpec("filter_touches", "*", "setFilterTouchesWhenObscured"),
    # dynamic code / exec
    ApiSpec("dexloader", "Ldalvik/system/DexClassLoader;", "<init>"),
    ApiSpec("memdexloader", "Ldalvik/system/InMemoryDexClassLoader;", "<init>"),
    ApiSpec("pathloader", "Ldalvik/system/PathClassLoader;", "<init>"),
    ApiSpec("load_dex", "Ldalvik/system/DexFile;", "loadDex", static=True),
    ApiSpec("exec", "Ljava/lang/Runtime;", "exec"),
    ApiSpec("process_builder", "Ljava/lang/ProcessBuilder;", "<init>"),
    ApiSpec("load_library", "Ljava/lang/System;", "load", static=True),
    # privacy / capabilities
    ApiSpec("device_id", "Landroid/telephony/TelephonyManager;", "getDeviceId"),
    ApiSpec("imei", "Landroid/telephony/TelephonyManager;", "getImei"),
    ApiSpec("subscriber_id", "Landroid/telephony/TelephonyManager;", "getSubscriberId"),
    ApiSpec("line1", "Landroid/telephony/TelephonyManager;", "getLine1Number"),
    ApiSpec("sim_serial", "Landroid/telephony/TelephonyManager;", "getSimSerialNumber"),
    ApiSpec("android_id", "Landroid/provider/Settings$Secure;", "getString", static=True),
    ApiSpec("mac", "Landroid/net/wifi/WifiInfo;", "getMacAddress"),
    ApiSpec("send_sms", "Landroid/telephony/SmsManager;", "sendTextMessage"),
    ApiSpec("send_sms_multi", "Landroid/telephony/SmsManager;", "sendMultipartTextMessage"),
    ApiSpec("send_data_sms", "Landroid/telephony/SmsManager;", "sendDataMessage"),
    ApiSpec("abort_broadcast", "*", "abortBroadcast", ""),
    ApiSpec("location_last", "Landroid/location/LocationManager;", "getLastKnownLocation"),
    ApiSpec("location_updates", "Landroid/location/LocationManager;", "requestLocationUpdates"),
    ApiSpec("fused_location", "Lcom/google/android/gms/location/FusedLocationProviderClient;", "getLastLocation"),
    ApiSpec("audio_record", "Landroid/media/AudioRecord;", "startRecording"),
    ApiSpec("media_record", "Landroid/media/MediaRecorder;", "setAudioSource"),
    ApiSpec("camera_open", "Landroid/hardware/Camera;", "open", static=True),
    ApiSpec("camera2_open", "Landroid/hardware/camera2/CameraManager;", "openCamera"),
    ApiSpec("installed_pkgs", "Landroid/content/pm/PackageManager;", "getInstalledPackages"),
    ApiSpec("installed_apps", "Landroid/content/pm/PackageManager;", "getInstalledApplications"),
    ApiSpec("component_state", "Landroid/content/pm/PackageManager;", "setComponentEnabledSetting"),
    ApiSpec("dpm_lock", "Landroid/app/admin/DevicePolicyManager;", "lockNow"),
    ApiSpec("dpm_wipe", "Landroid/app/admin/DevicePolicyManager;", "wipeData"),
    ApiSpec("dpm_reset_pw", "Landroid/app/admin/DevicePolicyManager;", "resetPassword"),
    ApiSpec("a11y_global", "Landroid/accessibilityservice/AccessibilityService;", "performGlobalAction"),
    ApiSpec("a11y_gesture", "Landroid/accessibilityservice/AccessibilityService;", "dispatchGesture"),
    ApiSpec("a11y_root", "Landroid/accessibilityservice/AccessibilityService;", "getRootInActiveWindow"),
    ApiSpec("a11y_node_action", "Landroid/view/accessibility/AccessibilityNodeInfo;", "performAction"),
    ApiSpec("overlay_add", "Landroid/view/WindowManager;", "addView"),
    ApiSpec("pkg_installer", "Landroid/content/pm/PackageInstaller;", "createSession"),
    ApiSpec("media_projection", "Landroid/media/projection/MediaProjectionManager;", "createScreenCaptureIntent"),
    ApiSpec("contacts_query", "Landroid/content/ContentResolver;", "query"),
    ApiSpec("call_log_delete", "Landroid/content/ContentResolver;", "delete"),
    ApiSpec("set_wallpaper", "Landroid/app/WallpaperManager;", "setBitmap"),
    ApiSpec("hide_icon_alias", "Landroid/content/ComponentName;", "<init>"),
    ApiSpec("reflection_invoke", "Ljava/lang/reflect/Method;", "invoke"),
    ApiSpec("class_forname", "Ljava/lang/Class;", "forName", static=True),
    ApiSpec("debug_check", "Landroid/os/Debug;", "isDebuggerConnected", static=True),
    ApiSpec("keyguard_disable", "Landroid/app/KeyguardManager$KeyguardLock;", "disableKeyguard"),
    ApiSpec("battery_ignore", "Landroid/os/PowerManager;", "isIgnoringBatteryOptimizations"),
]


def _str(v):
    return v[1] if isinstance(v, tuple) and v[0] == "str" else None


def _true(v) -> bool:
    return isinstance(v, int) and not isinstance(v, bool) and v != 0


def run(ctx: ScanContext) -> None:
    dex = ctx.dex
    if not dex.dexes:
        ctx.add(Finding("CODE-000", "No DEX bytecode found", "Info", "M7", "MASVS-RESILIENCE", "CWE-693",
                        "Code", "The APK contains no classes*.dex. It may be a resource-only split, or code is "
                        "packed/encrypted and loaded at runtime.",
                        "Scan the base APK of the bundle, or investigate runtime unpacking."))
        return
    ctx.log(f"bytecode scan across {len(dex.dexes)} dex file(s)")
    calls = dex.find_calls(SPECS, max_per_api=60)
    ctx._calls = calls
    _webview(ctx, calls)
    _tls(ctx, calls)
    _crypto(ctx, calls)
    _storage(ctx, calls)
    _sql(ctx, calls)
    _ipc(ctx, calls)
    _logging_leaks(ctx, calls)
    _dynamic_code(ctx, calls)
    _capabilities(ctx, calls)
    _controls(ctx)
    _obfuscation(ctx)


def app_sites(ctx: ScanContext, sites: List[CallSite]) -> List[CallSite]:
    return [s for s in sites if not ctx.is_library(s.caller_class)]


# --------------------------------------------------------------------------- #
def _webview(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    js = [s for s in c["wv_js"] if _true(s.args[0]) or s.args[0] is None]
    if js:
        ctx.add_code_finding(Finding(
            "WV-001", "JavaScript enabled in WebView", "Low", "M4", "MASVS-PLATFORM", "CWE-79", "WebView",
            "WebSettings.setJavaScriptEnabled(true) is called. If the WebView renders any content an attacker "
            "can influence (deep-link URLs, HTTP pages, user data) this enables XSS inside the app context.",
            "Enable JavaScript only for trusted, HTTPS-loaded content and validate every URL before loadUrl().",
            evidence=["WebSettings.setJavaScriptEnabled(true)"]), js)

    for key, rid, title, sev, why in (
        ("wv_universal", "WV-002", "WebView allows universal access from file URLs", "High",
         "setAllowUniversalAccessFromFileURLs(true) lets JavaScript in a file:// page read ANY origin and "
         "local file, so a single malicious HTML file can exfiltrate app data."),
        ("wv_file_from_file", "WV-003", "WebView allows file access from file URLs", "High",
         "setAllowFileAccessFromFileURLs(true) lets file:// pages read other local files (e.g. "
         "shared_prefs/*.xml) through XHR."),
        ("wv_file", "WV-004", "WebView file:// access explicitly enabled", "Medium",
         "setAllowFileAccess(true) exposes the app's files to content loaded in the WebView."),
        ("wv_content", "WV-005", "WebView content:// access explicitly enabled", "Low",
         "setAllowContentAccess(true) lets WebView content read from content providers."),
    ):
        sites = [s for s in c[key] if _true(s.args[0])]
        if sites:
            ctx.add_code_finding(Finding(
                rid, title, sev, "M4", "MASVS-PLATFORM", "CWE-200", "WebView", why,
                f"Pass false (the secure default on modern API levels):\n\nwebView.getSettings().{key_to_method(key)}(false);",
                evidence=[f"WebSettings.{key_to_method(key)}(true)"]), sites)

    mixed = [s for s in c["wv_mixed"] if s.args and s.args[0] == 0]
    if mixed:
        ctx.add_code_finding(Finding(
            "WV-006", "WebView allows mixed (HTTP) content", "Medium", "M5", "MASVS-NETWORK", "CWE-319",
            "WebView", "setMixedContentMode(MIXED_CONTENT_ALWAYS_ALLOW) loads HTTP sub-resources (scripts!) "
            "inside HTTPS pages, letting a network attacker inject JavaScript.",
            "Use WebSettings.MIXED_CONTENT_NEVER_ALLOW.", evidence=["setMixedContentMode(0)"]), mixed)

    dbg = [s for s in c["wv_debug"] if _true(s.args[0])]
    if dbg:
        ctx.add_code_finding(Finding(
            "WV-007", "WebView remote debugging enabled", "Medium", "M7", "MASVS-RESILIENCE", "CWE-489",
            "WebView", "WebView.setWebContentsDebuggingEnabled(true) exposes every WebView to chrome://inspect "
            "over ADB, allowing script injection and cookie/session theft.",
            "Guard the call with BuildConfig.DEBUG or remove it from release builds.",
            evidence=["WebView.setWebContentsDebuggingEnabled(true)"]), dbg)

    if c["wv_jsi"]:
        old = ctx.min_sdk < 17
        ctx.add_code_finding(Finding(
            "WV-008", "JavaScript bridge exposed to WebView (addJavascriptInterface)",
            "High" if old else "Medium", "M4", "MASVS-PLATFORM", "CWE-749", "WebView",
            ("minSdkVersion < 17: on these devices every public method of the bridged object, including "
             "getClass().forName(...), is callable from JavaScript = remote code execution. " if old else "") +
            "Any page loaded in the WebView (including one injected via XSS or an open redirect) can call the "
            "@JavascriptInterface methods.",
            "Only expose minimal @JavascriptInterface methods, load exclusively trusted HTTPS origins and "
            "verify the current URL inside each bridge method.",
            evidence=[f"addJavascriptInterface(obj, \"{_str(s.args[1]) or '?'}\")" for s in c["wv_jsi"][:6]]),
            c["wv_jsi"])

    proceed = [s for s in c["wv_ssl_proceed"] if s.caller_method == "onReceivedSslError"]
    if proceed:
        ctx.add_code_finding(Finding(
            "WV-009", "WebView ignores TLS certificate errors", "High", "M5", "MASVS-NETWORK", "CWE-295",
            "Network Security",
            "WebViewClient.onReceivedSslError() calls handler.proceed(), so invalid, self-signed or attacker "
            "certificates are silently accepted and HTTPS pages can be intercepted.",
            "Call handler.cancel() (the default) and fix the server certificate instead.",
            evidence=["SslErrorHandler.proceed() inside onReceivedSslError()"]), proceed)

    http_loads = [s for s in c["wv_load"] if (_str(s.args[0]) or "").startswith("http://")]
    if http_loads:
        ctx.add_code_finding(Finding(
            "WV-010", "WebView loads hardcoded HTTP URL", "Medium", "M5", "MASVS-NETWORK", "CWE-319",
            "WebView", "A WebView loads content over plain HTTP; an attacker on the network can replace the page "
            "(and abuse any JavaScript bridge).",
            "Load HTTPS URLs only.", evidence=[f"loadUrl(\"{_str(s.args[0])}\")" for s in http_loads[:6]]),
            http_loads)
    file_loads = [s for s in c["wv_load"] if (_str(s.args[0]) or "").startswith("file://") and
                  not (_str(s.args[0]) or "").startswith("file:///android_asset/")]
    if file_loads:
        ctx.add_code_finding(Finding(
            "WV-011", "WebView loads file:// content from storage", "Low", "M4", "MASVS-PLATFORM", "CWE-73",
            "WebView", "Loading HTML from writable storage lets anyone who can write that file inject script.",
            "Bundle HTML in assets and load via WebViewAssetLoader (https://appassets.androidplatform.net).",
            evidence=[f"loadUrl(\"{_str(s.args[0])}\")" for s in file_loads[:6]]), file_loads)


def key_to_method(key: str) -> str:
    return {"wv_universal": "setAllowUniversalAccessFromFileURLs",
            "wv_file_from_file": "setAllowFileAccessFromFileURLs",
            "wv_file": "setAllowFileAccess", "wv_content": "setAllowContentAccess"}[key]


# --------------------------------------------------------------------------- #
def _tls(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    dex = ctx.dex
    trust_all = []
    for dx, cls in dex.implementors(["Ljavax/net/ssl/X509TrustManager;", "Ljavax/net/ssl/X509ExtendedTrustManager;"]):
        for em in cls.methods:
            m = dx.methods[em.method_idx]
            if m.name != "checkServerTrusted" or not em.code_off:
                continue
            u = dx.code_units(em.code_off)
            if u is None:
                continue
            trivial, _ = method_is_trivial(u, dx.methods)
            if trivial:
                trust_all.append(cls.name)
                break
    if trust_all:
        app = [t for t in trust_all if not ctx.is_library(t)]
        f = Finding(
            "TLS-001", "TrustManager accepts every certificate", "Critical", "M5", "MASVS-NETWORK", "CWE-295",
            "Network Security",
            "A custom X509TrustManager has an empty checkServerTrusted() implementation. Any certificate, "
            "including one generated by an attacker, is accepted, which completely defeats HTTPS.",
            "Delete the custom TrustManager and use the platform default. To trust a private CA, declare it "
            "in res/xml/network_security_config.xml instead of overriding validation in code.",
            evidence=[f"{java(t)}.checkServerTrusted() is empty" for t in trust_all[:8]],
            locations=[java(t) + ("" if t in app else "  [library]") for t in trust_all],
            references=["https://developer.android.com/privacy-and-security/risks/unsafe-trustmanager"])
        if not app:
            f.severity, f.confidence, f.in_library = "Medium", "Low", True
            f.description += " The implementation lives in third-party code (may be unused)."
        ctx.add(f)
        if app:
            ctx.signal("trust_all", "Disables TLS certificate validation", 3, java(app[0]))

    always_true = []
    for dx, cls in dex.implementors(["Ljavax/net/ssl/HostnameVerifier;"]):
        for em in cls.methods:
            m = dx.methods[em.method_idx]
            if m.name != "verify" or not em.code_off:
                continue
            u = dx.code_units(em.code_off)
            if u is None:
                continue
            trivial, ret = method_is_trivial(u, dx.methods)
            if trivial and ret == 1:
                always_true.append(cls.name)
    allow_all_field = dex.references_field("Lorg/apache/http/conn/ssl/SSLSocketFactory;", "ALLOW_ALL_HOSTNAME_VERIFIER")
    if always_true or allow_all_field:
        app = [t for t in always_true if not ctx.is_library(t)]
        f = Finding(
            "TLS-002", "Hostname verification disabled", "High", "M5", "MASVS-NETWORK", "CWE-297",
            "Network Security",
            "A HostnameVerifier always returns true (or ALLOW_ALL_HOSTNAME_VERIFIER is used), so a valid "
            "certificate for ANY domain is accepted for your API host.",
            "Never override hostname verification; use HttpsURLConnection/OkHttp defaults.",
            evidence=[f"{java(t)}.verify() returns true" for t in always_true[:8]] +
                     (["SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER referenced"] if allow_all_field else []),
            locations=[java(t) for t in always_true])
        if always_true and not app and not allow_all_field:
            f.severity, f.confidence, f.in_library = "Low", "Low", True
        ctx.add(f)

    weak_proto = [s for s in c["ssl_ctx_get"] if (_str(s.args[0]) or "").upper() in ("SSL", "SSLV3", "TLSV1", "TLSV1.1")]
    if weak_proto:
        ctx.add_code_finding(Finding(
            "TLS-003", "Deprecated SSL/TLS protocol requested", "Medium", "M5", "MASVS-NETWORK", "CWE-326",
            "Network Security", "SSLContext.getInstance() is asked for SSL/TLS 1.0/1.1, which are broken or "
            "deprecated (POODLE, BEAST).", "Use SSLContext.getInstance(\"TLS\") and let the platform negotiate "
            "TLS 1.2/1.3.", evidence=[f"SSLContext.getInstance(\"{_str(s.args[0])}\")" for s in weak_proto[:5]]),
            weak_proto)


# --------------------------------------------------------------------------- #
WEAK_CIPHERS = re.compile(r"^(DES|DESEDE|3DES|TRIPLEDES|RC2|RC4|ARCFOUR|BLOWFISH)(/|$)", re.I)


def _crypto(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    weak, ecb, rsa_nopad, rsa_pkcs1 = [], [], [], []
    for s in c["cipher"]:
        t = _str(s.args[0]) if s.args else None
        if not t:
            continue
        tu = t.upper()
        if WEAK_CIPHERS.match(tu):
            weak.append((s, t))
        elif tu.startswith("AES") and ("/ECB" in tu or tu == "AES"):
            ecb.append((s, t))
        elif tu.startswith("RSA") and "NOPADDING" in tu:
            rsa_nopad.append((s, t))
        elif tu in ("RSA", "RSA/ECB/PKCS1PADDING", "RSA/NONE/PKCS1PADDING"):
            rsa_pkcs1.append((s, t))
    if weak:
        ctx.add_code_finding(Finding(
            "CRY-001", "Broken symmetric cipher (DES/3DES/RC4/Blowfish)", "High", "M10", "MASVS-CRYPTO",
            "CWE-327", "Cryptography",
            "Obsolete ciphers with small keys/blocks are used; ciphertext can be brute-forced or attacked "
            "with known cryptanalysis (Sweet32, RC4 biases).",
            "Use AES-256-GCM (Cipher.getInstance(\"AES/GCM/NoPadding\")) with keys from the Android Keystore.",
            evidence=[f"Cipher.getInstance(\"{t}\")" for _, t in weak[:8]]), [s for s, _ in weak])
    if ecb:
        ctx.add_code_finding(Finding(
            "CRY-002", "AES used in ECB mode", "High", "M10", "MASVS-CRYPTO", "CWE-327", "Cryptography",
            "ECB encrypts identical plaintext blocks to identical ciphertext blocks, leaking patterns. Note "
            "that Cipher.getInstance(\"AES\") silently defaults to AES/ECB/PKCS5Padding.",
            "Use an authenticated mode: Cipher.getInstance(\"AES/GCM/NoPadding\") with a random 12-byte IV per "
            "message.", evidence=[f"Cipher.getInstance(\"{t}\")" for _, t in ecb[:8]]), [s for s, _ in ecb])
    if rsa_nopad:
        ctx.add_code_finding(Finding(
            "CRY-003", "RSA without padding", "High", "M10", "MASVS-CRYPTO", "CWE-780", "Cryptography",
            "Textbook RSA (NoPadding) is deterministic and malleable.", "Use RSA/ECB/OAEPWithSHA-256AndMGF1Padding.",
            evidence=[f"Cipher.getInstance(\"{t}\")" for _, t in rsa_nopad[:8]]), [s for s, _ in rsa_nopad])
    if rsa_pkcs1:
        ctx.add_code_finding(Finding(
            "CRY-004", "RSA with PKCS#1 v1.5 padding", "Medium", "M10", "MASVS-CRYPTO", "CWE-780", "Cryptography",
            "PKCS#1 v1.5 encryption padding is vulnerable to padding-oracle attacks (Bleichenbacher).",
            "Use OAEP padding: RSA/ECB/OAEPWithSHA-256AndMGF1Padding.",
            evidence=[f"Cipher.getInstance(\"{t}\")" for _, t in rsa_pkcs1[:8]]), [s for s, _ in rsa_pkcs1])

    weak_hash = [(s, _str(s.args[0])) for s in c["digest"] if s.args and
                 (_str(s.args[0]) or "").upper().replace("-", "") in ("MD5", "MD4", "MD2", "SHA1", "SHA")]
    if weak_hash:
        ctx.add_code_finding(Finding(
            "CRY-005", "Weak hash algorithm (MD5/SHA-1)", "Medium", "M10", "MASVS-CRYPTO", "CWE-328",
            "Cryptography",
            "MD5 and SHA-1 are broken for collision resistance and must not be used for passwords, signatures "
            "or integrity checks.",
            "Use SHA-256 or better; for passwords use PBKDF2/Argon2/scrypt with a salt.",
            evidence=sorted({f"MessageDigest.getInstance(\"{t}\")" for _, t in weak_hash})),
            [s for s, _ in weak_hash], min_app_sites=1)

    hard_keys = [s for s in c["secret_key"] if s.args and isinstance(s.args[0], tuple) and s.args[0][0] == "bytes"]
    if hard_keys:
        ctx.add_code_finding(Finding(
            "CRY-006", "Hardcoded encryption key", "High", "M10", "MASVS-CRYPTO", "CWE-321", "Cryptography",
            "A SecretKeySpec is built from a string literal compiled into the app. Anyone can decompile the "
            "APK, recover the key and decrypt (or forge) the protected data.",
            "Generate keys inside the Android Keystore (KeyGenerator with KeyGenParameterSpec) and never embed "
            "them in code.",
            evidence=[f"new SecretKeySpec(\"{_mask(s.args[0][1])}\".getBytes(), \"{_str(s.args[1]) or '?'}\")"
                      for s in hard_keys[:6]], tags=["secret"]), hard_keys)
        if app_sites(ctx, hard_keys):
            ctx.signal("hardcoded_key", "Hardcoded crypto key (often used to hide config/C2)", 2)

    static_iv = [s for s in c["iv_spec"] if s.args and isinstance(s.args[0], tuple) and s.args[0][0] == "bytes"]
    if static_iv:
        ctx.add_code_finding(Finding(
            "CRY-007", "Static / hardcoded IV", "Medium", "M10", "MASVS-CRYPTO", "CWE-329", "Cryptography",
            "An IvParameterSpec is built from a constant. Reusing an IV breaks CBC confidentiality and is "
            "catastrophic for GCM/CTR.", "Generate a fresh random IV with SecureRandom for every encryption "
            "and store it alongside the ciphertext.",
            evidence=[f"new IvParameterSpec(\"{_mask(s.args[0][1])}\".getBytes())" for s in static_iv[:6]]),
            static_iv)

    hard_pw = [s for s in c["pbe_spec"] if s.args and isinstance(s.args[0], tuple) and s.args[0][0] == "bytes"]
    if hard_pw:
        ctx.add_code_finding(Finding(
            "CRY-008", "Hardcoded password for key derivation", "High", "M1", "MASVS-CRYPTO", "CWE-259",
            "Cryptography", "PBEKeySpec is created from a constant password, so the derived key is effectively "
            "public.", "Derive keys from user secrets or use Keystore-backed keys.",
            evidence=[f"new PBEKeySpec(\"{_mask(s.args[0][1])}\".toCharArray(), …)" for s in hard_pw[:5]]), hard_pw)

    rnd = app_sites(ctx, c["random"]) + app_sites(ctx, c["math_random"])
    if rnd:
        ctx.add_code_finding(Finding(
            "CRY-009", "Non-cryptographic random number generator", "Low", "M10", "MASVS-CRYPTO", "CWE-330",
            "Cryptography",
            "java.util.Random / Math.random() are predictable. If their output is used for tokens, OTPs, "
            "nonces or keys an attacker can reproduce it.",
            "Use java.security.SecureRandom for anything security-relevant.",
            evidence=["new java.util.Random() / Math.random()"], confidence="Medium"), rnd)

    seeded = [s for s in c["securerandom_seed"] if s.args and isinstance(s.args[0], tuple)] + \
             [s for s in c["securerandom_setseed"] if s.args and (isinstance(s.args[0], int) or isinstance(s.args[0], tuple))]
    if seeded:
        ctx.add_code_finding(Finding(
            "CRY-010", "SecureRandom seeded with a constant", "High", "M10", "MASVS-CRYPTO", "CWE-336",
            "Cryptography", "Seeding SecureRandom with a fixed value makes its output deterministic on some "
            "providers.", "Never call setSeed() with constants; let the platform seed SecureRandom.",
            evidence=["SecureRandom(seed) / setSeed(constant)"]), seeded)


def _mask(s: str) -> str:
    s = s or ""
    if len(s) <= 6:
        return s[:1] + "•" * max(len(s) - 1, 0)
    return s[:3] + "•" * min(len(s) - 5, 12) + s[-2:]


# --------------------------------------------------------------------------- #
def _storage(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    world = []
    for key in ("prefs", "file_out", "get_dir", "open_db"):
        for s in c[key]:
            mode = s.args[1] if len(s.args) > 1 else None
            if isinstance(mode, int) and mode & 0x3:
                world.append((s, key, mode))
    if world:
        ctx.add_code_finding(Finding(
            "STO-001", "World-readable/writable files", "High", "M9", "MASVS-STORAGE", "CWE-276", "Data Storage",
            "Files, SharedPreferences or databases are created with MODE_WORLD_READABLE/WRITEABLE, so every app "
            "on the device can read or tamper with them.",
            "Always use Context.MODE_PRIVATE and share data through a FileProvider with explicit grants.",
            evidence=[f"{k}(…, mode={m})" for _, k, m in world[:8]]), [s for s, _, _ in world])

    for key, rid in (("file_readable", "STO-002"), ("file_writable", "STO-003")):
        sites = [s for s in c[key] if len(s.args) >= 2 and _true(s.args[0]) and s.args[1] == 0]
        if sites:
            ctx.add_code_finding(Finding(
                rid, "File permissions opened to all users", "Medium", "M9", "MASVS-STORAGE", "CWE-732",
                "Data Storage", f"File.{key.split('_')[1]}… is called with ownerOnly=false, granting the "
                "permission to every app.", "Keep ownerOnly=true (the default).",
                evidence=[f"File.set{'Readable' if 'read' in key else 'Writable'}(true, false)"]), sites)

    ext = c["ext_dir"] + c["ext_pub_dir"]
    if ext:
        ctx.add_code_finding(Finding(
            "STO-004", "Data written to shared external storage", "Medium" if ctx.target_sdk < 29 else "Low",
            "M9", "MASVS-STORAGE", "CWE-922", "Data Storage",
            "The app uses public external storage. Files there are readable by other apps with storage "
            "permissions and survive uninstall - never store tokens, PII or downloaded code there.",
            "Use Context.getFilesDir() / getCacheDir() for private data, or EncryptedFile for sensitive files.",
            evidence=["Environment.getExternalStorageDirectory() / getExternalStoragePublicDirectory()"],
            confidence="Medium"), ext)

    tmp = app_sites(ctx, c["temp_file"])
    if tmp:
        ctx.add_code_finding(Finding(
            "STO-005", "Temporary files created", "Info", "M9", "MASVS-STORAGE", "CWE-377", "Data Storage",
            "File.createTempFile() is used; make sure sensitive temp files are created in the app's cache dir "
            "and deleted promptly.", "Pass getCacheDir() as directory and delete files after use.",
            evidence=["File.createTempFile(…)"], confidence="Low"), tmp)

    # Plaintext SharedPreferences storing obvious secrets
    names = [(s, _str(s.args[0])) for s in c["prefs"] if s.args and _str(s.args[0])]
    sens = [(s, n) for s, n in names if re.search(r"(pass|pwd|token|secret|cred|auth|session|pin|key)", n, re.I)
            and not ctx.is_library(s.caller_class)]
    if sens and "encrypted_prefs" not in ctx.controls:
        ctx.add_code_finding(Finding(
            "STO-006", "Sensitive data likely stored in plaintext SharedPreferences", "Medium", "M9",
            "MASVS-STORAGE", "CWE-312", "Data Storage",
            "SharedPreferences files with security-related names are created without EncryptedSharedPreferences. "
            "They are stored as plain XML in the app sandbox and leak through backups, root or debuggable builds.",
            "Use androidx.security.crypto.EncryptedSharedPreferences (or DataStore + Tink) for secrets.",
            evidence=[f"getSharedPreferences(\"{n}\", MODE_PRIVATE)" for _, n in sens[:6]],
            confidence="Medium"), [s for s, _ in sens])


# --------------------------------------------------------------------------- #
SQL_CONCAT = re.compile(r"\b(select|update|delete|insert)\b.*(=|like)\s*['\"]?$", re.I)


def _sql(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    dyn = [s for s in c["raw_query"] + c["exec_sql"] if s.args and s.args[0] is None
           and not ctx.is_library(s.caller_class)]
    fragments = sorted({s for _, s in ctx.dex.iter_strings() if len(s) < 300 and SQL_CONCAT.search(s.strip())})
    if dyn:
        conf = "Medium" if fragments else "Low"
        ctx.add_code_finding(Finding(
            "SQL-001", "Possible SQL injection (dynamic raw query)", "Medium" if fragments else "Low", "M4",
            "MASVS-CODE", "CWE-89", "Injection",
            "rawQuery()/execSQL() receive a query that is not a compile-time constant" +
            (", and the string pool contains SQL fragments ending in an operator, a typical sign of string "
             "concatenation with user input." if fragments else ".") +
            " If any part comes from intents, deep links or a ContentProvider selection, attackers can read or "
            "modify the database.",
            "Use bound parameters:\n\ndb.rawQuery(\"SELECT * FROM users WHERE name = ?\", new String[]{name});",
            evidence=[f"SQL fragment: \"{f[:120]}\"" for f in fragments[:6]] or ["non-constant query argument"],
            confidence=conf), dyn)


# --------------------------------------------------------------------------- #
def _ipc(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    comps = ctx.extra.get("components") or []
    exported = {"L" + x["name"].replace(".", "/") + ";" for x in comps if x["exported"] and x["enabled"]}
    by_class: Dict[str, set] = {}
    for key in ("get_parcelable_extra", "parse_uri", "start_activity", "start_activity_fr", "start_service",
                "send_broadcast", "set_result", "get_data", "get_string_extra", "get_query_param", "wv_load"):
        for s in c[key]:
            base = s.caller_class.split("$")[0] + (";" if "$" in s.caller_class else "")
            by_class.setdefault(base, set()).add(key)
    redirect, webview_inject = [], []
    for cls in exported:
        keys = by_class.get(cls, set())
        if ("get_parcelable_extra" in keys or "parse_uri" in keys) and keys & {"start_activity", "start_activity_fr",
                                                                               "start_service", "send_broadcast", "set_result"}:
            redirect.append(java(cls))
        if "wv_load" in keys and keys & {"get_data", "get_string_extra", "get_query_param"}:
            webview_inject.append(java(cls))
    if redirect:
        ctx.add(Finding(
            "IPC-001", "Possible intent redirection from exported component", "High", "M4", "MASVS-PLATFORM",
            "CWE-940", "Intent Security",
            "Exported components read a nested Intent from extras (getParcelableExtra / Intent.parseUri) and "
            "launch it. A malicious app can make them start private, non-exported components or grant URI "
            "permissions to private files.",
            "Never launch intents received from extras. If needed, validate the target with "
            "intent.resolveActivity() against an allow-list and strip FLAG_GRANT_* flags.",
            evidence=[f"{r}: getParcelableExtra/parseUri → start*/setResult" for r in redirect[:8]],
            locations=redirect, confidence="Medium",
            references=["https://developer.android.com/privacy-and-security/risks/intent-redirection"]))
    if webview_inject:
        ctx.add(Finding(
            "IPC-002", "Untrusted Intent / deep-link data loaded into WebView", "High", "M4", "MASVS-PLATFORM",
            "CWE-939", "WebView",
            "Exported (or deep-link) activities read URLs from the incoming Intent and pass data to "
            "WebView.loadUrl(). Attackers can open arbitrary pages inside the app (phishing, XSS against the "
            "JavaScript bridge, file:// theft).",
            "Parse the URI and accept only https URLs whose host is on a strict allow-list before loading.",
            evidence=[f"{w}: Intent.getData/getStringExtra/getQueryParameter → WebView.loadUrl" for w in webview_inject[:8]],
            locations=webview_inject, confidence="Medium"))

    mutable = []
    for key in ("pending_activity", "pending_broadcast", "pending_service"):
        for s in c[key]:
            flags = s.args[3] if len(s.args) > 3 else None
            if isinstance(flags, int) and not flags & 0x04000000 and (ctx.target_sdk < 31 or flags & 0x02000000):
                mutable.append(s)
    if mutable:
        ctx.add_code_finding(Finding(
            "IPC-003", "Mutable PendingIntent", "Medium", "M8", "MASVS-PLATFORM", "CWE-927", "Intent Security",
            "PendingIntents are created without FLAG_IMMUTABLE. Apps that receive them (notifications, widgets, "
            "other apps) can fill in the base Intent and execute actions with this app's identity/permissions.",
            "Use PendingIntent.FLAG_IMMUTABLE and an explicit target component.",
            evidence=["PendingIntent.get*(…, flags without FLAG_IMMUTABLE)"], confidence="Medium"), mutable)

    sticky = app_sites(ctx, c["sticky_broadcast"])
    if sticky:
        ctx.add_code_finding(Finding(
            "IPC-004", "Sticky broadcasts", "Low", "M8", "MASVS-PLATFORM", "CWE-925", "Intent Security",
            "Sticky broadcasts are readable and replaceable by any app (deprecated since API 21).",
            "Use explicit broadcasts or LiveData/Flow for in-process events.",
            evidence=["sendStickyBroadcast(…)"]), sticky)


# --------------------------------------------------------------------------- #
SENSITIVE_LOG = re.compile(r"\b(password|passwd|pwd|passcode|token|access[_ ]?token|secret|otp|pin|cvv|card[_ ]?number|"
                           r"session[_ ]?id|api[_ ]?key|auth(orization)?|credentials?)\b\s*[:=]", re.I)


def _logging_leaks(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    logs = app_sites(ctx, c["log_d"] + c["log_v"] + c["log_i"])
    sens = [s for s in logs if len(s.args) > 1 and SENSITIVE_LOG.search(_str(s.args[1]) or "")]
    if sens:
        ctx.add_code_finding(Finding(
            "LOG-001", "Sensitive values written to logcat", "Medium", "M6", "MASVS-STORAGE", "CWE-532",
            "Data Leakage", "Log messages reference credentials/tokens. Logcat is readable over ADB, by OEM log "
            "collectors and by crash-reporting SDKs.",
            "Strip Log.d/v/i in release with R8 (-assumenosideeffects class android.util.Log { *; }) and never "
            "log secrets.", evidence=[f"Log(\"{_str(s.args[0]) or '?'}\", \"{(_str(s.args[1]) or '')[:60]}…\")"
                                      for s in sens[:6]]), sens)
    elif len(logs) >= 25:
        ctx.add_code_finding(Finding(
            "LOG-002", "Verbose debug logging in release build", "Info", "M6", "MASVS-STORAGE", "CWE-532",
            "Data Leakage", f"{len(logs)}+ debug/verbose log calls in app code survive in this build.",
            "Remove debug logs in release with R8 rules or a logging wrapper.",
            evidence=[f"{len(logs)}+ Log.d/v/i call sites in app code"], confidence="Medium"), logs)

    clip = app_sites(ctx, c["clipboard"])
    if clip:
        ctx.add_code_finding(Finding(
            "PRIV-001", "Data copied to the clipboard", "Low", "M6", "MASVS-PLATFORM", "CWE-200", "Data Leakage",
            "The clipboard is shared across apps (and with keyboards). Copying passwords, OTPs or tokens leaks "
            "them.", "Avoid copying sensitive values; on API 33+ mark ClipData as sensitive "
            "(ClipDescription.EXTRA_IS_SENSITIVE).", evidence=["ClipboardManager.setPrimaryClip(…)"],
            confidence="Low"), clip)

    secure = [s for s in c["win_add_flags"] + c["win_set_flags"] if s.args and isinstance(s.args[0], int) and s.args[0] & 0x2000]
    if secure:
        ctx.control("flag_secure", "Window FLAG_SECURE")
    sensitive = ctx.extra.get("sensitive_screens") or []
    if sensitive and not c["filter_touches"]:
        ctx.add(Finding(
            "UI-001", "Tapjacking on sensitive screens", "Low", "M8", "MASVS-PLATFORM", "CWE-1021", "UI Security",
            f"targetSdkVersion {ctx.target_sdk} < 31 and these sensitive-looking screens do not filter touches "
            "when obscured, so an overlay can trick users into tapping.",
            "Set android:filterTouchesWhenObscured=\"true\" on sensitive views/activities and target API 31+.",
            evidence=sensitive[:10], locations=sensitive, confidence="Low"))
    if sensitive and not secure and ctx.target_sdk < 31:
        ctx.add(Finding(
            "UI-002", "Sensitive screens can be captured (no FLAG_SECURE)", "Low", "M6", "MASVS-PLATFORM",
            "CWE-200", "Data Leakage",
            "No use of WindowManager.LayoutParams.FLAG_SECURE was found. Login/payment screens appear in the "
            "recents thumbnail, screenshots and screen recordings (and to screen-capturing malware).",
            "getWindow().setFlags(WindowManager.LayoutParams.FLAG_SECURE, WindowManager.LayoutParams.FLAG_SECURE);",
            evidence=sensitive[:10], confidence="Low"))


# --------------------------------------------------------------------------- #
def _dynamic_code(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    loaders = c["dexloader"] + c["memdexloader"] + c["load_dex"]
    if loaders:
        ctx.add_code_finding(Finding(
            "DYN-001", "Dynamic code loading", "Medium", "M2", "MASVS-CODE", "CWE-829", "Supply Chain",
            "Code is loaded at runtime with DexClassLoader / InMemoryDexClassLoader. If the payload comes from "
            "the network or writable storage it can be replaced by an attacker; malware uses this to fetch "
            "malicious modules after passing store review.",
            "Avoid runtime code loading; if unavoidable, load only from the app's private, read-only files and "
            "verify a signature over the payload.",
            evidence=["DexClassLoader / InMemoryDexClassLoader / DexFile.loadDex"]), loaders)
        appl = app_sites(ctx, loaders)
        if appl:
            ctx.capability("dynamic_code", "Loads code at runtime", appl[0].location, 8)
            if c["memdexloader"] and app_sites(ctx, c["memdexloader"]):
                ctx.signal("inmemory_dex", "Loads DEX directly from memory (fileless payload)", 10,
                           app_sites(ctx, c["memdexloader"])[0].location)

    su = [s for s in c["exec"] + c["process_builder"] if any((_str(a) or "").strip() in ("su", "/system/bin/su",
                                                                                          "/system/xbin/su")
                                                             for a in s.args)]
    if su and app_sites(ctx, su):
        ctx.capability("root", "Executes commands as root (su)", app_sites(ctx, su)[0].location, 8)
    cmds = app_sites(ctx, c["exec"])
    if cmds:
        ctx.add_code_finding(Finding(
            "DYN-002", "Shell command execution", "Info", "M4", "MASVS-CODE", "CWE-78", "Code",
            "Runtime.exec() is used. Make sure no part of the command line is attacker-controlled.",
            "Avoid shelling out; if required pass an argument array and never concatenate input.",
            evidence=[f"Runtime.exec(\"{_str(s.args[0])}\")" if s.args and _str(s.args[0]) else "Runtime.exec(<dynamic>)"
                      for s in cmds[:6]], confidence="Medium"), cmds)


def _capabilities(ctx: ScanContext, c: Dict[str, List[CallSite]]) -> None:
    def cap(keys, cid, label, weight):
        sites = []
        for k in keys:
            sites += app_sites(ctx, c[k])
        if sites:
            ctx.capability(cid, label, sites[0].location, weight)
        return sites

    ids = cap(["device_id", "imei", "subscriber_id", "sim_serial", "line1", "mac"], "device_ids",
              "Reads hardware/SIM identifiers (IMEI, IMSI, phone number)", 4)
    if ids:
        ctx.add_code_finding(Finding(
            "PRIV-002", "Collects persistent device identifiers", "Medium", "M6", "MASVS-PRIVACY", "CWE-359",
            "Privacy", "The app reads non-resettable identifiers (IMEI/IMSI/SIM serial/phone number/MAC). These "
            "allow tracking users across apps and resets and are restricted by Google Play policy.",
            "Use app-scoped identifiers (UUID stored in app storage) or the resettable advertising ID with "
            "consent.", evidence=sorted({s.api.replace('_', ' ') for s in ids})), ids)

    sms = cap(["send_sms", "send_sms_multi", "send_data_sms"], "sms_send", "Sends SMS messages", 12)
    if sms:
        ctx.signal("sms_send_code", "Sends SMS from code", 8, sms[0].location)
        for s in sms:
            if s.args and _str(s.args[0]):
                ctx.signal("sms_hardcoded_number", "Sends SMS to a hardcoded number (premium-rate fraud)", 18,
                           f"{_str(s.args[0])} @ {s.location}")
    if cap(["abort_broadcast"], "abort_broadcast", "Suppresses broadcasts (hides incoming SMS)", 0) and \
            "sms_intercept" in ctx.capabilities:
        ctx.signal("sms_abort", "Intercepts and hides incoming SMS", 15)
    cap(["location_last", "location_updates", "fused_location"], "location", "Tracks device location", 3)
    cap(["audio_record", "media_record"], "microphone", "Records audio", 5)
    cap(["camera_open", "camera2_open"], "camera", "Uses the camera", 2)
    if cap(["installed_pkgs", "installed_apps"], "app_inventory", "Enumerates installed apps", 3):
        pass
    if cap(["media_projection"], "screen_capture", "Captures the screen", 6):
        pass
    if cap(["pkg_installer"], "installer", "Installs packages", 6):
        pass
    if cap(["dpm_lock", "dpm_wipe", "dpm_reset_pw"], "device_admin_actions", "Locks / wipes the device", 10):
        ctx.signal("ransom_like", "Device-admin lock/wipe/reset-password calls (ransomware pattern)", 15)
    a11y = cap(["a11y_global", "a11y_gesture", "a11y_node_action", "a11y_root"], "a11y_actions",
               "Automates UI through accessibility (clicks, reads other apps)", 6)
    if a11y and "accessibility" in ctx.capabilities:
        ctx.signal("a11y_automation", "Accessibility service that reads and clicks other apps (banking-trojan pattern)",
                   14, a11y[0].location)
    hide = [s for s in app_sites(ctx, c["component_state"]) if len(s.args) > 1 and s.args[1] == 2]
    if hide:
        ctx.signal("hide_icon", "Disables its own components at runtime (icon hiding)", 10, hide[0].location)
    if cap(["keyguard_disable"], "keyguard", "Disables the lock screen", 6):
        pass
    overlay = app_sites(ctx, c["overlay_add"])
    if overlay and "android.permission.SYSTEM_ALERT_WINDOW" in (ctx.extra.get("permissions") or []):
        ctx.capability("overlay", "Draws windows over other apps", overlay[0].location, 6)


def _controls(ctx: ScanContext) -> None:
    dex = ctx.dex
    for key, (label, apis) in SECURITY_CONTROL_APIS.items():
        for cls, name in apis:
            if dex.references_method(cls, name):
                ctx.control(key, f"{label}: {java(cls) if cls != '*' else ''}{'.' if cls != '*' else ''}{name}()")
                break
    strings = None
    if "root_detection" not in ctx.controls:
        strings = strings or {s for _, s in dex.iter_strings()}
        if {"/system/xbin/su", "/system/app/Superuser.apk"} & strings or "com.topjohnwu.magisk" in strings:
            ctx.control("root_detection", "Root artefact path checks (su / Superuser.apk / Magisk)")
    if "emulator" not in ctx.controls:
        strings = strings or {s for _, s in dex.iter_strings()}
        if {"goldfish", "ranchu", "generic_x86"} & strings:
            ctx.control("emulator_detection", "Emulator fingerprint checks (goldfish/ranchu)")

    if not ctx.controls.get("root_detection") and not ctx.controls.get("play_integrity"):
        ctx.add(Finding(
            "RES-001", "No root / integrity detection", "Info", "M7", "MASVS-RESILIENCE", "CWE-919",
            "Resilience",
            "No root detection, Play Integrity or SafetyNet attestation was found. For apps handling money or "
            "sensitive data, a compromised device can bypass all client-side protections.",
            "Use the Play Integrity API (server-verified) and treat client-side root checks as defence in depth.",
            confidence="Medium"))


def _obfuscation(ctx: ScanContext) -> None:
    app_classes = [c for c in ctx.dex.class_names if not ctx.is_library(c)]
    if len(app_classes) < 15:
        ctx.extra["obfuscation"] = {"app_classes": len(app_classes), "ratio": None}
        return
    short = 0
    for c in app_classes:
        simple = c[1:-1].rsplit("/", 1)[-1].split("$")[0]
        if len(simple) <= 2:
            short += 1
    ratio = short / len(app_classes)
    ctx.extra["obfuscation"] = {"app_classes": len(app_classes), "ratio": round(ratio, 3)}
    if ratio < 0.25:
        ctx.add(Finding(
            "RES-002", "Code is not obfuscated", "Low", "M7", "MASVS-RESILIENCE", "CWE-656", "Resilience",
            f"Only {ratio * 100:.0f}% of {len(app_classes)} app classes have short (minified) names, so the "
            "decompiled code reads like the original source, easing reverse engineering, repackaging and "
            "secret extraction.",
            "Enable R8 full mode in release:\n\nbuildTypes {\n    release {\n        minifyEnabled true\n"
            "        shrinkResources true\n        proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), "
            "'proguard-rules.pro'\n    }\n}",
            evidence=[f"obfuscated ratio: {ratio * 100:.1f}% of {len(app_classes)} classes"], confidence="Medium"))
