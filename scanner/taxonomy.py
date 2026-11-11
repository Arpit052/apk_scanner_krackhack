"""
Standards the findings are mapped to.

* OWASP Mobile Top 10 - 2024 final release
  https://owasp.org/www-project-mobile-top-10/
* OWASP MASVS v2 control groups
  https://mas.owasp.org/MASVS/
"""

OWASP_MOBILE_2024 = {
    "M1": {
        "title": "Improper Credential Usage",
        "summary": "Hardcoded credentials, API keys or tokens shipped in the app, or credentials "
                   "transmitted/stored insecurely.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m1-improper-credential-usage.html",
    },
    "M2": {
        "title": "Inadequate Supply Chain Security",
        "summary": "Untrusted third-party SDKs, dynamically loaded code and compromised build or "
                   "signing pipelines.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m2-inadequate-supply-chain-security.html",
    },
    "M3": {
        "title": "Insecure Authentication/Authorization",
        "summary": "Components and endpoints reachable without proper authentication or "
                   "authorization checks (exported components, weak custom permissions).",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m3-insecure-authentication-authorization.html",
    },
    "M4": {
        "title": "Insufficient Input/Output Validation",
        "summary": "Untrusted data reaching WebViews, SQL queries, intents or file paths without "
                   "validation (XSS, SQLi, intent redirection, path traversal).",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m4-insufficient-input-output-validation.html",
    },
    "M5": {
        "title": "Insecure Communication",
        "summary": "Cleartext traffic, disabled certificate validation, trust of user CAs and "
                   "missing pinning.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m5-insecure-communication.html",
    },
    "M6": {
        "title": "Inadequate Privacy Controls",
        "summary": "Excessive collection of personal data, trackers, device identifiers and "
                   "leaks through logs, clipboard or screenshots.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m6-inadequate-privacy-controls.html",
    },
    "M7": {
        "title": "Insufficient Binary Protections",
        "summary": "Missing obfuscation, debuggable builds and absence of tamper/root/debugger "
                   "detection that make reverse engineering easy.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m7-insufficient-binary-protection.html",
    },
    "M8": {
        "title": "Security Misconfiguration",
        "summary": "Insecure manifest defaults: backups, debug flags, task hijacking, permissive "
                   "file providers and similar configuration issues.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m8-security-misconfiguration.html",
    },
    "M9": {
        "title": "Insecure Data Storage",
        "summary": "Sensitive data in world-readable files, external storage, unencrypted "
                   "SharedPreferences/databases or backups.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m9-insecure-data-storage.html",
    },
    "M10": {
        "title": "Insufficient Cryptography",
        "summary": "Broken algorithms (DES, RC4, MD5, SHA-1), ECB mode, hardcoded keys/IVs and "
                   "weak randomness.",
        "url": "https://owasp.org/www-project-mobile-top-10/2023-risks/m10-insufficient-cryptography.html",
    },
}

MASVS = {
    "MASVS-STORAGE": "Secure storage of sensitive data",
    "MASVS-CRYPTO": "Correct use of cryptography",
    "MASVS-AUTH": "Authentication and authorization",
    "MASVS-NETWORK": "Secure network communication",
    "MASVS-PLATFORM": "Secure interaction with the platform and other apps",
    "MASVS-CODE": "Code quality, input validation and dependency hygiene",
    "MASVS-RESILIENCE": "Resilience against reverse engineering and tampering",
    "MASVS-PRIVACY": "Privacy of user data",
}

SEVERITY_ORDER = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEVERITY_WEIGHT = {"Critical": 26.0, "High": 11.0, "Medium": 4.0, "Low": 1.0, "Info": 0.0}
CONFIDENCE_FACTOR = {"High": 1.0, "Medium": 0.7, "Low": 0.4}
SEVERITY_RISK = {"Critical": 9.5, "High": 7.8, "Medium": 5.5, "Low": 3.0, "Info": 1.0}
