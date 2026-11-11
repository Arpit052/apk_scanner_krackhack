"""APK signature scheme + signing certificate analysis."""

from __future__ import annotations

import datetime as _dt
import hashlib

from .context import Finding, ScanContext

# AOSP test/platform/shared/media keys are generated from the same public
# template subject; the private keys ship in build/target/product/security.
AOSP_TEST_KEYS: dict = {}
AOSP_SUBJECT_HINT = "android@android.com"


def run(ctx: ScanContext) -> None:
    apk = ctx.apk
    info = {"v1": False, "v2": False, "v3": False, "v4": False, "certificates": []}
    try:
        info["v1"] = bool(apk.is_signed_v1())
        info["v2"] = bool(apk.is_signed_v2())
        info["v3"] = bool(apk.is_signed_v3())
    except Exception:
        pass
    info["v4"] = any(n.endswith(".idsig") for n in ctx.names)
    ders = []
    for getter in ("get_certificates_der_v3", "get_certificates_der_v2"):
        try:
            ders = list(getattr(apk, getter)() or [])
        except Exception:
            ders = []
        if ders:
            break
    if not ders:
        try:
            ders = [apk.get_certificate_der(n) for n in apk.get_signature_names()]
        except Exception:
            ders = []
    ctx.extra["signing"] = info

    if not (info["v1"] or info["v2"] or info["v3"]):
        ctx.add(Finding(
            "SIG-001", "APK is not signed", "High", "M7", "MASVS-RESILIENCE", "CWE-347", "Integrity",
            "No v1 (JAR), v2 or v3 signature was found. Android refuses to install unsigned APKs, so this file "
            "was either stripped, is a build intermediate, or was tampered with.",
            "Sign release builds with apksigner using v2+v3 schemes.",
            evidence=["no META-INF/*.RSA|DSA|EC and no APK Signing Block"]))
        ctx.signal("unsigned", "Unsigned / stripped APK", 6)
        return

    try:
        from cryptography import x509
        from cryptography.hazmat.primitives.asymmetric import dsa, ec, rsa
    except Exception:  # pragma: no cover
        x509 = None

    now = _dt.datetime.now(_dt.timezone.utc)
    for der in ders[:3]:
        sha256 = hashlib.sha256(der).hexdigest()
        cert = {"sha256": sha256, "sha1": hashlib.sha1(der).hexdigest(), "md5": hashlib.md5(der).hexdigest()}
        if x509 is not None:
            try:
                c = x509.load_der_x509_certificate(der)
                pk = c.public_key()
                if isinstance(pk, rsa.RSAPublicKey):
                    algo, bits = "RSA", pk.key_size
                elif isinstance(pk, ec.EllipticCurvePublicKey):
                    algo, bits = "EC", pk.curve.key_size
                elif isinstance(pk, dsa.DSAPublicKey):
                    algo, bits = "DSA", pk.key_size
                else:
                    algo, bits = type(pk).__name__, None
                cert.update({
                    "subject": c.subject.rfc4514_string(),
                    "issuer": c.issuer.rfc4514_string(),
                    "serial": format(c.serial_number, "x"),
                    "not_before": c.not_valid_before_utc.isoformat(),
                    "not_after": c.not_valid_after_utc.isoformat(),
                    "signature_algorithm": (c.signature_hash_algorithm.name if c.signature_hash_algorithm else "?"),
                    "public_key": f"{algo} {bits or ''}".strip(),
                    "key_bits": bits,
                    "key_algo": algo,
                    "self_signed": c.subject == c.issuer,
                    "expired": c.not_valid_after_utc < now,
                })
            except Exception as e:
                cert["error"] = str(e)
        info["certificates"].append(cert)

    if not info["certificates"]:
        return
    c0 = info["certificates"][0]
    subject = c0.get("subject", "")

    if "CN=Android Debug" in subject:
        ctx.add(Finding(
            "SIG-002", "Signed with the Android debug certificate", "High", "M7", "MASVS-RESILIENCE", "CWE-321",
            "Integrity",
            "The APK is signed with an auto-generated debug keystore (CN=Android Debug). Debug builds are not "
            "meant for distribution: the key is unprotected on developer machines, and debug builds usually "
            "carry debug flags and endpoints.",
            "Sign releases with a dedicated, protected upload key (Play App Signing).",
            evidence=[f"Subject: {subject}", f"SHA-256: {c0['sha256']}"]))
        ctx.signal("debug_cert", "Signed with a debug certificate", 2)
    elif c0["sha256"] in AOSP_TEST_KEYS or AOSP_SUBJECT_HINT in subject:
        ctx.add(Finding(
            "SIG-003", "Signed with a public AOSP test/platform key", "Critical", "M7", "MASVS-RESILIENCE",
            "CWE-321", "Integrity",
            "The signing key's private part is published in the AOSP source tree. Anyone can produce "
            "'updates' that Android will accept as this app (and, on some ROMs, gain system privileges).",
            "Re-sign with a private release key.", evidence=[f"Subject: {subject}", f"SHA-256: {c0['sha256']}"]))
        ctx.signal("aosp_key", "Signed with publicly known AOSP key", 10)

    if c0.get("signature_algorithm") in ("md5", "sha1"):
        ctx.add(Finding(
            "SIG-004", "Weak certificate signature algorithm", "Low", "M10", "MASVS-CRYPTO", "CWE-328",
            "Integrity", f"The signing certificate uses {c0['signature_algorithm'].upper()}withRSA. This mainly "
            "matters for the v1 (JAR) scheme, where digests of SHA-1 are accepted by old devices.",
            "Use a SHA-256 based key/certificate for new apps (key rotation via v3 for existing ones).",
            evidence=[f"signature algorithm: {c0['signature_algorithm']}"]))
    if c0.get("key_algo") == "RSA" and (c0.get("key_bits") or 4096) < 2048:
        ctx.add(Finding(
            "SIG-005", "Short RSA signing key", "Medium", "M10", "MASVS-CRYPTO", "CWE-326", "Integrity",
            f"The signing key is RSA-{c0['key_bits']}, below the 2048-bit minimum.",
            "Rotate to an RSA-4096 or EC P-256 key using APK Signature Scheme v3.",
            evidence=[f"public key: {c0['public_key']}"]))

    if info["v1"] and not info["v2"] and not info["v3"]:
        ctx.add(Finding(
            "SIG-006", "Only v1 (JAR) signature - Janus vulnerability", "High" if ctx.min_sdk < 24 else "Medium",
            "M7", "MASVS-RESILIENCE", "CWE-347", "Integrity",
            "The APK relies on the legacy JAR signature only. On Android 5.0-8.0 a DEX file can be prepended "
            "to the APK without invalidating the v1 signature (Janus, CVE-2017-13156), letting attackers inject "
            "code into 'validly signed' updates. v1 also leaves parts of the ZIP unprotected.",
            "Sign with APK Signature Scheme v2 and v3 (apksigner does this by default).",
            evidence=["v1=yes, v2=no, v3=no", f"minSdkVersion={ctx.min_sdk}"],
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-13156"]))
    elif info["v1"] and ctx.min_sdk < 24:
        ctx.add(Finding(
            "SIG-007", "Janus exposure on Android 5.0-6.0 devices", "Low", "M7", "MASVS-RESILIENCE", "CWE-347",
            "Integrity",
            "Devices below Android 7.0 only verify the v1 signature, which is susceptible to the Janus "
            "attack (CVE-2017-13156) on unpatched 5.x/6.x devices.",
            "Raise minSdkVersion to 24+ so only v2+ verification is used.",
            evidence=[f"v1=yes, v2={'yes' if info['v2'] else 'no'}, minSdkVersion={ctx.min_sdk}"], confidence="Medium",
            references=["https://nvd.nist.gov/vuln/detail/CVE-2017-13156"]))

    if c0.get("expired"):
        ctx.add(Finding(
            "SIG-008", "Signing certificate has expired", "Info", "M7", "MASVS-RESILIENCE", "CWE-298",
            "Integrity", "The signing certificate's validity period has ended. Android still installs the app, "
            "but Google Play rejects new uploads signed with it.",
            "Plan a key rotation (APK Signature Scheme v3).", evidence=[f"notAfter: {c0['not_after']}"]))
