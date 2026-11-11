"""SDK/tracker/framework fingerprinting, packers, payloads and the malware risk model."""

from __future__ import annotations



from .context import Finding, ScanContext
from .knowledge import (FAKE_SYSTEM_NAMES, FRAMEWORKS, HOOKING_FRAMEWORKS, PACKER_CLASSES, PACKERS,
                        PERMISSIONS, TRACKERS)

KNOWN_BAD_PACKAGES = {
    "com.android.battery", "com.system.update", "com.android.settings.backup", "com.google.provider",
    "com.android.provider.security", "android.security.update", "com.android.systemui.fake",
    "com.fake.google", "org.malware", "com.trojan",
}

MINER_STRINGS = ("stratum+tcp://", "stratum+ssl://", "xmrig", "cryptonight", "coinhive.min.js", "minergate")


def run(ctx: ScanContext) -> None:
    _permissions(ctx)
    _trackers(ctx)
    _frameworks(ctx)
    _native(ctx)
    _packers_and_payloads(ctx)
    _impersonation(ctx)
    _misc_strings(ctx)


def _permissions(ctx: ScanContext) -> None:
    perms = ctx.extra.get("permissions") or sorted(set(ctx.apk.get_permissions() or []))
    table = []
    for p in perms:
        lvl, desc, risk = PERMISSIONS.get(p, ("custom" if not p.startswith("android.") else "normal",
                                             "Custom / third-party permission" if not p.startswith("android.")
                                             else "", 0))
        table.append({"name": p, "short": p.rsplit(".", 1)[-1], "level": lvl, "description": desc, "risk": risk})
    table.sort(key=lambda x: (-x["risk"], x["name"]))
    ctx.extra["permission_table"] = table

    high = [t for t in table if t["risk"] >= 7]
    if high:
        ctx.add(Finding(
            "PERM-001", "High-risk permissions requested", "Medium" if len(high) >= 3 else "Low", "M6",
            "MASVS-PRIVACY", "CWE-250", "Permissions",
            f"The app requests {len(high)} permission(s) that grant access to highly sensitive data or device "
            "control. Each one should be strictly necessary for core functionality and requested at runtime "
            "with a clear rationale.",
            "Remove permissions that are not essential, prefer privacy-preserving alternatives (photo picker, "
            "SMS Retriever API, coarse location) and request the rest just-in-time.",
            evidence=[f"{t['short']} - {t['description']}" for t in high], confidence="High"))
    ps = {t["name"] for t in table}
    if "android.permission.MANAGE_EXTERNAL_STORAGE" in ps:
        ctx.add(Finding(
            "PERM-002", "All-files access requested", "Medium", "M6", "MASVS-PRIVACY", "CWE-250", "Permissions",
            "MANAGE_EXTERNAL_STORAGE gives read/write access to every file on shared storage, including other "
            "apps' exported documents and media.", "Use scoped storage APIs or the Storage Access Framework.",
            evidence=["android.permission.MANAGE_EXTERNAL_STORAGE"]))
    if "android.permission.QUERY_ALL_PACKAGES" in ps:
        ctx.add(Finding(
            "PERM-003", "Queries all installed packages", "Low", "M6", "MASVS-PRIVACY", "CWE-359", "Privacy",
            "QUERY_ALL_PACKAGES reveals every installed app (banking, dating, health apps), which is sensitive "
            "personal data and restricted by Play policy.",
            "Declare specific <queries> entries instead.", evidence=["android.permission.QUERY_ALL_PACKAGES"]))

    # capability combinations from permissions alone
    if {"android.permission.READ_SMS", "android.permission.RECEIVE_SMS"} & ps and "android.permission.INTERNET" in ps:
        ctx.signal("sms_internet", "Reads SMS and has Internet access (OTP exfiltration combo)", 8)
    if "android.permission.SEND_SMS" in ps:
        ctx.capability("sms_send_perm", "Permission to send SMS", "SEND_SMS", 4)
    if "android.permission.REQUEST_INSTALL_PACKAGES" in ps:
        ctx.capability("install_perm", "Can prompt to install other APKs", "REQUEST_INSTALL_PACKAGES", 4)
    if "android.permission.SYSTEM_ALERT_WINDOW" in ps:
        ctx.capability("overlay_perm", "Can draw over other apps", "SYSTEM_ALERT_WINDOW", 3)
    if {"android.permission.READ_CALL_LOG", "android.permission.READ_CONTACTS"} <= ps:
        ctx.capability("contacts_calls", "Reads contacts and call history", "READ_CONTACTS + READ_CALL_LOG", 4)
    spy = {"android.permission.RECORD_AUDIO", "android.permission.ACCESS_FINE_LOCATION",
           "android.permission.READ_SMS", "android.permission.READ_CALL_LOG", "android.permission.CAMERA",
           "android.permission.READ_CONTACTS"} & ps
    if len(spy) >= 5:
        ctx.signal("spyware_perms", "Spyware-like permission set (mic, location, SMS, calls, camera, contacts)", 10,
                   ", ".join(sorted(p.rsplit('.', 1)[-1] for p in spy)))


def _trackers(ctx: ScanContext) -> None:
    classes = ctx.dex.class_names
    found = []
    for name, cat, prefixes in TRACKERS:
        if any(c.startswith(prefixes) for c in classes):
            found.append({"name": name, "category": cat})
    ctx.extra["trackers"] = found
    if found:
        ads = [t for t in found if t["category"] in ("Advertisement", "Profiling")]
        ctx.add(Finding(
            "PRIV-003", f"{len(found)} third-party tracker SDK(s) embedded",
            "Low" if ads else "Info", "M6", "MASVS-PRIVACY", "CWE-359", "Privacy",
            "Tracker and analytics SDKs collect device and behavioural data and send it to third parties. They "
            "must be disclosed in the privacy policy / Data safety form and gated behind user consent where "
            "required (GDPR, DPDP Act).",
            "Remove unused SDKs, disable automatic data collection until consent, and document data flows.",
            evidence=[f"{t['name']} ({t['category']})" for t in found], confidence="High"))


def _frameworks(ctx: ScanContext) -> None:
    out = []
    names = ctx.names
    joined = "\n".join(names)
    for fw, hints in FRAMEWORKS:
        if any(h in joined for h in hints):
            out.append(fw)
    if any(c.startswith("Lkotlin/") for c in list(ctx.dex.class_names)[:200000]) and "Kotlin" not in out:
        out.append("Kotlin")
    if not out:
        out.append("Java / Android SDK")
    ctx.extra["frameworks"] = out


def _native(ctx: ScanContext) -> None:
    libs = [n for n in ctx.names if n.startswith("lib/") and n.endswith(".so")]
    abis = sorted({n.split("/")[1] for n in libs if n.count("/") >= 2})
    uniq = sorted({n.rsplit("/", 1)[-1] for n in libs})
    ctx.extra["native"] = {"abis": abis, "libraries": uniq[:200], "count": len(uniq)}
    hooks = []
    for lib in uniq:
        low = lib.lower()
        for frag, label in HOOKING_FRAMEWORKS.items():
            if label and frag in low:
                hooks.append(f"{lib} ({label})")
    if any(c.startswith("Lde/robv/android/xposed/") for c in ctx.dex.referenced_types):
        hooks.append("de.robv.android.xposed API (Xposed module)")
    if hooks:
        ctx.add(Finding(
            "RES-003", "Instrumentation / hooking framework embedded", "High", "M7", "MASVS-RESILIENCE",
            "CWE-912", "Tampering",
            "The APK bundles a dynamic instrumentation framework. In a production app this usually means the "
            "APK was repackaged (e.g. frida-gadget injected) or is a hooking tool / Xposed module able to alter "
            "other apps.",
            "Obtain the app from the official store and verify its signing certificate. Developers: never ship "
            "instrumentation libraries in release builds.",
            evidence=hooks[:8]))
        ctx.signal("hooking", "Bundles hooking/instrumentation framework (repackaged or tooling)", 10, hooks[0])


def _packers_and_payloads(ctx: ScanContext) -> None:
    packers = set()
    for n in ctx.names:
        if n.startswith("lib/") or n.startswith("assets/"):
            low = n.rsplit("/", 1)[-1].lower()
            for frag, label in PACKERS.items():
                if low.startswith(frag) or frag in low:
                    packers.add(label)
    for cls, label in PACKER_CLASSES.items():
        if cls in ctx.dex.class_names:
            packers.add(label)
    app_cls = ctx.app_attr("name")
    missing = []
    if app_cls and ctx.dex.dexes:
        q = ctx.qualify(app_cls)
        if not ctx.dex.has_class(q):
            missing.append(q)
    comps = ctx.extra.get("components") or []
    own = [c["name"] for c in comps if c["name"].startswith(ctx.package) and c["type"] in ("activity", "service")]
    missing_comps = [c for c in own if not ctx.dex.has_class(c)] if ctx.dex.dexes else []
    ctx.extra["packers"] = sorted(packers)
    benign_packer = packers == {"Google Play Integrity (pairip) protection"}
    if packers or (missing and len(missing_comps) >= 2):
        ev = [f"packer: {p}" for p in sorted(packers)]
        if missing:
            ev.append(f"Application class {missing[0]} is not present in any DEX")
        if missing_comps:
            ev.append(f"{len(missing_comps)} declared components have no code in the APK (e.g. {missing_comps[0]})")
        ctx.add(Finding(
            "RES-004", "Packed / encrypted code detected", "Info" if benign_packer else "Medium", "M7",
            "MASVS-RESILIENCE", "CWE-506", "Tampering",
            "The real application code is hidden and unpacked at runtime. Commercial packers are used by "
            "legitimate apps to deter reverse engineering, but they are also the #1 tool malware uses to evade "
            "static scanners - this scan only sees the loader stub.",
            "Analyse the app dynamically (sandbox) or unpack it before trusting a clean static result.",
            evidence=ev, confidence="High" if packers else "Medium"))
        if not benign_packer:
            ctx.signal("packed", "Code is packed/encrypted (hides real behaviour)", 12, ev[0])

    payloads = []
    for n in ctx.names:
        if not (n.startswith("assets/") or n.startswith("res/raw/")) or n.endswith("/"):
            continue
        try:
            with ctx.zip.open(n) as fh:
                head = fh.read(8)
        except Exception:
            continue
        if head.startswith(b"dex\n"):
            payloads.append((n, "DEX bytecode"))
        elif head.startswith(b"PK\x03\x04") and n.lower().endswith((".apk", ".jar", ".dex", ".zip", ".bin", ".dat", ".so", "")):
            try:
                import io
                import zipfile
                inner = zipfile.ZipFile(io.BytesIO(ctx.zip.read(n)))
                inner_names = inner.namelist()
                if "classes.dex" in inner_names or "AndroidManifest.xml" in inner_names:
                    payloads.append((n, "embedded APK/JAR with code"))
            except Exception:
                pass
        elif head.startswith(b"\x7fELF") and not n.endswith(".so"):
            payloads.append((n, "ELF executable"))
    ctx.extra["payloads"] = [{"path": p, "kind": k} for p, k in payloads]
    if payloads:
        ctx.add(Finding(
            "DYN-003", "Executable payloads hidden in assets", "Medium", "M2", "MASVS-CODE", "CWE-506",
            "Supply Chain",
            "Assets contain DEX/APK/ELF files that are not part of the normal code path. They can be loaded or "
            "installed at runtime (dropper behaviour) and are invisible to store review.",
            "Review what loads these files; legitimate apps rarely need executable assets.",
            evidence=[f"{p} - {k}" for p, k in payloads[:10]]))
        ctx.signal("payload", "Hidden executable payload in assets (dropper)", 12, payloads[0][0])
        if "install_perm" in ctx.capabilities and any("APK" in k for _, k in payloads):
            ctx.signal("dropper", "Embedded APK + install permission (dropper)", 12)


def _impersonation(ctx: ScanContext) -> None:
    pkg = ctx.package
    try:
        label = (ctx.apk.get_app_name() or "").strip()
    except Exception:
        label = ""
    ctx.extra["app_label"] = label
    if pkg in KNOWN_BAD_PACKAGES:
        ctx.signal("known_bad_pkg", "Package name on known-malware list", 40, pkg)
    if pkg.startswith(("com.android.", "android.", "com.google.android.")) and \
            not (ctx.extra.get("signing") or {}).get("certificates", [{}])[0].get("subject", "").count("Google"):
        ctx.signal("system_pkg_name", "Uses a system/Google package namespace without a Google certificate", 12, pkg)
        ctx.add(Finding(
            "MAL-001", "Package name impersonates a system app", "High", "M2", "MASVS-RESILIENCE", "CWE-290",
            "Malware", f"The package '{pkg}' sits in a namespace reserved for Android/Google apps but is not "
            "signed by Google. Malware commonly uses such names to look trustworthy.",
            "Do not install apps that impersonate system components; verify the publisher.",
            evidence=[f"package={pkg}", f"label={label}"], confidence="Medium"))
    low = label.lower()
    if any(n == low or n in low for n in FAKE_SYSTEM_NAMES) and not pkg.startswith(("com.android.settings",)):
        ctx.signal("fake_name", "App label mimics a system/update app", 8, label)


def _misc_strings(ctx: ScanContext) -> None:
    strings_lower = None
    hits = []
    for _src, s in ctx.dex.iter_strings():
        if len(s) > 200:
            continue
        sl = s.lower()
        for m in MINER_STRINGS:
            if m in sl:
                hits.append(s)
    if hits:
        ctx.signal("miner", "Cryptocurrency-mining references", 20, hits[0][:80])
        ctx.add(Finding(
            "MAL-002", "Cryptocurrency miner indicators", "High", "M2", "MASVS-CODE", "CWE-506", "Malware",
            "Mining-pool protocols or miner names were found. Hidden mining drains battery and is malware "
            "behaviour under every store policy.", "Remove the miner; investigate how it got into the build.",
            evidence=sorted(set(hits))[:6]))
    del strings_lower


# --------------------------------------------------------------------------- #
# Malware risk model
# --------------------------------------------------------------------------- #
def assess(ctx: ScanContext) -> dict:
    caps = ctx.capabilities
    signals = list(ctx.malware_signals)

    def has(*keys):
        return all(k in caps for k in keys)

    # combination bonuses - capabilities that are dangerous *together*
    combos = [
        (("sms_intercept", "sms_send"), "SMS interception + sending (SMS trojan)", 14),
        (("accessibility", "overlay_perm"), "Accessibility + overlay (banking trojan toolkit)", 14),
        (("accessibility", "notification_listener"), "Accessibility + notification access (2FA theft)", 10),
        (("device_admin", "boot"), "Device admin + boot persistence", 8),
        (("microphone", "location", "boot"), "Mic + location + boot persistence (stalkerware)", 10),
        (("dynamic_code", "install_perm"), "Runtime code + APK installs (loader/dropper)", 8),
        (("sms_intercept", "dynamic_code"), "SMS interception + runtime code loading", 8),
    ]
    for keys, label, w in combos:
        if has(*keys):
            signals.append({"key": "combo_" + "_".join(keys), "label": label, "weight": w,
                            "evidence": [caps[k]["evidence"][0] for k in keys if caps[k]["evidence"]][:3]})
    cap_score = sum(c["weight"] for c in caps.values())
    sig_score = sum(s["weight"] for s in signals)
    score = min(100, int(round(sig_score + cap_score * 0.45)))
    if any(s["key"] == "known_bad_pkg" for s in signals):
        score = max(score, 90)
    if score >= 60:
        verdict, label = "malicious", "Likely malicious"
    elif score >= 35:
        verdict, label = "suspicious", "Suspicious"
    elif score >= 15:
        verdict, label = "low", "Low risk - sensitive capabilities"
    else:
        verdict, label = "clean", "No malware indicators"
    signals.sort(key=lambda s: -s["weight"])
    return {
        "score": score,
        "verdict": verdict,
        "label": label,
        "signals": [s for s in signals if s["weight"] > 0],
        "capabilities": sorted(caps.values(), key=lambda c: -c["weight"]),
        "note": "Heuristic static assessment. A high score means the app is able to behave like malware, "
                "not proof that it does. Confirm with dynamic analysis.",
    }
