"""AndroidManifest.xml, network security config and FileProvider rules."""

from __future__ import annotations

import datetime as _dt
from typing import Dict, List, Optional

from .context import ANDROID_NS, Finding, ScanContext
from .knowledge import PERMISSIONS, SENSITIVE_SCREEN_KEYWORDS, SYSTEM_GUARD_PERMISSIONS

COMPONENT_TAGS = ("activity", "activity-alias", "service", "receiver", "provider")

PROTECTION_LEVELS = {0: "normal", 1: "dangerous", 2: "signature", 3: "signatureOrSystem"}


# --------------------------------------------------------------------------- #
# Component model
# --------------------------------------------------------------------------- #
def extract_components(ctx: ScanContext) -> List[dict]:
    app = ctx.application
    if app is None:
        return []
    app_perm = ctx.attr(app, "permission")
    out = []
    for el in app:
        tag = el.tag if isinstance(el.tag, str) else ""
        if tag not in COMPONENT_TAGS:
            continue
        name = ctx.qualify(ctx.attr(el, "name", "") or "")
        if tag == "activity-alias":
            target = ctx.qualify(ctx.attr(el, "targetActivity", "") or "")
        else:
            target = None
        filters = []
        for f in el.findall("intent-filter"):
            data = []
            for d in f.findall("data"):
                data.append({k: ctx.attr(d, k) for k in ("scheme", "host", "port", "path", "pathPrefix",
                                                         "pathPattern", "mimeType") if ctx.attr(d, k)})
            filters.append({
                "actions": [ctx.attr(a, "name") for a in f.findall("action") if ctx.attr(a, "name")],
                "categories": [ctx.attr(c, "name") for c in f.findall("category") if ctx.attr(c, "name")],
                "data": data,
                "priority": _int(ctx.attr(f, "priority")),
                "autoVerify": (ctx.attr(f, "autoVerify") or "").lower() == "true",
            })
        explicit = ctx.attr(el, "exported")
        if explicit is not None:
            exported = explicit.lower() == "true"
            exported_reason = f'android:exported="{explicit}"'
        elif tag == "provider":
            exported = ctx.min_sdk <= 16 or ctx.target_sdk <= 16
            exported_reason = "implicit (SDK<=16 default)" if exported else "default false"
        else:
            exported = bool(filters)
            exported_reason = "implicit (has intent-filter)" if exported else "default false"
        perm = ctx.attr(el, "permission")
        comp = {
            "type": tag.replace("activity-alias", "activity"),
            "tag": tag,
            "name": name,
            "target": target,
            "exported": exported,
            "exported_reason": exported_reason,
            "enabled": (ctx.attr(el, "enabled") or "true").lower() != "false",
            "permission": perm or (app_perm if tag != "provider" else None),
            "read_permission": ctx.attr(el, "readPermission"),
            "write_permission": ctx.attr(el, "writePermission"),
            "authorities": ctx.attr(el, "authorities"),
            "grant_uri": (ctx.attr(el, "grantUriPermissions") or "").lower() == "true",
            "launch_mode": ctx.attr(el, "launchMode"),
            "task_affinity": ctx.attr(el, "taskAffinity"),
            "filter_touches": (ctx.attr(el, "filterTouchesWhenObscured") or "").lower() == "true",
            "filters": filters,
            "meta": {ctx.attr(m, "name"): (ctx.attr(m, "resource") or ctx.attr(m, "value"))
                     for m in el.findall("meta-data") if ctx.attr(m, "name")},
        }
        comp["is_launcher"] = any("android.intent.action.MAIN" in f["actions"] and
                                  "android.intent.category.LAUNCHER" in f["categories"] for f in filters)
        out.append(comp)
    return out


def declared_permissions(ctx: ScanContext) -> Dict[str, str]:
    out = {}
    if ctx.manifest is None:
        return out
    for p in ctx.manifest.findall("permission"):
        name = ctx.attr(p, "name")
        if not name:
            continue
        lvl = ctx.attr(p, "protectionLevel") or "normal"
        try:
            base = int(lvl, 0) & 0xF
            lvl = PROTECTION_LEVELS.get(base, "normal")
        except ValueError:
            lvl = lvl.split("|")[0]
        out[name] = lvl
    return out


def protection(ctx: ScanContext, perm: Optional[str], declared: Dict[str, str]) -> str:
    """none | weak | strong | system | unknown"""
    if not perm:
        return "none"
    if perm in SYSTEM_GUARD_PERMISSIONS or perm.startswith("android.permission.BIND_"):
        return "system"
    if perm in declared:
        return "strong" if declared[perm].startswith("signature") else "weak"
    if perm.startswith("android.permission."):
        info = PERMISSIONS.get(perm)
        if info is None:
            return "unknown"
        return "system" if info[0] == "signature" else "weak"
    return "unknown"


# --------------------------------------------------------------------------- #
# Rules
# --------------------------------------------------------------------------- #
def run(ctx: ScanContext) -> None:
    if ctx.manifest is None:
        ctx.add(Finding("MAN-000", "AndroidManifest.xml could not be decoded", "Info", "M8",
                        "MASVS-CODE", "CWE-20", "Configuration",
                        "The binary manifest could not be parsed; manifest checks were skipped.",
                        "Verify the APK is not corrupted or intentionally malformed (anti-analysis)."))
        return
    comps = extract_components(ctx)
    declared = declared_permissions(ctx)
    ctx.extra["components"] = comps
    ctx.extra["declared_permissions"] = declared
    _app_flags(ctx)
    _network_security(ctx)
    _exported(ctx, comps, declared)
    _custom_permissions(ctx, comps, declared)
    _deep_links(ctx, comps)
    _file_providers(ctx, comps)
    _task_hijacking(ctx, comps)
    _platform_versions(ctx)
    _manifest_capabilities(ctx, comps)


def _app_flags(ctx: ScanContext) -> None:
    a = ctx.app_attr
    if (a("debuggable") or "").lower() == "true":
        ctx.add(Finding(
            "MAN-001", "Application is debuggable", "High", "M7", "MASVS-RESILIENCE", "CWE-489",
            "Configuration",
            "android:debuggable=\"true\" lets anyone with USB/ADB access attach a debugger (JDWP), "
            "dump memory, bypass checks at runtime and read the private data directory via "
            "`run-as`. Release builds must never ship with this flag.",
            "Remove android:debuggable from the manifest and let the build type control it:\n\n"
            "android {\n    buildTypes {\n        release { debuggable false }\n    }\n}",
            evidence=['<application android:debuggable="true">'],
            references=["https://mas.owasp.org/MASTG/tests/android/MASVS-RESILIENCE/MASTG-TEST-0039/"]))
        ctx.signal("debuggable", "Shipped as debuggable build", 0)

    backup = a("allowBackup")
    rules = a("fullBackupContent") or a("dataExtractionRules")
    if backup is None or backup.lower() == "true":
        if rules:
            sev, conf = "Info", "Medium"
            desc = ("Backups are enabled with custom backup/data-extraction rules. Review the rules to "
                    "ensure tokens, keys and databases are excluded.")
        else:
            sev = "Medium" if ctx.target_sdk < 31 else "Low"
            conf = "High"
            desc = ("android:allowBackup is " + ("not set (defaults to true)" if backup is None else "true") +
                    ". Application data (SharedPreferences, databases, files) can be extracted with "
                    "`adb backup`" + (" " if ctx.target_sdk < 31 else " on devices below Android 12 ") +
                    "and is included in cloud/device-to-device transfers, exposing session tokens and PII.")
        ctx.add(Finding(
            "MAN-002", "Application data backup enabled", sev, "M9", "MASVS-STORAGE", "CWE-530",
            "Data Protection", desc,
            "Disable backups or exclude sensitive files explicitly:\n\n"
            "<application android:allowBackup=\"false\"\n"
            "             android:dataExtractionRules=\"@xml/data_extraction_rules\"\n"
            "             android:fullBackupContent=\"@xml/backup_rules\">",
            evidence=[f'allowBackup={backup or "unset"}', f"rules={'present' if rules else 'none'}"],
            confidence=conf))

    if (a("testOnly") or "").lower() == "true":
        ctx.add(Finding("MAN-003", "Test-only build", "Medium", "M8", "MASVS-CODE", "CWE-489",
                        "Configuration",
                        "android:testOnly=\"true\" marks a development build. Such builds often keep debug "
                        "endpoints and verbose logging and cannot be installed normally.",
                        "Build release artifacts with the release build type (testOnly is injected by "
                        "Android Studio 'Run' builds).", evidence=['android:testOnly="true"']))

    shared = ctx.manifest.get(ANDROID_NS + "sharedUserId")
    if shared:
        ctx.add(Finding("MAN-004", "sharedUserId in use", "Low", "M8", "MASVS-PLATFORM", "CWE-269",
                        "Configuration",
                        f"The app shares a Linux UID ('{shared}') with other apps signed by the same key. "
                        "A vulnerability in any app of the group exposes all of their data. sharedUserId is "
                        "deprecated since API 29.",
                        "Remove android:sharedUserId and use explicit IPC (bound services / content "
                        "providers protected by signature permissions).",
                        evidence=[f'android:sharedUserId="{shared}"']))

    if (a("requestLegacyExternalStorage") or "").lower() == "true":
        ctx.add(Finding("MAN-005", "Opted out of scoped storage", "Low", "M9", "MASVS-STORAGE", "CWE-922",
                        "Data Storage",
                        "requestLegacyExternalStorage=\"true\" keeps the legacy shared-storage model on Android 10, "
                        "where files written to external storage are readable by any app holding the storage "
                        "permission.",
                        "Migrate to scoped storage (MediaStore / Storage Access Framework / app-specific dirs) "
                        "and drop the flag.",
                        evidence=['android:requestLegacyExternalStorage="true"']))


def _network_security(ctx: ScanContext) -> None:
    a = ctx.app_attr
    cleartext = a("usesCleartextTraffic")
    nsc_ref = a("networkSecurityConfig")
    nsc_path = ctx.resolve_resource(nsc_ref) if nsc_ref else None
    nsc = ctx.read_xml(nsc_path) if isinstance(nsc_path, str) else None
    ctx.extra["network_security_config"] = None

    if nsc is None:
        if cleartext and cleartext.lower() == "true":
            ctx.add(Finding(
                "NET-001", "Cleartext HTTP traffic allowed", "High", "M5", "MASVS-NETWORK", "CWE-319",
                "Network Security",
                "android:usesCleartextTraffic=\"true\" allows unencrypted HTTP connections to any host. "
                "Anyone on the same Wi-Fi / network path can read and modify traffic (credentials, session "
                "tokens, API responses).",
                "Set usesCleartextTraffic=\"false\" and serve every endpoint over HTTPS. If a legacy host "
                "needs HTTP, scope it with a network_security_config domain-config.",
                evidence=['<application android:usesCleartextTraffic="true">']))
        elif cleartext is None and ctx.target_sdk < 28:
            ctx.add(Finding(
                "NET-002", "Cleartext traffic permitted by default (targetSdk < 28)", "Medium", "M5",
                "MASVS-NETWORK", "CWE-319", "Network Security",
                f"targetSdkVersion is {ctx.target_sdk}; before API 28 cleartext HTTP is allowed unless "
                "explicitly disabled.",
                "Add android:usesCleartextTraffic=\"false\" or a network_security_config with "
                "cleartextTrafficPermitted=\"false\", and raise targetSdkVersion.",
                evidence=[f"targetSdkVersion={ctx.target_sdk}", "usesCleartextTraffic unset"]))
        if ctx.target_sdk < 24:
            ctx.add(Finding(
                "NET-003", "User-installed CA certificates trusted (targetSdk < 24)", "Medium", "M5",
                "MASVS-NETWORK", "CWE-295", "Network Security",
                "Apps targeting API < 24 trust certificates the user (or malware/MDM) installs, making "
                "TLS interception trivial.",
                "Target API 24+ or ship a network_security_config whose trust-anchors only include "
                "<certificates src=\"system\"/>.",
                evidence=[f"targetSdkVersion={ctx.target_sdk}", "no networkSecurityConfig"]))
        return

    summary = {"file": nsc_path, "cleartext_base": None, "cleartext_domains": [], "user_ca": False,
               "pins": [], "debug_overrides": False}
    base = nsc.find("base-config")
    if base is not None and (base.get("cleartextTrafficPermitted") or "").lower() == "true":
        summary["cleartext_base"] = True
        ctx.add(Finding(
            "NET-004", "Network config permits cleartext traffic globally", "High", "M5", "MASVS-NETWORK",
            "CWE-319", "Network Security",
            "The <base-config> of the network security configuration allows HTTP to every domain.",
            "Set cleartextTrafficPermitted=\"false\" in <base-config> and whitelist only the domains that "
            "truly need it.", evidence=[f"{nsc_path}: <base-config cleartextTrafficPermitted=\"true\">"]))
    for dc in nsc.iter("domain-config"):
        domains = [d.text for d in dc.findall("domain") if d.text]
        if (dc.get("cleartextTrafficPermitted") or "").lower() == "true":
            summary["cleartext_domains"].extend(domains)
        for pinset in dc.findall("pin-set"):
            exp = pinset.get("expiration")
            summary["pins"].append({"domains": domains, "count": len(pinset.findall("pin")), "expiration": exp})
            ctx.control("cert_pinning", f"network_security_config pin-set for {', '.join(domains)[:80]}")
            if exp:
                try:
                    if _dt.date.fromisoformat(exp) < _dt.date.today():
                        ctx.add(Finding(
                            "NET-005", "Certificate pin-set has expired", "Low", "M5", "MASVS-NETWORK",
                            "CWE-295", "Network Security",
                            f"The pin-set for {', '.join(domains)} expired on {exp}; after expiration the "
                            "platform silently stops enforcing the pins.",
                            "Rotate pins and move the expiration date forward with each release.",
                            evidence=[f"{nsc_path}: pin-set expiration=\"{exp}\""]))
                except ValueError:
                    pass
    if summary["cleartext_domains"]:
        ctx.add(Finding(
            "NET-006", "Cleartext traffic allowed for specific domains", "Medium", "M5", "MASVS-NETWORK",
            "CWE-319", "Network Security",
            "The network security configuration explicitly allows HTTP for: " +
            ", ".join(summary["cleartext_domains"][:10]) + ". Traffic to these hosts can be intercepted.",
            "Serve these hosts over HTTPS and remove cleartextTrafficPermitted=\"true\".",
            evidence=[f"{nsc_path}: domain-config cleartextTrafficPermitted=\"true\" → {d}"
                      for d in summary["cleartext_domains"][:10]]))

    debug = nsc.find("debug-overrides")
    summary["debug_overrides"] = debug is not None
    for scope in ([base] if base is not None else []) + list(nsc.iter("domain-config")):
        for ta in scope.findall("trust-anchors"):
            for c in ta.findall("certificates"):
                src = (c.get("src") or "")
                if src == "user":
                    summary["user_ca"] = True
                if (c.get("overridePins") or "").lower() == "true":
                    ctx.add(Finding(
                        "NET-007", "Trust anchors override certificate pins", "Medium", "M5",
                        "MASVS-NETWORK", "CWE-295", "Network Security",
                        f"<certificates src=\"{src}\" overridePins=\"true\"> lets those CAs bypass pinning.",
                        "Remove overridePins outside of <debug-overrides>.",
                        evidence=[f"{nsc_path}: certificates src=\"{src}\" overridePins=\"true\""]))
    if summary["user_ca"]:
        ctx.add(Finding(
            "NET-008", "App trusts user-installed CA certificates", "High", "M5", "MASVS-NETWORK", "CWE-295",
            "Network Security",
            "The release network security configuration includes <certificates src=\"user\"/>. Any CA "
            "the user (or a malicious profile/MDM) installs can intercept the app's TLS traffic.",
            "Restrict trust-anchors to <certificates src=\"system\"/>; keep user CAs only inside "
            "<debug-overrides>.",
            evidence=[f"{nsc_path}: <trust-anchors><certificates src=\"user\"/>"]))
    ctx.extra["network_security_config"] = summary


def _exported(ctx: ScanContext, comps: List[dict], declared: Dict[str, str]) -> None:
    groups: Dict[str, List[dict]] = {"activity": [], "service": [], "receiver": [], "provider": []}
    for c in comps:
        if not c["exported"] or not c["enabled"]:
            continue
        if c["type"] == "activity" and c["is_launcher"]:
            continue
        perms = [c["permission"]] if c["type"] != "provider" else \
            [c["permission"] or c["read_permission"], c["permission"] or c["write_permission"]]
        levels = [protection(ctx, p, declared) for p in perms]
        if all(l in ("system", "strong") for l in levels):
            continue
        if all(l == "unknown" for l in levels):
            continue
        c["protection"] = levels
        groups[c["type"]].append(c)

    meta = {
        "activity": ("COMP-001", "Exported activities without protection", "Medium", "CWE-926",
                     "Any installed app can launch these screens directly, skipping login flows and passing "
                     "crafted extras (intent spoofing, UI/auth bypass, data injection)."),
        "service": ("COMP-002", "Exported services without protection", "High", "CWE-926",
                    "Any app can start or bind to these services and invoke their functionality with "
                    "attacker-controlled input."),
        "receiver": ("COMP-003", "Exported broadcast receivers without protection", "Medium", "CWE-925",
                     "Any app can send broadcasts to these receivers and trigger their logic with spoofed "
                     "intents."),
        "provider": ("COMP-004", "Exported content providers without effective protection", "High", "CWE-200",
                     "Other apps can query/insert/update/delete through these providers. Unprotected providers "
                     "commonly lead to data leaks, SQL injection in selection arguments and path traversal "
                     "via openFile()."),
    }
    for t, items in groups.items():
        if not items:
            continue
        rid, title, sev, cwe, desc = meta[t]
        app_items = [i for i in items if not ctx.is_library("L" + i["name"].replace(".", "/") + ";")]
        lib_only = not app_items
        ev = []
        for i in items[:15]:
            detail = i["exported_reason"]
            if t == "provider":
                detail += f", authorities={i['authorities']}"
                rp = i["read_permission"] or i["permission"]
                if rp:
                    detail += f", readPermission={rp} ({'weak: ' + declared.get(rp, 'normal') if rp in declared else 'weak'})"
            elif i["permission"]:
                detail += f", permission={i['permission']} (weak)"
            ev.append(f"{i['name']}  —  {detail}")
        f = Finding(rid, title, sev, "M3", "MASVS-PLATFORM", cwe, "Exported Components",
                    f"{len(items)} {t}(s) can be invoked by any app on the device. {desc}",
                    _remediation_for(t), evidence=ev,
                    locations=[i["name"] for i in items],
                    references=["https://developer.android.com/privacy-and-security/risks/android-exported"])
        if lib_only:
            f.severity = "Low"
            f.confidence = "Medium"
            f.in_library = True
            f.description += " All of them belong to third-party SDKs."
        ctx.add(f)


def _remediation_for(t: str) -> str:
    if t == "provider":
        return ("Set android:exported=\"false\" unless other apps must use the provider. If they must, guard "
                "it with a signature-level permission and use parameterized queries:\n\n"
                "<permission android:name=\"com.example.permission.DATA\"\n"
                "            android:protectionLevel=\"signature\"/>\n"
                "<provider android:name=\".DataProvider\"\n"
                "          android:exported=\"true\"\n"
                "          android:readPermission=\"com.example.permission.DATA\"\n"
                "          android:writePermission=\"com.example.permission.DATA\"/>")
    return ("Set android:exported=\"false\" on components that are only used internally. For components "
            "that must be reachable, require a signature-level permission and validate every extra:\n\n"
            "<" + t + " android:name=\".Foo\"\n"
            "    android:exported=\"true\"\n"
            "    android:permission=\"com.example.permission.INTERNAL\"/>\n\n"
            "<permission android:name=\"com.example.permission.INTERNAL\"\n"
            "            android:protectionLevel=\"signature\"/>")


def _custom_permissions(ctx: ScanContext, comps: List[dict], declared: Dict[str, str]) -> None:
    weak = {p: lvl for p, lvl in declared.items() if not lvl.startswith("signature")}
    if not weak:
        return
    users = [c["name"] for c in comps if weak.keys() & {c["permission"], c["read_permission"], c["write_permission"]}]
    ctx.add(Finding(
        "COMP-005", "Custom permission with weak protectionLevel", "Medium" if users else "Low", "M3",
        "MASVS-PLATFORM", "CWE-276", "Permissions",
        "These custom permissions use protectionLevel normal/dangerous, so any app can simply request "
        "them and gain access to the components they 'protect'.",
        "Use android:protectionLevel=\"signature\" for permissions that guard internal components.",
        evidence=[f"<permission android:name=\"{p}\" protectionLevel=\"{l}\"/>" for p, l in weak.items()] +
                 [f"used by: {u}" for u in users[:10]]))


def _deep_links(ctx: ScanContext, comps: List[dict]) -> None:
    links = []
    custom = []
    unverified = []
    secret_codes = []
    for c in comps:
        for f in c["filters"]:
            schemes = {d.get("scheme") for d in f["data"] if d.get("scheme")}
            if "android_secret_code" in schemes:
                secret_codes.append(c["name"])
            if "android.intent.category.BROWSABLE" not in f["categories"]:
                continue
            hosts = [d.get("host") for d in f["data"] if d.get("host")] or ["*"]
            paths = [d.get("path") or d.get("pathPrefix") or d.get("pathPattern") for d in f["data"]
                     if d.get("path") or d.get("pathPrefix") or d.get("pathPattern")]
            for s in sorted(schemes):
                for h in hosts:
                    uri = f"{s}://{h}{paths[0] if paths else ''}"
                    links.append({"uri": uri, "component": c["name"], "verified": f["autoVerify"]})
                    if s not in ("http", "https"):
                        custom.append(f"{uri}  →  {c['name']}")
                    elif not f["autoVerify"]:
                        unverified.append(f"{uri}  →  {c['name']}")
    ctx.extra["deep_links"] = links
    if custom:
        ctx.add(Finding(
            "LINK-001", "Custom URL scheme deep links", "Low", "M4", "MASVS-PLATFORM", "CWE-939",
            "Deep Links",
            "Custom schemes can be registered by any app, so links may be hijacked, and every parameter "
            "arrives from untrusted web content. Validate all deep-link input before using it (especially "
            "URLs passed to WebViews or intents).",
            "Prefer verified Android App Links (https + autoVerify) and strictly validate host, path and "
            "query parameters in the handling activity.",
            evidence=custom[:15], locations=sorted({l["component"] for l in links})))
    if unverified:
        ctx.add(Finding(
            "LINK-002", "HTTP(S) deep links without App Link verification", "Info", "M4", "MASVS-PLATFORM",
            "CWE-939", "Deep Links",
            "These web links are not verified (autoVerify missing), so another app can claim them and "
            "receive the user's URLs, which may contain tokens.",
            "Add android:autoVerify=\"true\" and publish /.well-known/assetlinks.json on the domain.",
            evidence=unverified[:15]))
    if secret_codes:
        ctx.add(Finding(
            "LINK-003", "Hidden dialer secret codes", "Low", "M8", "MASVS-CODE", "CWE-912",
            "Hidden Functionality",
            "The app registers android_secret_code handlers (*#*#code#*#*), a common way to hide debug "
            "menus or, in malware, to re-open a hidden app.",
            "Remove debug/secret entry points from production builds.",
            evidence=secret_codes[:10]))


def _file_providers(ctx: ScanContext, comps: List[dict]) -> None:
    for c in comps:
        if c["type"] != "provider":
            continue
        res = c["meta"].get("android.support.FILE_PROVIDER_PATHS")
        if not res:
            continue
        path = ctx.resolve_resource(res)
        xml = ctx.read_xml(path) if isinstance(path, str) else None
        if xml is None:
            continue
        issues = []
        sev = None
        conf = "High"
        for el in xml:
            tag = el.tag if isinstance(el.tag, str) else ""
            p = (el.get("path") or "").strip()
            if tag == "root-path":
                issues.append(f'<root-path path="{p}"> exposes the entire filesystem')
                sev = "High"
                conf = "Medium"
            elif p in ("", ".", "/") and tag in ("external-path", "external-files-path", "files-path",
                                                 "external-cache-path", "cache-path"):
                issues.append(f'<{tag} path="{p or "(empty)"}"> shares the whole directory')
                if tag == "external-path":
                    sev = sev or "Medium"
                else:
                    sev = sev or "Low"
        if issues:
            ctx.add(Finding(
                "FP-001", "Overly broad FileProvider paths", sev, "M8", "MASVS-STORAGE", "CWE-22",
                "Data Exposure",
                f"FileProvider {c['name']} ({path}) can grant access to far more files than needed. If any "
                "code path builds a content URI from user input (e.g. a share/export feature) attackers can "
                "read private files such as databases and shared_prefs.",
                "Share only dedicated sub-directories:\n\n<paths>\n    <files-path name=\"shared\" "
                "path=\"shared/\"/>\n</paths>",
                evidence=issues, locations=[c["name"]], confidence=conf))


def _task_hijacking(ctx: ScanContext, comps: List[dict]) -> None:
    app_affinity = ctx.app_attr("taskAffinity")
    risky = []
    for c in comps:
        if c["type"] != "activity":
            continue
        ta = c["task_affinity"]
        if ta and ta != ctx.package:
            risky.append(f"{c['name']} taskAffinity=\"{ta}\"")
    if ctx.target_sdk < 29 and app_affinity != "":
        singles = [c["name"] for c in comps if c["type"] == "activity" and
                   (c["launch_mode"] or "") in ("singleTask", "singleInstance", "2", "3")]
        ctx.add(Finding(
            "TASK-001", "Task hijacking (StrandHogg) possible", "Low" if not singles else "Medium", "M8",
            "MASVS-PLATFORM", "CWE-1021", "UI Security",
            f"targetSdkVersion {ctx.target_sdk} (< 29) and no empty taskAffinity: a malicious app can "
            "insert its own activity into this app's task and phish credentials (StrandHogg).",
            "Set android:taskAffinity=\"\" on the <application> element and target API 29+.",
            evidence=[f"targetSdkVersion={ctx.target_sdk}"] + [f"launchMode single*: {s}" for s in singles[:8]]))
    if risky:
        ctx.add(Finding(
            "TASK-002", "Activities with custom taskAffinity", "Low", "M8", "MASVS-PLATFORM", "CWE-1021",
            "UI Security",
            "Activities that declare a foreign taskAffinity can be grouped into other apps' tasks, a "
            "building block for task hijacking.",
            "Remove custom taskAffinity values unless strictly required.", evidence=risky[:10]))


def _platform_versions(ctx: ScanContext) -> None:
    if ctx.min_sdk < 21:
        ctx.add(Finding(
            "PLAT-001", "Supports obsolete Android versions", "Low", "M8", "MASVS-CODE", "CWE-1104",
            "Platform",
            f"minSdkVersion is {ctx.min_sdk}. Android versions below 5.0 lack modern TLS defaults, "
            "WebView updates, and are vulnerable to well-known platform bugs (e.g. addJavascriptInterface RCE, "
            "Janus, FakeID).",
            "Raise minSdkVersion to at least 23 (Android 6.0).", evidence=[f"minSdkVersion={ctx.min_sdk}"]))
    if ctx.target_sdk < 31:
        ctx.add(Finding(
            "PLAT-002", "Targets an outdated API level", "Low", "M8", "MASVS-CODE", "CWE-1104", "Platform",
            f"targetSdkVersion is {ctx.target_sdk}. The app opts out of newer platform protections "
            "(explicit exported flags, PendingIntent mutability, package visibility, scoped storage) and "
            "cannot be published on Google Play.",
            "Raise targetSdkVersion to the current Play requirement and adapt to the behaviour changes.",
            evidence=[f"targetSdkVersion={ctx.target_sdk}"]))


def _manifest_capabilities(ctx: ScanContext, comps: List[dict]) -> None:
    perms = set(ctx.apk.get_permissions() or [])
    ctx.extra["permissions"] = sorted(perms)
    has_launcher = any(c["is_launcher"] for c in comps) or any(
        "android.intent.category.LEANBACK_LAUNCHER" in f["categories"] for c in comps for f in c["filters"])
    ctx.extra["has_launcher"] = has_launcher

    for c in comps:
        acts = {a for f in c["filters"] for a in f["actions"]}
        if c["type"] == "service":
            if "android.accessibilityservice.AccessibilityService" in acts or \
                    c["permission"] == "android.permission.BIND_ACCESSIBILITY_SERVICE":
                ctx.capability("accessibility", "Accessibility service (can read screen & perform actions)",
                               c["name"], 12)
            if "android.service.notification.NotificationListenerService" in acts:
                ctx.capability("notification_listener", "Reads all notifications (OTP/2FA access)", c["name"], 8)
            if "android.net.VpnService" in acts:
                ctx.capability("vpn", "VPN service (can see all traffic)", c["name"], 4)
            if "android.view.InputMethod" in acts:
                ctx.capability("ime", "Custom keyboard (sees everything typed)", c["name"], 6)
        if c["type"] == "receiver":
            if "android.app.action.DEVICE_ADMIN_ENABLED" in acts or c["permission"] == "android.permission.BIND_DEVICE_ADMIN":
                ctx.capability("device_admin", "Device administrator (lock/wipe device, block uninstall)", c["name"], 12)
            if "android.intent.action.BOOT_COMPLETED" in acts or "android.intent.action.QUICKBOOT_POWERON" in acts:
                ctx.capability("boot", "Starts automatically at boot", c["name"], 3)
            if "android.provider.Telephony.SMS_RECEIVED" in acts or "android.provider.Telephony.SMS_DELIVER" in acts:
                prio = max((f["priority"] or 0) for f in c["filters"]) if c["filters"] else 0
                ctx.capability("sms_intercept", "Intercepts incoming SMS", f"{c['name']} (priority {prio})", 14)
                if prio >= 999:
                    ctx.signal("sms_high_priority", "SMS receiver with maximum priority (OTP hijack pattern)", 10,
                               c["name"])
            if "android.intent.action.NEW_OUTGOING_CALL" in acts or "android.intent.action.PHONE_STATE" in acts:
                ctx.capability("call_monitor", "Monitors phone calls", c["name"], 6)
            if "android.intent.action.PACKAGE_ADDED" in acts:
                ctx.capability("pkg_monitor", "Watches app installs", c["name"], 2)

    if not has_launcher and comps:
        ctx.signal("no_launcher", "No launcher icon (app hides from the home screen)", 10,
                   "no MAIN/LAUNCHER activity")

    for p in perms:
        info = PERMISSIONS.get(p)
        if info and info[0] == "signature" and p not in ("android.permission.BIND_VPN_SERVICE",):
            ctx.signal("privileged_perm", "Requests system/signature-only permissions", 4, p)

    # Sensitive screens without tapjacking protection (only meaningful before Android 12)
    if ctx.target_sdk < 31:
        sensitive = [c["name"] for c in comps if c["type"] == "activity" and not c["filter_touches"] and
                     any(k in c["name"].rsplit(".", 1)[-1].lower() for k in SENSITIVE_SCREEN_KEYWORDS)]
        ctx.extra["sensitive_screens"] = sensitive
    else:
        ctx.extra["sensitive_screens"] = []


def _int(v) -> Optional[int]:
    try:
        return int(v, 0) if isinstance(v, str) else (int(v) if v is not None else None)
    except (TypeError, ValueError):
        return None
