"""Hardcoded secrets + network endpoint intelligence."""

from __future__ import annotations

import base64
import ipaddress
import json
import math
import re
from collections import Counter, defaultdict
from typing import Dict, Iterable, Tuple
from urllib.parse import urlsplit

from .context import Finding, ScanContext
from .knowledge import C2_HOST_HINTS, IGNORED_URL_HOSTS, SUSPICIOUS_TLDS

# (id, label, regex, severity, owasp)
PATTERNS = [
    ("aws_key", "AWS access key ID", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|ANPA|ANVA|AIPA)[A-Z0-9]{16}\b", "High"),
    ("gcp_sa", "Google Cloud service-account private key", r'"type"\s*:\s*"service_account"', "Critical"),
    ("google_oauth_secret", "Google OAuth client secret", r"\bGOCSPX-[A-Za-z0-9_\-]{28}\b", "High"),
    ("google_api", "Google API key", r"\bAIza[0-9A-Za-z_\-]{35}\b", "Low"),
    ("firebase_db", "Firebase Realtime Database URL", r"\bhttps://[a-z0-9\-]+\.(?:firebaseio\.com|firebasedatabase\.app)\b", "Info"),
    ("stripe_secret", "Stripe live secret key", r"\b(?:sk|rk)_live_[0-9a-zA-Z]{24,99}\b", "Critical"),
    ("stripe_test", "Stripe test secret key", r"\bsk_test_[0-9a-zA-Z]{24,99}\b", "Low"),
    ("github_token", "GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{82})\b", "Critical"),
    ("gitlab_token", "GitLab personal access token", r"\bglpat-[A-Za-z0-9_\-]{20}\b", "Critical"),
    ("slack_token", "Slack token", r"\bxox[abposr]-[0-9A-Za-z\-]{10,72}\b", "High"),
    ("slack_webhook", "Slack incoming webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]{20,}", "High"),
    ("discord_webhook", "Discord webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w\-]{20,}", "High"),
    ("telegram_bot", "Telegram bot token", r"\b\d{8,10}:AA[0-9A-Za-z_\-]{33}\b", "High"),
    ("twilio_key", "Twilio API key", r"\bSK[0-9a-fA-F]{32}\b", "Medium"),
    ("sendgrid", "SendGrid API key", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", "High"),
    ("mailgun", "Mailgun API key", r"\bkey-[0-9a-f]{32}\b", "High"),
    ("mailchimp", "Mailchimp API key", r"\b[0-9a-f]{32}-us\d{1,2}\b", "High"),
    ("openai", "OpenAI API key", r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_\-]{20,}T3BlbkFJ[A-Za-z0-9_\-]{20,}\b", "Critical"),
    ("openai_new", "OpenAI project API key", r"\bsk-proj-[A-Za-z0-9_\-]{80,}\b", "Critical"),
    ("anthropic", "Anthropic API key", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}\b", "Critical"),
    ("gemini", "Google AI Studio key", r"\bAIzaSy[0-9A-Za-z_\-]{33}\b", None),   # covered by google_api
    ("mapbox_secret", "Mapbox secret token", r"\bsk\.eyJ[A-Za-z0-9_\-]{20,}\.[A-Za-z0-9_\-]{20,}\b", "High"),
    ("azure_storage", "Azure storage connection string",
     r"DefaultEndpointsProtocol=https?;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{40,}", "Critical"),
    ("private_key", "Private key (PEM)", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----", "Critical"),
    ("jwt", "JSON Web Token", r"\beyJ[A-Za-z0-9_\-]{8,}\.eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\b", "Medium"),
    ("basic_auth_url", "Credentials embedded in URL", r"\b(?:https?|ftp)://[^\s:/@\"']{2,64}:[^\s:/@\"']{3,64}@[a-z0-9.\-]+", "High"),
    ("facebook_token", "Facebook access token", r"\bEAACEdEose0cBA[0-9A-Za-z]+\b", "High"),
    ("square", "Square access token", r"\bsq0atp-[0-9A-Za-z\-_]{22}\b|\bEAAA[a-zA-Z0-9\-_]{60}\b", "High"),
    ("shopify", "Shopify access token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", "High"),
    ("razorpay_secret", "Razorpay key", r"\brzp_live_[0-9A-Za-z]{14}\b", "Medium"),
    ("npm", "npm token", r"\bnpm_[A-Za-z0-9]{36}\b", "High"),
    ("huggingface", "Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b", "High"),
]
COMPILED = [(i, l, re.compile(r), s) for i, l, r, s in PATTERNS if s]

NAME_HINT = re.compile(r"(pass(word|wd)?|secret|api[_\-]?key|apikey|token|auth|client[_\-]?secret|private[_\-]?key|"
                       r"access[_\-]?key|credential|pwd|bearer)", re.I)
NAME_IGNORE = re.compile(r"(hint|label|title|desc|message|error|prompt|toggle|show|hide|forgot|reset|change|enter|"
                         r"confirm|invalid|wrong|required|summary|_msg|_text|content_description|abc_|mtrl_|"
                         r"common_google|fcm_fallback|gcm_defaultSenderId|password_toggle|google_app_id|"
                         r"google_storage_bucket|project_id|default_web_client_id|google_api_key|google_crash_reporting_api_key|"
                         r"google_maps_key|firebase_database_url|gcm_defaultsenderid)", re.I)

URL_RE = re.compile(r"\b(?:https?|wss?|ftp)://[A-Za-z0-9\-._~%]+(?::\d{2,5})?(?:/[^\s\"'<>\\{}|^`]*)?")
IP_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")
IP_LINE_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$", re.M)

TEXT_EXT = (".json", ".xml", ".properties", ".txt", ".js", ".html", ".htm", ".cfg", ".conf", ".ini", ".yml",
            ".yaml", ".env", ".config", ".plist", ".bundle", ".csv", ".pem", ".key", ".crt", ".jsbundle", ".toml")


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


def mask(s: str) -> str:
    if len(s) <= 10:
        return s[:2] + "•" * (len(s) - 2)
    return s[:6] + "•" * min(len(s) - 10, 16) + s[-4:]


def _sources(ctx: ScanContext) -> Iterable[Tuple[str, str]]:
    # One joined blob per DEX: running each regex once over a big string is
    # far faster than calling it for every one of ~100k pool entries.
    for dx in ctx.dex.dexes:
        yield dx.name, "\n".join(s for s in dx.strings if 7 <= len(s) <= 20000)
    budget = 60 * 1024 * 1024
    for n in ctx.names:
        low = n.lower()
        if not (low.startswith(("assets/", "res/raw/")) or "/" not in low):
            continue
        if not low.endswith(TEXT_EXT) and not low.endswith("index.android.bundle"):
            continue
        try:
            info = ctx.zip.getinfo(n)
            if info.file_size > 25 * 1024 * 1024 or info.file_size > budget:
                continue
            budget -= info.file_size
            data = ctx.zip.read(n)
        except Exception:
            continue
        if data[:4] == b"\x03\x00\x08\x00":       # binary XML
            continue
        yield n, data.decode("utf-8", "ignore")


def run(ctx: ScanContext) -> None:
    hits: Dict[str, Dict[str, set]] = defaultdict(lambda: defaultdict(set))
    urls: Dict[str, set] = defaultdict(set)
    ips: Dict[str, set] = defaultdict(set)

    for src, text in _sources(ctx):
        if "://" in text:
            for m in URL_RE.finditer(text):
                urls[m.group(0).rstrip(".,;)")].add(src)
        for m in IP_LINE_RE.finditer(text):
            ips[m.group(0)].add(src)
        for pid, _label, rx, _sev in COMPILED:
            for m in rx.finditer(text):
                val = m.group(0)
                if pid == "jwt" and not _valid_jwt(val):
                    continue
                if pid == "twilio_key" and len(set(val[2:])) < 8:
                    continue
                if pid == "gcp_sa" and "private_key" not in text:
                    continue
                hits[pid][val].add(src)

    # resources.arsc: name-aware heuristics
    named = []
    try:
        arsc = ctx.arsc
        xml = arsc.get_strings_resources() if arsc else b""
        from lxml import etree
        root = etree.fromstring(xml) if xml else None
        if root is not None:
            for el in root.iter("string"):
                name = el.get("name") or ""
                val = (el.text or "").strip()
                if not val:
                    continue
                if "://" in val:
                    for m in URL_RE.finditer(val):
                        urls[m.group(0)].add("resources.arsc")
                for pid, _l, rx, _s in COMPILED:
                    for m in rx.finditer(val):
                        hits[pid][m.group(0)].add(f"resources.arsc (@string/{name})")
                if NAME_HINT.search(name) and not NAME_IGNORE.search(name) and 8 <= len(val) <= 200 \
                        and " " not in val and _entropy(val) >= 3.0 and not val.startswith(("@", "http", "#")):
                    named.append((name, val))
    except Exception as e:
        ctx.log(f"arsc string scan: {e}")

    _report_secrets(ctx, hits, named)
    _report_network(ctx, urls, ips)


def _valid_jwt(tok: str) -> bool:
    try:
        head = tok.split(".")[0]
        head += "=" * (-len(head) % 4)
        return "alg" in json.loads(base64.urlsafe_b64decode(head))
    except Exception:
        return False


def _report_secrets(ctx: ScanContext, hits, named) -> None:
    labels = {i: (l, s) for i, l, _r, s in PATTERNS}
    out = []
    for pid, vals in hits.items():
        label, sev = labels[pid]
        if pid == "google_api" and any(pid2 == "gemini" for pid2 in hits):
            pass
        for val, srcs in list(vals.items())[:10]:
            out.append({"type": label, "id": pid, "value": mask(val), "severity": sev,
                        "sources": sorted(srcs)[:4]})
    seen_vals = {v for vals in hits.values() for v in vals}
    for name, val in named[:20]:
        if val in seen_vals:
            continue
        out.append({"type": "Suspicious credential in string resource", "id": "named_resource",
                    "value": mask(val), "severity": "Medium", "sources": [f"@string/{name}"]})
    ctx.extra["secrets"] = out
    if not out:
        return

    groups = defaultdict(list)
    for o in out:
        groups[o["severity"]].append(o)
    remediation = ("Remove secrets from the client. Anything inside an APK is public: move privileged calls to "
                   "your backend, issue short-lived tokens per user, and rotate every exposed key now.\n\n"
                   "For Google/Firebase API keys (which are meant to be public) restrict them in Google Cloud "
                   "Console to your package name + signing certificate SHA-1 and to the APIs you use.")
    titles = {
        "Critical": ("SEC-001", "Hardcoded high-privilege secrets"),
        "High": ("SEC-002", "Hardcoded API tokens / credentials"),
        "Medium": ("SEC-003", "Possible hardcoded credentials"),
        "Low": ("SEC-004", "Client API keys embedded (verify restrictions)"),
        "Info": ("SEC-005", "Backend endpoints embedded"),
    }
    for sev in ("Critical", "High", "Medium", "Low", "Info"):
        items = groups.get(sev)
        if not items:
            continue
        rid, title = titles[sev]
        kinds = sorted({i["type"] for i in items})
        desc = (f"Found {len(items)} value(s): {', '.join(kinds)}. Secrets compiled into an APK can be "
                "extracted in seconds with apktool/jadx and abused to access your cloud resources or third-party "
                "accounts.")
        if sev == "Info":
            desc = ("Firebase Realtime Database URLs were found. If the database rules allow public read, "
                    "anyone can dump it via https://<db>.firebaseio.com/.json - verify the security rules.")
        ctx.add(Finding(rid, title, sev, "M1", "MASVS-STORAGE", "CWE-798", "Secrets", desc, remediation,
                        evidence=[f"{i['type']}: {i['value']}  ({', '.join(i['sources'][:2])})" for i in items],
                        confidence="Medium" if sev == "Medium" else "High", tags=["secret"]))
    for o in out:
        if o["id"] in ("telegram_bot", "discord_webhook"):
            ctx.signal("exfil_token", "Embedded Telegram/Discord bot credentials (exfiltration channel)", 14,
                       f"{o['type']} {o['value']}")


def _report_network(ctx: ScanContext, urls: Dict[str, set], ips: Dict[str, set]) -> None:
    domains: Dict[str, dict] = {}
    http_urls = []
    suspicious = []
    for u, srcs in urls.items():
        try:
            parts = urlsplit(u)
            host = (parts.hostname or "").lower()
        except ValueError:
            continue
        if not host or "." not in host or host.endswith(IGNORED_URL_HOSTS) or host in IGNORED_URL_HOSTS:
            continue
        if host.endswith((".xsd", ".dtd")):
            continue
        d = domains.setdefault(host, {"host": host, "count": 0, "schemes": set(), "samples": [], "flags": []})
        d["count"] += 1
        d["schemes"].add(parts.scheme)
        if len(d["samples"]) < 3:
            d["samples"].append(u[:200])
        is_ip = bool(IP_RE.match(host))
        if parts.scheme in ("http", "ws") and not _private(host):
            http_urls.append(u)
        for hint, why in C2_HOST_HINTS.items():
            if hint in u:
                d["flags"].append(why)
                suspicious.append((u, why))
        if host.endswith(SUSPICIOUS_TLDS):
            d["flags"].append("suspicious TLD")
        if is_ip and not _private(host):
            d["flags"].append("raw IP address")
    for ip in ips:
        if _public_ip(ip):
            d = domains.setdefault(ip, {"host": ip, "count": 0, "schemes": set(), "samples": [], "flags": []})
            d["count"] += 1
            d["flags"].append("raw IP address")
    out = sorted(domains.values(), key=lambda d: (-len(d["flags"]), -d["count"], d["host"]))
    for d in out:
        d["schemes"] = sorted(d["schemes"])
        d["flags"] = sorted(set(d["flags"]))
    ctx.extra["domains"] = out[:400]

    if http_urls:
        uniq = sorted(set(http_urls))
        ctx.add(Finding(
            "NET-009", "Hardcoded cleartext HTTP endpoints", "Low", "M5", "MASVS-NETWORK", "CWE-319",
            "Network Security",
            f"{len(uniq)} http:// URL(s) are embedded. If any of them is contacted at runtime, the traffic and "
            "responses can be read or modified by a network attacker.",
            "Switch every endpoint to HTTPS and block cleartext in network_security_config.",
            evidence=uniq[:15], confidence="Medium"))
    for u, why in suspicious:
        ctx.signal("c2_infra", "Embedded endpoints commonly used for C2 / exfiltration", 10, f"{why}: {u[:90]}")
    sus_tld = [d["host"] for d in out if "suspicious TLD" in d["flags"]]
    if sus_tld:
        ctx.signal("sus_tld", "Contacts domains on abuse-prone TLDs", 3, ", ".join(sus_tld[:5]))
    raw_ips = [d["host"] for d in out if "raw IP address" in d["flags"]]
    if raw_ips:
        ctx.signal("raw_ip", "Hardcoded public IP endpoints", 4, ", ".join(raw_ips[:5]))
        ctx.add(Finding(
            "NET-010", "Hardcoded public IP addresses", "Info", "M5", "MASVS-NETWORK", "CWE-1188",
            "Network Security", "Endpoints are addressed by raw IP. Certificates are rarely issued for IPs, which "
            "often leads to disabled validation; IP endpoints are also typical for C2 servers.",
            "Use DNS names with valid TLS certificates.", evidence=raw_ips[:15], confidence="Low"))


def _private(host: str) -> bool:
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved
    except ValueError:
        return host in ("localhost",) or host.endswith((".local", ".internal", ".lan"))


def _public_ip(s: str) -> bool:
    try:
        ip = ipaddress.ip_address(s)
    except ValueError:
        return False
    if not ip.is_global:
        return False
    first = int(s.split(".")[0])
    return first >= 11 and s.count(".") == 3 and not s.endswith(".0")
