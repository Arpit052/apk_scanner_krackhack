# APK X-Ray: KrackHack APK Security Scanner

Static security and malware analysis for Android apps. Drop an APK and it gets taken apart: manifest, every DEX method call, signing certificates, secrets, SDKs and trackers. Every finding is mapped to the **OWASP Mobile Top 10 (2024)**, **OWASP MASVS** and a **CWE**, with the exact class/method it was found in and a concrete fix.

Started at the KrackHack hackathon; v3 is a ground-up rewrite of the analysis engine and the UI.

**Live demo:** https://apkscannerkrackhack-production.up.railway.app · https://apk-scanner-krackhack.onrender.com

---

## What's new in v3

| | v2 (hackathon) | v3 |
|---|---|---|
| Code analysis | substring search (`b"su"`, `b"DES"`) in the *smallest* DEX only | full DEX parser over **all** `classes*.dex`, bytecode call-site tracing with constant tracking |
| Manifest checks | silently never ran (lxml object passed to `ET.fromstring`) | debuggable, backup, cleartext, exported components with real exported/permission semantics, weak custom permissions, deep links, FileProvider paths, task hijacking |
| Signatures | only `META-INF/CERT.RSA` → v2/v3-signed apps flagged "unsigned" | v1/v2/v3/v4 schemes, cert parsing, debug/AOSP keys, Janus, weak keys |
| Network | – | `network_security_config.xml` parsing (cleartext domains, user CAs, pins), trust-all `TrustManager` and always-true `HostnameVerifier` detection by inspecting method bodies |
| Secrets | whole file skipped if it contained the word "test" | 30+ validated formats (AWS, GCP SA, Stripe, GitHub, Slack, Telegram, OpenAI…), masked output |
| Malware | ≥1 weak indicator ⇒ "MALWARE DETECTED" | weighted 0–100 model: capabilities + signals + dangerous combinations, packer & payload detection |
| Standards | OWASP 2016 labels | OWASP Mobile Top 10 **2024** + MASVS + CWE |
| Output | JSON / print | JSON, **SARIF** (GitHub code scanning), print/PDF, CLI with `--fail-on` for CI |
| UI | static dashboard | live scan with streaming log, simple report with findings list and detail tabs |

### Accuracy on real apps

| APK | v2 result | v3 result |
|---|---|---|
| **InsecureShop** (intentionally vulnerable) | 7 findings; missed debuggable, cleartext, exported provider, root-path FileProvider, deep-link → WebView, SSL `proceed()` | 26 findings incl. all of those, each with the class it's in |
| **Allsafe** (intentionally vulnerable) | – | flags AES/ECB, hardcoded key `1nf0…`, SQLi string concatenation, intent redirection in `ProxyActivity`, cleartext domain config, credentials in URL |
| **NewPipe** (legit open-source app) | "Missing APK Signature" **Critical** + **MALWARE DETECTED** (false positives) | correctly signed v1+v2+v3, no malware indicators |
| **Termux** 110 MB debug build | – | scanned in ~2 s; debuggable, weak `RUN_COMMAND` permission, exported services |

---

## How it works

```
APK ──► manifest (pyaxmlparser) ──► components, exported rules, NSC, FileProvider
    ├─► signing block / META-INF ──► schemes + X.509 (cryptography)
    ├─► classes*.dex ──► scanner/dex.py
    │        string pool · type/method/field tables · class hierarchy
    │        bytecode walk tracking const / const-string / moves per register
    │        → "WebSettings.setAllowUniversalAccessFromFileURLs(true) in WebViewActivity.onCreate()"
    ├─► strings (DEX + resources.arsc + assets) ──► secrets, URLs, IPs
    └─► SDK / tracker / packer / framework fingerprints
                     │
                     ▼
     findings (OWASP 2024 · MASVS · CWE · confidence · locations)
     malware verdict (clean / low / suspicious / likely malicious)
```

Findings that only appear inside third-party libraries are marked `[library]`, downgraded, and can be hidden in the UI, so most of the noise from SDK dead code goes away.

## Run it locally

```bash
git clone https://github.com/Arpit052/apk_scanner_krackhack.git
cd apk_scanner_krackhack
pip install -r requirements.txt
python main.py            # http://localhost:8000
```

Or with Docker: `docker build -t apk-xray . && docker run -p 8000:8000 apk-xray`

Environment variables: `PORT` (8000), `MAX_UPLOAD_MB` (300), `SCANNER_WORKERS` (2), `JOB_TTL_SECONDS` (3600).

## CLI and CI

```bash
python analyzer.py app.apk                         # summary in the terminal
python analyzer.py app.apk --json report.json      # full report
python analyzer.py app.apk --sarif results.sarif   # GitHub code scanning
python analyzer.py app.apk --fail-on high          # exit 1 if any (non-library) High+ finding
```

GitHub Actions example:

```yaml
- run: pip install -r requirements.txt
- run: python analyzer.py app/build/outputs/apk/release/app-release.apk --sarif xray.sarif --fail-on critical
- uses: github/codeql-action/upload-sarif@v3
  with: { sarif_file: xray.sarif }
```

## API

| Method | Path | |
|---|---|---|
| `POST` | `/api/scan` | multipart `file` → `{"job_id"}` (async) |
| `GET` | `/api/scan/{job_id}?since=N` | status, progress %, new log lines, and the report when done |
| `GET` | `/api/report/{job_id}.json` / `.sarif` | downloads |
| `POST` | `/analyze` | legacy synchronous endpoint (returns the report) |
| `GET` | `/health` | liveness + queue info |

Interactive docs at `/docs`. `.xapk` / `.apks` bundles are supported (the base APK is scanned).

## Tests

```bash
python -m pytest -q                                   # bytecode scanner & scoring unit tests
APK_SAMPLE=/path/InsecureShop.apk python -m pytest -q # + end-to-end check
```

## Project layout

```
main.py              FastAPI server (async jobs, live progress)
analyzer.py          CLI + backwards-compatible analyze_apk()
index.html           single-file UI (no build step)
scanner/
  dex.py             DEX parser + bytecode call-site scanner
  context.py         scan state, Finding model
  checks_manifest.py manifest, network security config, FileProvider, deep links
  checks_code.py     WebView, TLS, crypto, storage, SQL, IPC, logging, capabilities
  checks_signing.py  signature schemes & certificates
  checks_secrets.py  secrets + endpoint intelligence
  checks_intel.py    permissions, trackers, frameworks, packers, malware model
  taxonomy.py        OWASP Mobile Top 10 2024 / MASVS
  sarif.py           SARIF 2.1.0 export
static/              self-hosted fonts (OFL) + demo report
```

## Limits

This is static analysis. It can't see code that is downloaded or unpacked at runtime (packed apps are flagged), and data-flow checks such as intent redirection are heuristics with a stated confidence. Treat findings as leads to verify, and use dynamic testing (Frida, MobSF dynamic, a sandbox) for confirmation.

## License

MIT for the code. Geist fonts in `static/fonts` are licensed under the SIL Open Font License.
