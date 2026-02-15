# 🛡️ Hybrid Ultimate APK Security Scanner

A high-performance, web-based static analysis tool for Android applications.  
Designed to rapidly detect OWASP Mobile Top 10 vulnerabilities, hardcoded secrets, and malware signatures in APK files up to 300MB.

🔴 **Live Demo:**  
https://apkscannerkrackhack-production.up.railway.app

---

## ✨ Features

- 🚀 **High-Speed Analysis**  
  Utilizes a 12-worker parallel processing engine to analyze large APKs (up to 300MB).

- 🕵️ **Deep Static Analysis**  
  Detects critical flaws like Intent Redirection, Exported Accessibility Services, and Insecure WebViews.

- 🔑 **Secrets Scanning**  
  Rapid regex-based detection for hardcoded AWS keys, Firebase URLs, Stripe tokens, and Private Keys.

- 🦠 **Malware Detection**  
  Identifies malicious permission combinations, hooking frameworks, and known malicious packages.

- 📊 **Interactive Dashboard**  
  A beautiful, responsive frontend featuring Chart.js visualizations, OWASP/CWE breakdowns, and actionable remediation steps.

- 🔌 **API-First Design**  
  Built on FastAPI, making it easy to integrate with CI/CD pipelines.

---

## 🌐 Live Usage (Recommended for Evaluation)

- Access the fully functional deployed scanner directly from your browser (no local installation required):  
  https://apkscannerkrackhack-production.up.railway.app

- Upload any `.apk` file (e.g., a vulnerable app like InsecureShop.apk).

- Click **Start Security Scan** to initiate the analysis engine.

- View the generated vulnerability dashboard and export the detailed report in JSON/PDF formats.

---

## 💻 Local Installation (For Developers)

If you wish to run the analysis engine locally:

### Clone the repository

```bash
git clone https://github.com/yourusername/apk-scanner.git
cd apk-scanner

## 💻 Run Locally
```bash
pip install -r requirements.txt
python main.py


## The server will start with Uvicorn on:
http://localhost:8000





