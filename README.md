# apk_scanner_krackhack


🛡️ Hybrid Ultimate APK Security Scanner
A high-performance, web-based static analysis tool for Android applications. Designed to rapidly detect OWASP Mobile Top 10 vulnerabilities, hardcoded secrets, and malware signatures in APK files up to 300MB.

🔴 Live Demo: https://apkscannerkrackhack-production.up.railway.app

✨ Features
🚀 High-Speed Analysis: Utilizes a 12-worker parallel processing engine to analyze large APKs (up to 300MB).
🕵️ Deep Static Analysis: Detects critical flaws like Intent Redirection, Exported Accessibility Services, and Insecure WebViews.
🔑 Secrets Scanning: Rapid regex-based detection for hardcoded AWS keys, Firebase URLs, Stripe tokens, and Private Keys.
🦠 Malware Detection: Identifies malicious permission combinations, hooking frameworks, and known malicious packages.
📊 Interactive Dashboard: A beautiful, responsive frontend featuring Chart.js visualizations, OWASP/CWE breakdowns, and actionable remediation steps.
🔌 API-First Design: Built on FastAPI, making it easy to integrate with CI/CD pipelines.
🌐 Live Usage (Recommended for Evaluation)
You can access the fully functional, deployed scanner directly from your browser—no local installation required!
Navigate to our live server: https://apkscannerkrackhack-production.up.railway.app
Upload any .apk file (e.g., a vulnerable app like InsecureShop.apk).
Click Start Security Scan to initiate the analysis engine.
View the generated vulnerability dashboard and export the detailed report in JSON/PDF formats.
💻 Local Installation (For Developers)
If you wish to run the analysis engine locally:
Clone the repository:
Bash
git clone https://github.com/yourusername/apk-scanner.git
cd apk-scanner
Install dependencies:
Bash
pip install -r requirement.txt
Start the server:
Bash
python main.py
The server will start with Uvicorn on http://localhost:8000.
🧪 API Validation & Testing (Requestly Partner Track)
We utilized the Requestly API Client as a core part of our development workflow to rigorously test and validate our live production backend.

To test our API using Requestly:
Open the Requestly Desktop App or Web Client.
Create a POST request targeting our live analysis endpoint:
https://apkscannerkrackhack-production.up.railway.app/analyze
Set the Body type to multipart/form-data.
Add a key named file (type: File) and upload a sample APK.
Send the request to validate our JSON schema. Requestly helps ensure our engine correctly parses large files and returns a 200 OK status code with accurate CWE reporting.
Built for KrackHack S3.
