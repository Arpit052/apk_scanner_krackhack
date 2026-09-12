#  Hybrid Ultimate APK Security Scanner

A high-performance, web-based static analysis tool for Android applications.  
Designed to rapidly detect OWASP Mobile Top 10 vulnerabilities, hardcoded secrets, and malware signatures in APK files up to 300MB.

 **Live Demo:**  
https://apkscannerkrackhack-production.up.railway.app

---

##  Features

-  **High-Speed Analysis**  
  Utilizes a 12-worker parallel processing engine to analyze large APKs (up to 300MB).

-  **Deep Static Analysis**  
  Detects Intent Redirection, Exported Accessibility Services, and Insecure WebViews.

-  **Secrets Scanning**  
  Regex-based detection for AWS keys, Firebase URLs, Stripe tokens, and Private Keys.

-  **Malware Detection**  
  Identifies malicious permission combinations, hooking frameworks, and known malicious packages.

-  **Interactive Dashboard**  
  Responsive frontend with Chart.js visualizations, OWASP/CWE breakdowns, and remediation steps.

-  **API-First Design**  
  Built on FastAPI for easy CI/CD integration.

---

##  Live Usage (Steps)

- Open the live server:  
  https://apkscannerkrackhack-production.up.railway.app

- Upload any `.apk` file (e.g., InsecureShop.apk)

- Click **Start Security Scan**

- View vulnerability dashboard

- Export detailed JSON/PDF reports

---

## Local Installation (For Developers)

If you wish to run the analysis engine locally:

### Clone the repository

```bash
git clone https://github.com/yourusername/apk-scanner.git
cd apk-scanner
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Start the server

```bash
python main.py
```

### Server URL

```
http://localhost:8000
```


