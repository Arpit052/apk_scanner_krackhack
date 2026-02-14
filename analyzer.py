import subprocess
import zipfile
import xml.etree.ElementTree as ET
import re
import os
from pathlib import Path

def analyze_apk(apk_path):
    """
    FAST APK Analyzer using native tools
    No heavy libraries - just Android SDK tools + Python stdlib
    """
    print(f"🔍 Fast scanning: {apk_path}")
    
    report = {
        "app_name": "Unknown",
        "package_name": "Unknown",
        "version_name": "Unknown",
        "version_code": "Unknown",
        "min_sdk": "Unknown",
        "target_sdk": "Unknown",
        "vulnerabilities": [],
        "summary": {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "total": 0
        }
    }
    
    try:
        # ===================================================
        # STEP 1: Extract APK (Fast - uses Python zipfile)
        # ===================================================
        print("📦 Extracting APK...")
        temp_dir = "temp_extract"
        os.makedirs(temp_dir, exist_ok=True)
        
        with zipfile.ZipFile(apk_path, 'r') as zip_ref:
            # Only extract what we need!
            try:
                zip_ref.extract('AndroidManifest.xml', temp_dir)
            except:
                pass
            
            # Extract classes.dex for string analysis (optional)
            try:
                zip_ref.extract('classes.dex', temp_dir)
            except:
                pass
        
        # ===================================================
        # STEP 2: Use AAPT (Android Asset Packaging Tool)
        # Super fast - comes with Android SDK
        # ===================================================
        print("🔎 Using AAPT for quick analysis...")
        
        try:
            # Get basic info
            result = subprocess.run(
                ['aapt', 'dump', 'badging', apk_path],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                output = result.stdout
                
                # Parse package info
                for line in output.split('\n'):
                    if line.startswith('package:'):
                        match = re.search(r"name='([^']+)'", line)
                        if match:
                            report['package_name'] = match.group(1)
                        
                        match = re.search(r"versionCode='([^']+)'", line)
                        if match:
                            report['version_code'] = match.group(1)
                        
                        match = re.search(r"versionName='([^']+)'", line)
                        if match:
                            report['version_name'] = match.group(1)
                    
                    elif line.startswith('application-label:'):
                        report['app_name'] = line.split("'")[1] if "'" in line else "Unknown"
                    
                    elif line.startswith('sdkVersion:'):
                        report['min_sdk'] = line.split("'")[1] if "'" in line else "Unknown"
                    
                    elif line.startswith('targetSdkVersion:'):
                        report['target_sdk'] = line.split("'")[1] if "'" in line else "Unknown"
                
                # Get permissions
                permissions = re.findall(r"uses-permission: name='([^']+)'", output)
                print(f"DEBUG: Found {len(permissions)} permissions")
                
                # Check dangerous permissions
                dangerous = {
                    "android.permission.READ_SMS": "Can read SMS messages",
                    "android.permission.SEND_SMS": "Can send SMS",
                    "android.permission.RECORD_AUDIO": "Can record audio",
                    "android.permission.READ_CONTACTS": "Can read contacts",
                    "android.permission.ACCESS_FINE_LOCATION": "Can track location",
                    "android.permission.CAMERA": "Can access camera",
                    "android.permission.READ_PHONE_STATE": "Can read phone state"
                }
                
                for perm in permissions:
                    if perm in dangerous:
                        _add_vuln(report, {
                            "type": f"Dangerous Permission: {perm.split('.')[-1]}",
                            "severity": "Medium",
                            "owasp": "M1 (Improper Platform Usage)",
                            "category": "Permissions",
                            "details": f"App requests {perm.split('.')[-1]}. {dangerous[perm]}",
                            "remediation": "Remove if not necessary."
                        })
        
        except subprocess.TimeoutExpired:
            print("⚠️ AAPT timeout - skipping")
        except FileNotFoundError:
            print("⚠️ AAPT not found - using fallback")
            report['app_name'] = Path(apk_path).stem
            report['package_name'] = "com.unknown.app"
        
        # ===================================================
        # STEP 3: Quick Manifest Checks (No heavy parsing!)
        # ===================================================
        print("🔎 Checking manifest...")
        
        try:
            # Use aapt to dump xml
            result = subprocess.run(
                ['aapt', 'dump', 'xmltree', apk_path, 'AndroidManifest.xml'],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode == 0:
                manifest_text = result.stdout
                
                # Check debuggable
                if 'android:debuggable(0x0101000f)=(type 0x12)0xffffffff' in manifest_text:
                    _add_vuln(report, {
                        "type": "App is Debuggable",
                        "severity": "High",
                        "owasp": "M7 (Client Code Quality)",
                        "category": "Configuration",
                        "details": "App is debuggable in production",
                        "remediation": "Set android:debuggable='false'"
                    })
                
                # Check allowBackup (if NOT explicitly false, it's a vuln)
                if 'allowBackup' not in manifest_text or 'allowBackup(0x01010280)=(type 0x12)0xffffffff' in manifest_text:
                    _add_vuln(report, {
                        "type": "Backup Enabled",
                        "severity": "Medium",
                        "owasp": "M2 (Insecure Data Storage)",
                        "category": "Data Protection",
                        "details": "App data can be backed up",
                        "remediation": "Set android:allowBackup='false'"
                    })
                
                # Check cleartext traffic
                if 'usesCleartextTraffic(0x010104ec)=(type 0x12)0xffffffff' in manifest_text:
                    _add_vuln(report, {
                        "type": "Cleartext Traffic Allowed",
                        "severity": "Critical",
                        "owasp": "M3 (Insecure Communication)",
                        "category": "Network Security",
                        "details": "HTTP traffic is allowed",
                        "remediation": "Enforce HTTPS only"
                    })
        
        except subprocess.TimeoutExpired:
            print("⚠️ Manifest check timeout")
        except:
            print("⚠️ Manifest check failed - skipping")
        
        # ===================================================
        # STEP 4: Quick String Scan (Limited to save time)
        # ===================================================
        print("🔎 Quick string scan...")
        
        try:
            # Use strings command (fast!)
            result = subprocess.run(
                ['strings', apk_path],
                capture_output=True,
                text=True,
                timeout=30
            )
            
            if result.returncode == 0:
                strings_output = result.stdout.split('\n')
                
                # Limit to first 5000 strings
                strings_output = strings_output[:5000]
                
                patterns = {
                    "AWS Key": re.compile(r'AKIA[0-9A-Z]{16}'),
                    "API Key": re.compile(r'(?i)(api[_-]?key|apikey)["\s:=]+["\']?([A-Za-z0-9\-_]{20,})["\']?'),
                    "Google API": re.compile(r'AIza[0-9A-Za-z\-_]{35}')
                }
                
                found = set()
                for s in strings_output:
                    if len(s) < 200:
                        for name, pattern in patterns.items():
                            if pattern.search(s) and s not in found:
                                found.add(s)
                                _add_vuln(report, {
                                    "type": f"Hardcoded {name}",
                                    "severity": "Critical",
                                    "owasp": "M9 (Reverse Engineering)",
                                    "category": "Secrets",
                                    "details": f"Found: {s[:50]}...",
                                    "remediation": "Remove hardcoded secrets"
                                })
                                if len(found) >= 3:
                                    break
                    if len(found) >= 3:
                        break
        
        except subprocess.TimeoutExpired:
            print("⚠️ String scan timeout - skipping")
        except FileNotFoundError:
            print("⚠️ 'strings' command not found - skipping secret scan")
        
        print(f"✓ Analysis complete! Found {len(report['vulnerabilities'])} issues")
        
    except Exception as e:
        print(f"❌ Error: {e}")
        return {
            "error": str(e),
            "app_name": report.get('app_name', 'Unknown'),
            "package_name": report.get('package_name', 'Unknown')
        }
    
    finally:
        # Cleanup
        try:
            import shutil
            if os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
        except:
            pass
    
    # Update summary
    report['summary']['total'] = len(report['vulnerabilities'])
    
    # Sort by severity
    severity_order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    report['vulnerabilities'].sort(key=lambda x: severity_order.get(x['severity'], 4))
    
    return report


def _add_vuln(report, vuln):
    """Add vulnerability and update summary"""
    report['vulnerabilities'].append(vuln)
    sev = vuln['severity'].lower()
    if sev in report['summary']:
        report['summary'][sev] += 1


def generate_report_text(report):
    """Generate text report"""
    if 'error' in report:
        return f"ERROR: {report['error']}"
    
    output = []
    output.append("="*60)
    output.append("APK SECURITY REPORT")
    output.append("="*60)
    output.append(f"App: {report['app_name']}")
    output.append(f"Package: {report['package_name']}")
    output.append(f"Version: {report['version_name']}")
    output.append("")
    output.append(f"Critical: {report['summary']['critical']}")
    output.append(f"High: {report['summary']['high']}")
    output.append(f"Medium: {report['summary']['medium']}")
    output.append(f"Low: {report['summary']['low']}")
    output.append(f"Total: {report['summary']['total']}")
    output.append("="*60)
    
    for i, v in enumerate(report['vulnerabilities'], 1):
        output.append(f"\n[{i}] {v['type']} ({v['severity']})")
        output.append(f"Details: {v['details']}")
        output.append(f"Fix: {v['remediation']}")
    
    return "\n".join(output)
