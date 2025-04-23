#!/usr/bin/env python3
"""
Apache Sling Enumeration and Audit Script

This script performs enumeration and security auditing of Apache Sling instances.
It checks for common misconfigurations, default credentials, and potential security vulnerabilities.

Usage:
    python sling_audit.py -t <target_url> [options]

Example:
    python sling_audit.py -t http://example.com:4502 -u admin -p admin -v
"""

import argparse
import json
import re
import sys
import time
from urllib.parse import urljoin, urlparse
import warnings

import requests
from requests.packages.urllib3.exceptions import InsecureRequestWarning

# Suppress insecure request warnings
warnings.simplefilter('ignore', InsecureRequestWarning)

class SlingAuditor:
    """Apache Sling security auditor"""

    # Common paths and endpoints to check
    SLING_PATHS = {
        # Core Sling endpoints
        'felix_console': '/system/console',
        'content_explorer': '/crx/explorer/index.jsp',
        'crx_de': '/crx/de/index.jsp',
        'package_manager': '/crx/packmgr/index.jsp',
        'cq_damadmin': '/damadmin',
        'useradmin': '/useradmin',
        'query_builder': '/bin/querybuilder.json',
        'groovy_console': '/apps/groovyconsole.html',
        'aem_version': '/libs/cq/core/content/welcome.html',
        'wcm_debug': '/libs/cq/core/content/welcome.html?wcmmode=preview',
        'dispatcher_invalidate': '/dispatcher/invalidate.cache',
        'webdav': '/dav/crx.default',
        'sling_nodes': '/.json',
        'audit_log': '/bin/audit/com.day.cq.replication.servlet.AuditServlet',
        'post_servlet': '/bin/receive',
        'sling_rewrite': '/etc/rewrite.html',
        
        # Additional endpoints for better detection
        'felix_bundles': '/system/console/bundles',
        'felix_components': '/system/console/components',
        'felix_configmgr': '/system/console/configMgr',
        'crxde_logs': '/crx/de/logs.jsp',
        'sling_jcr_registration': '/libs/granite/core/content/login.html',
        
        # OSGI endpoint checks
        'osgi_console': '/system/console/bundles.json',
        'osgi_config': '/system/console/config/config.json',
        'osgi_status': '/system/console/status-slingsettings.json',
        'osgi_services': '/system/console/services.json',
        
        # AEM-specific paths
        'aem_sites': '/sites.html',
        'aem_assets': '/assets.html',
        'aem_projects': '/projects.html',
        'aem_tools': '/tools.html',
        'aem_publications': '/publications.html',
        'aem_forms': '/aem/forms.html',
        'aem_commerce': '/aem/commerce.html',
        'aem_screens': '/aem/screens.html',
        'aem_communities': '/aem/communities.html',
        
        # Additional JCR content endpoints
        'jcr_root': '/content.json',
        'jcr_apps': '/apps.json',
        'jcr_libs': '/libs.json',
        'jcr_etc': '/etc.json',
        'jcr_content': '/content.json',
        'jcr_system': '/system.json',
        
        # Servlet paths
        'servlet_querybuilder': '/bin/querybuilder.json',
        'servlet_wcmdebug': '/libs/cq/wcm/debug/param/html.jsp',
        'servlet_audit': '/bin/audit/com.day.cq.workflow.purge.Audit',
        'servlet_statistics': '/bin/statistics/tracker',
        'servlet_search': '/bin/wcm/search/gql.servlet.json',
        'servlet_traversing': '/bin/wcm/contentfinder/connector/suggestions.json',
        'servlet_resourceresolver': '/system/console/jmx/org.apache.sling.jcr.resource:type=JcrResourceResolverFactoryMetrics',
        
        # Security-related paths
        'userinfo': '/libs/granite/security/currentuser.json'
    }

    # Default credentials to try
    DEFAULT_CREDENTIALS = [
        ('admin', 'admin'),
        ('author', 'author'),
        ('admin', 'admin123'),
        ('admin', 'password'),
        ('admin', ''),
        ('', ''),
    ]

    # Known vulnerabilities to check
    VULNERABILITIES = {
        'CVE-2016-0788': {
            'name': 'Apache Sling XSS Vulnerability',
            'path': '/bin/wcm/contentfinder/connector/suggestions.json/<script>alert(1)</script>.html',
            'check': lambda r: '<script>alert(1)</script>' in r.text
        },
        'CVE-2017-3066': {
            'name': 'Adobe Experience Manager RCE via Serialized Java',
            'path': '/libs/cq/analytics/components/sitecatalystpage/segments.json.servlet',
            'check': lambda r: r.status_code == 200 and 'segmentdata' in r.text
        },
        'CVE-2018-12809': {
            'name': 'Apache Sling XXE Vulnerability',
            'path': '/system/sling/loginstatus',
            'check': lambda r: r.status_code == 200
        },
        'CVE-2019-7816': {
            'name': 'Sling Context-Sensitive Configuration Missing Resource Access Control',
            'path': '/conf',
            'check': lambda r: r.status_code == 200 and 'json' in r.headers.get('Content-Type', '')
        },
        'CVE-2022-21707': {
            'name': 'AEM Information Disclosure in Data Layer',
            'path': '/libs/cq/analytics/testandtarget/init.jsp',
            'check': lambda r: r.status_code == 200 and 'digitalData' in r.text
        },
        'CVE-2021-44228': {
            'name': 'Log4Shell - Log4j Remote Code Execution',
            'path': '/system/console/status-slingsettings.json',
            'check': lambda r: r.status_code == 200 and any(v for v in r.json().get('status', []) if 'log4j' in str(v).lower() and '2.14' in str(v))
        },
        'SLING-RCE-SCRIPTING': {
            'name': 'Sling Scripting RCE via JSP',
            'path': '/apps/sling/servlet/errorhandler/404.jsp',
            'check': lambda r: r.status_code == 200
        },
        'SLING-TRAVERSAL': {
            'name': 'Sling Path Traversal',
            'path': '/bin/../content.json',
            'check': lambda r: r.status_code == 200 and 'jcr:primaryType' in r.text
        }
    }

    def __init__(self, target_url, username=None, password=None, timeout=10, verify_ssl=False, verbose=False, 
                 threads=5, user_agent=None, cookies=None, proxy=None):
        """Initialize the auditor with target information"""
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.threads = threads
        self.proxy = proxy
        self.session = requests.Session()
        
        # Set custom user agent if provided, otherwise use default
        self.user_agent = user_agent or 'SlingAuditor/1.0'
        
        # Set cookies if provided
        if cookies:
            if isinstance(cookies, str):
                cookie_dict = {}
                for item in cookies.split(';'):
                    if '=' in item:
                        key, value = item.strip().split('=', 1)
                        cookie_dict[key] = value
                self.session.cookies.update(cookie_dict)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
                
        # Set proxy if provided
        if proxy:
            self.session.proxies = {
                'http': proxy,
                'https': proxy
            }
            
        self.results = {
            'target': self.target_url,
            'is_sling': False,
            'version': None,
            'product_info': {},
            'accessible_paths': [],
            'auth_required': [],
            'credentials_tested': [],
            'valid_credentials': [],
            'vulnerabilities': [],
            'exposed_apis': [],
            'query_results': [],
            'content_nodes': [],
            'jcr_structure': {},
            'users_found': [],
            'groups_found': [],
            'bundle_info': [],
            'osgi_configs': [],
            'dispatcher_config': {},
            'replication_agents': [],
            'security_findings': [],
            'scan_time': {
                'start': time.time(),
                'end': None,
                'duration': None
            }
        }

    def log(self, message, level="INFO"):
        """Print log messages if verbose mode is enabled"""
        if self.verbose:
            print(f"[{level}] {message}")

    def request(self, path, method='GET', auth=None, data=None, headers=None, allow_redirects=True):
        """Make a request to the target with enhanced error handling and throttling"""
        url = urljoin(self.target_url, path)
        default_headers = {'User-Agent': self.user_agent}
        
        if headers:
            default_headers.update(headers)
        
        try:
            if auth is None and self.username and self.password:
                auth = (self.username, self.password)
            
            self.log(f"Requesting: {method} {url}")
            
            # Add throttling to be gentler on the server
            time.sleep(0.5)  # Basic throttling
            
            response = self.session.request(
                method=method,
                url=url,
                auth=auth,
                data=data,
                headers=default_headers,
                timeout=self.timeout,
                verify=self.verify_ssl,
                allow_redirects=allow_redirects
            )
            
            # Log response details if verbose
            if self.verbose:
                self.log(f"Response: {response.status_code} - {len(response.content)} bytes")
                
                # Log interesting headers
                interesting_headers = ['Server', 'X-Powered-By', 'Set-Cookie', 'X-Content-Type-Options']
                for header in interesting_headers:
                    if header in response.headers:
                        self.log(f"Header: {header}: {response.headers[header]}")
            
            return response
        except requests.exceptions.Timeout:
            self.log(f"Request timeout: {url}", "ERROR")
            return None
        except requests.exceptions.ConnectionError:
            self.log(f"Connection error: {url}", "ERROR")
            return None
        except requests.exceptions.RequestException as e:
            self.log(f"Request error: {url} - {e}", "ERROR")
            return None

    def detect_sling(self):
        """Detect if the target is running Apache Sling with comprehensive fingerprinting"""
        # List of detection methods to try
        detection_methods = [
            # Felix Console detection
            {
                'path': '/system/console',
                'indicators': ['Apache Felix', 'OSGi System Console', 'Bundle List'],
                'name': 'Felix Console'
            },
            # JCR content paths
            {
                'path': '/.json',
                'indicators': ['jcr:primaryType', 'jcr:content', 'sling:resourceType'],
                'name': 'Sling JCR JSON'
            },
            # AEM-specific paths
            {
                'path': '/libs/granite/core/content/login.html',
                'indicators': ['AEM', 'Adobe Experience Manager', 'granite'],
                'name': 'AEM Login Page'
            },
            # CRXDE Lite detection
            {
                'path': '/crx/de/index.jsp',
                'indicators': ['CRXDE Lite', 'repository explorer'],
                'name': 'CRXDE Lite'
            },
            # AEM Welcome page
            {
                'path': '/libs/cq/core/content/welcome.html',
                'indicators': ['welcome', 'AEM', 'get started'],
                'name': 'AEM Welcome Page'
            },
        ]
        
        # Track detection methods that matched
        detection_matches = []
        
        # Try each detection method
        for method in detection_methods:
            path = method.get('path', '/')
            self.log(f"Trying detection method: {method.get('name')} at {path}")
            
            response = self.request(path)
            if not response:
                continue
                
            # Check for indicators in response text
            if 'indicators' in method and response.status_code == 200:
                for indicator in method['indicators']:
                    if indicator in response.text:
                        detection_matches.append({
                            'method': method.get('name'),
                            'path': path,
                            'indicator': indicator
                        })
                        self.log(f"Detection match: {method.get('name')} (found '{indicator}')")
                        break
        
        # Store detection results
        self.results['detection_matches'] = detection_matches
        
        # Determine if this is a Sling/AEM instance based on matches
        is_sling = len(detection_matches) > 0
        self.results['is_sling'] = is_sling
        self.results['detection_confidence'] = min(len(detection_matches) * 20, 100)  # Confidence percentage
        
        if is_sling:
            self.log(f"Apache Sling detected with {len(detection_matches)} indicators")
        else:
            self.log("Target does not appear to be running Apache Sling")
            
        return is_sling

    def detect_version(self):
        """Attempt to determine the Sling/AEM version"""
        # Check product info in Felix console
        response = self.request('/system/console/productinfo')
        if response and response.status_code == 200:
            version_match = re.search(r'Adobe Experience Manager \(([^)]+)\)', response.text)
            if version_match:
                self.results['version'] = version_match.group(1)
                return

        # Check version info in page metadata
        response = self.request('/libs/cq/core/content/welcome.html')
        if response and response.status_code == 200:
            version_match = re.search(r'data-version="([^"]+)"', response.text)
            if version_match:
                self.results['version'] = version_match.group(1)
                return

    def check_paths(self):
        """Check for accessible Sling paths"""
        for name, path in self.SLING_PATHS.items():
            response = self.request(path)
            if response:
                if response.status_code == 200:
                    self.results['accessible_paths'].append({
                        'path': path,
                        'name': name,
                        'status': response.status_code
                    })
                    self.log(f"Found accessible path: {path}")
                elif response.status_code == 401 or response.status_code == 403:
                    self.results['auth_required'].append({
                        'path': path,
                        'name': name,
                        'status': response.status_code
                    })
                    self.log(f"Auth required for path: {path}")

    def check_default_credentials(self):
        """Test for default credentials on auth-required paths"""
        if not self.results['auth_required']:
            return
        
        test_path = self.results['auth_required'][0]['path']
        
        for username, password in self.DEFAULT_CREDENTIALS:
            self.log(f"Testing credentials: {username}:{password}")
            self.results['credentials_tested'].append(f"{username}:{password}")
            
            response = self.request(test_path, auth=(username, password))
            if response and response.status_code == 200:
                self.results['valid_credentials'].append({
                    'username': username,
                    'password': password,
                    'path': test_path
                })
                self.log(f"Valid credentials found: {username}:{password}")

    def check_vulnerabilities(self):
        """Check for known vulnerabilities"""
        for vuln_id, vuln_info in self.VULNERABILITIES.items():
            self.log(f"Checking for {vuln_id}: {vuln_info['name']}")
            response = self.request(vuln_info['path'])
            
            if response and vuln_info['check'](response):
                self.results['vulnerabilities'].append({
                    'id': vuln_id,
                    'name': vuln_info['name'],
                    'path': vuln_info['path'],
                    'confirmed': True
                })
                self.log(f"Vulnerability found: {vuln_id}")

    def check_exposed_apis(self):
        """Check for exposed APIs and services"""
        # Check for exposed query builder
        response = self.request('/bin/querybuilder.json?path=/content&p.limit=-1')
        if response and response.status_code == 200 and 'results' in response.text:
            self.results['exposed_apis'].append({
                'name': 'Query Builder API',
                'path': '/bin/querybuilder.json',
                'severity': 'High'
            })
            
            # Store some query results
            try:
                data = response.json()
                if 'hits' in data:
                    for hit in data.get('hits', [])[:10]:  # Limit to first 10 results
                        self.results['query_results'].append(hit)
            except json.JSONDecodeError:
                pass
        
        # Check for content nodes exposure
        response = self.request('/content.json')
        if response and response.status_code == 200:
            self.results['exposed_apis'].append({
                'name': 'Content API',
                'path': '/content.json',
                'severity': 'Medium'
            })
            
            # Store some content nodes
            try:
                data = response.json()
                if isinstance(data, dict):
                    for key, value in list(data.items())[:10]:  # Limit to first 10 nodes
                        self.results['content_nodes'].append({
                            'path': f'/content/{key}',
                            'type': value.get('jcr:primaryType', 'unknown') if isinstance(value, dict) else 'unknown'
                        })
            except (json.JSONDecodeError, AttributeError):
                pass

    def check_post_servlet(self):
        """Check if POST servlet is accessible"""
        test_data = {
            'sling:resourceType': 'sling:Folder',
            './jcr:primaryType': 'nt:unstructured',
            './text': 'SlingAuditorTest',
            ':operation': 'import'
        }
        
        # Try to create a test node
        response = self.request('/content/slingauditortest', 
                               method='POST', 
                               data=test_data)
        
        if response and response.status_code in [200, 201]:
            self.results['exposed_apis'].append({
                'name': 'POST Servlet (Content Creation)',
                'path': '/content/*',
                'severity': 'Critical'
            })
            self.log("POST servlet is exposed and allows content creation")
            
            # Clean up - try to delete the test node
            delete_data = {':operation': 'delete'}
            self.request('/content/slingauditortest', method='POST', data=delete_data)

    def check_configuration_issues(self):
        """Check for misconfigured security settings"""
        self.log("Checking for configuration issues")
        
        # Check for OSGI configuration issues
        response = self.request('/system/console/configMgr')
        if response and response.status_code == 200:
            config_issues = []
            
            # Check for exposed error handler config
            if 'org.apache.sling.commons.log.LogManager' in response.text:
                config_issues.append({
                    'name': 'Log Manager Configuration Exposed',
                    'severity': 'Medium',
                    'description': 'Log configuration is accessible which can reveal sensitive information'
                })
            
            # Check for dispatcher config
            if 'com.day.cq.wcm.foundation.forms.impl.MailServlet' in response.text:
                config_issues.append({
                    'name': 'Mail Servlet Configuration Exposed',
                    'severity': 'Medium',
                    'description': 'Mail servlet configuration is accessible which can reveal SMTP credentials'
                })
                
            self.results['security_findings'].extend(config_issues)

    def check_jcr_structure(self):
        """Map the JCR structure and look for sensitive paths"""
        self.log("Checking JCR structure for sensitive information")
        
        # Define sensitive paths to check
        sensitive_paths = [
            '/etc/keys',
            '/etc/map',
            '/etc/passwords',
            '/etc/replication',
            '/home/users/system',
            '/apps/system',
            '/var/audit'
        ]
        
        # Check each path
        for path in sensitive_paths:
            json_path = f"{path}.json"
            response = self.request(json_path)
            
            if response and response.status_code == 200:
                try:
                    data = response.json()
                    self.results['jcr_structure'][path] = {
                        'accessible': True,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'size': len(response.content)
                    }
                    
                    # If this is a sensitive path, add it to security findings
                    self.results['security_findings'].append({
                        'name': 'Sensitive JCR Path Exposed',
                        'severity': 'High',
                        'description': f"Sensitive JCR path {path} is publicly accessible",
                        'path': json_path
                    })
                except json.JSONDecodeError:
                    # Not valid JSON but still accessible
                    self.results['jcr_structure'][path] = {
                        'accessible': True,
                        'content_type': response.headers.get('Content-Type', 'unknown'),
                        'size': len(response.content),
                        'valid_json': False
                    }
            else:
                # Path not accessible
                self.results['jcr_structure'][path] = {
                    'accessible': False,
                    'status_code': response.status_code if response else None
                }

    def run_audit(self, mode='full'):
        """Run the complete Sling audit"""
        self.log(f"Starting audit of {self.target_url} in {mode} mode")
        start_time = time.time()
        self.results['scan_time']['start'] = start_time
        
        # First detect if this is actually a Sling instance
        if not self.detect_sling():
            self.log("Target does not appear to be running Apache Sling", "WARNING")
            self.results['is_sling'] = False
            
            # Record scan time
            end_time = time.time()
            self.results['scan_time']['end'] = end_time
            self.results['scan_time']['duration'] = end_time - start_time
            return self.results
        
        self.log(f"Apache Sling detected with {self.results.get('detection_confidence', 0)}% confidence")
        
        # Run version detection
        self.detect_version()
        self.log(f"Version detected: {self.results.get('version') or 'Unknown'}")
        
        # Check accessible paths
        self.check_paths()
        self.log(f"Found {len(self.results['accessible_paths'])} accessible paths")
        
        # Only test credentials if we're not already authenticated
        if not (self.username and self.password) and self.results['auth_required']:
            self.check_default_credentials()
            
            if self.results['valid_credentials']:
                self.log(f"Found {len(self.results['valid_credentials'])} valid credentials")
                
                # Use the first valid credentials for further requests
                creds = self.results['valid_credentials'][0]
                self.username = creds['username']
                self.password = creds['password']
                self.log(f"Using discovered credentials: {self.username}:{self.password}")
        
        # Run basic checks
        self.check_vulnerabilities()
        self.check_exposed_apis()
        
        # Run more intensive checks if in full mode
        if mode in ['full', 'complete']:
            self.log("Running comprehensive checks in full mode")
            self.check_post_servlet()
            self.check_configuration_issues()
            self.check_jcr_structure()
        
        # Record scan completion time
        end_time = time.time()
        self.results['scan_time']['end'] = end_time
        self.results['scan_time']['duration'] = end_time - start_time
        
        self.log(f"Audit completed in {end_time - start_time:.2f} seconds")
        return self.results


def main():
    """Main entry point for the script"""
    parser = argparse.ArgumentParser(description='Apache Sling Security Auditor')
    parser.add_argument('-t', '--target', required=True, help='Target URL (e.g., http://example.com:4502)')
    parser.add_argument('-u', '--username', help='Username for authentication')
    parser.add_argument('-p', '--password', help='Password for authentication')
    parser.add_argument('-o', '--output', help='Output file for JSON results')
    parser.add_argument('-T', '--timeout', type=int, default=10, help='Request timeout in seconds')
    parser.add_argument('-k', '--insecure', action='store_true', help='Allow insecure connections')
    parser.add_argument('-v', '--verbose', action='store_true', help='Enable verbose output')
    parser.add_argument('--proxy', help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--mode', choices=['quick', 'full', 'stealth'], default='full',
                      help='Scan mode: quick (basic checks), full (all checks), stealth (minimal footprint)')
    args = parser.parse_args()

    # Validate URL
    if not urlparse(args.target).scheme:
        print("Error: Target URL must include scheme (http:// or https://)")
        sys.exit(1)

    print(r"""
    ___   ____    _   __   ____       ___   __  __  ____   ____  ______  ____    ____  
   /   | / __ \  / | / /  / __ \     /   | / / / / / __ \ /  _/ /_  __/ / __ \  / __ \ 
  / /| |/ /_/ / /  |/ /  / /_/ /    / /| |/ / / / / / / / / /    / /   / / / / / /_/ / 
 / ___ / ____/ / /|  /  / _, _/    / ___ / /_/ / / /_/ /_/ /    / /   / /_/ / / _, _/  
/_/  |_/_/     /_/ |_/  /_/ |_|   /_/  |_\____/  \____//___/   /_/    \____/ /_/ |_|   
                                                                                        
  Apache Sling/AEM Security Auditor v1.0                             
    """)

    print(f"[*] Target: {args.target}")
    if args.username:
        print(f"[*] Authenticating as: {args.username}")
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}")
    
    print("[*] Starting scan...")
    
    # Run the audit
    auditor = SlingAuditor(
        target_url=args.target,
        username=args.username,
        password=args.password,
        timeout=args.timeout,
        verify_ssl=not args.insecure,
        verbose=args.verbose,
        proxy=args.proxy
    )
    
    results = auditor.run_audit(mode=args.mode)
    
    # Calculate scan duration
    duration = results['scan_time']['duration']
    duration_str = f"{duration:.2f}s" if duration < 60 else f"{duration/60:.2f}m"
    
    # Print summary to console
    print("\n=== Apache Sling Audit Results ===")
    print(f"Target: {results['target']}")
    print(f"Scan Duration: {duration_str}")
    print(f"Is Sling Instance: {results['is_sling']}")
    
    if results['is_sling']:
        print(f"Version: {results['version'] or 'Unknown'}")
        print(f"Detection Confidence: {results.get('detection_confidence', 'Unknown')}%")
        print(f"Accessible Paths: {len(results['accessible_paths'])}")
        print(f"Auth Required Paths: {len(results['auth_required'])}")
        print(f"Valid Credentials: {len(results['valid_credentials'])}")
        print(f"Security Findings: {len(results['security_findings'])}")
        print(f"Vulnerabilities: {len(results['vulnerabilities'])}")
        print(f"Exposed APIs: {len(results['exposed_apis'])}")
        
        # Show high severity findings
        high_severity = [f for f in results['security_findings'] 
                         if f.get('severity') in ['Critical', 'High']]
        if high_severity:
            print("\n=== High Severity Findings ===")
            for finding in high_severity:
                print(f"[{finding.get('severity', 'Unknown')}] {finding.get('name')}")
                if 'path' in finding:
                    print(f"  Path: {finding['path']}")
                print(f"  {finding.get('description', '')}")
    
    # Save results to file if requested
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        print(f"\nDetailed results saved to {args.output}")

if __name__ == '__main__':
    main()
