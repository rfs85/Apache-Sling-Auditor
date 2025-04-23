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
import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Union
from urllib.parse import urljoin, urlparse

import aiohttp
import requests
import yaml
from bs4 import BeautifulSoup
from colorama import Fore, Style, init
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from tqdm import tqdm

# Initialize colorama for cross-platform colored output
init()

class SlingAuditor:
    """Apache Sling security auditor with enhanced features"""

    def __init__(self, target_url: str, username: Optional[str] = None, password: Optional[str] = None,
                 timeout: int = 10, verify_ssl: bool = False, verbose: bool = False, 
                 threads: int = 5, user_agent: Optional[str] = None, cookies: Optional[Union[str, dict]] = None,
                 proxy: Optional[str] = None, output_dir: Optional[str] = None):
        """Initialize the auditor with enhanced configuration"""
        self.target_url = target_url.rstrip('/')
        self.username = username
        self.password = password
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.verbose = verbose
        self.threads = threads
        self.proxy = proxy
        self.output_dir = output_dir or 'scan_results'
        
        # Create output directory if it doesn't exist
        Path(self.output_dir).mkdir(parents=True, exist_ok=True)
        
        # Initialize rich console for better output
        self.console = Console()
        
        # Setup async session for concurrent requests
        self.async_session = None
        self.semaphore = asyncio.Semaphore(threads)
        
        # Setup regular session
        self.session = requests.Session()
        self.setup_session(user_agent, cookies)
        
        # Load configuration
        self.config = self.load_config()
        
        # Initialize results dictionary
        self.results = self.initialize_results()

    def load_config(self) -> dict:
        """Load configuration from YAML file"""
        config_path = Path(__file__).parent / 'config' / 'audit_config.yaml'
        if config_path.exists():
            with open(config_path) as f:
                return yaml.safe_load(f)
        return {}

    def initialize_results(self) -> dict:
        """Initialize results dictionary with enhanced structure"""
        return {
            'scan_info': {
                'target': self.target_url,
                'start_time': datetime.now().isoformat(),
                'end_time': None,
                'duration': None,
                'scan_mode': None
            },
            'target_info': {
                'is_sling': False,
                'version': None,
                'product_info': {},
                'detection_confidence': 0
            },
            'security_findings': {
                'critical': [],
                'high': [],
                'medium': [],
                'low': [],
                'info': []
            },
            'vulnerabilities': [],
            'exposed_apis': [],
            'authentication': {
                'auth_required_paths': [],
                'credentials_tested': [],
                'valid_credentials': []
            },
            'configuration': {
                'osgi_configs': [],
                'dispatcher_config': {},
                'replication_agents': []
            },
            'content_security': {
                'exposed_paths': [],
                'sensitive_content': [],
                'jcr_structure': {}
            }
        }

    def setup_session(self, user_agent: Optional[str], cookies: Optional[Union[str, dict]]) -> None:
        """Setup session with enhanced security headers"""
        self.session.headers.update({
            'User-Agent': user_agent or 'SlingAuditor/2.0',
            'Accept': '*/*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'close',
            'Cache-Control': 'no-cache',
            'Pragma': 'no-cache'
        })
        
        if cookies:
            if isinstance(cookies, str):
                cookie_dict = dict(item.split('=', 1) for item in cookies.split(';') if '=' in item)
                self.session.cookies.update(cookie_dict)
            elif isinstance(cookies, dict):
                self.session.cookies.update(cookies)
        
        if self.proxy:
            self.session.proxies = {
                'http': self.proxy,
                'https': self.proxy
            }

    async def setup_async_session(self) -> None:
        """Setup async session for concurrent requests"""
        if not self.async_session:
            timeout = aiohttp.ClientTimeout(total=self.timeout)
            connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
            self.async_session = aiohttp.ClientSession(
                connector=connector,
                timeout=timeout,
                headers=self.session.headers,
                cookies=self.session.cookies
            )

    def log(self, message: str, level: str = "INFO", color: str = Fore.WHITE) -> None:
        """Enhanced logging with color support"""
        if self.verbose or level in ["ERROR", "CRITICAL"]:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            log_message = f"[{timestamp}] [{level}] {message}"
            print(f"{color}{log_message}{Style.RESET_ALL}")

    async def async_request(self, path: str, method: str = 'GET', **kwargs) -> Optional[aiohttp.ClientResponse]:
        """Make an async request with error handling"""
        url = urljoin(self.target_url, path)
        async with self.semaphore:
            try:
                async with self.async_session.request(method, url, **kwargs) as response:
                    return response
            except Exception as e:
                self.log(f"Request error: {url} - {str(e)}", "ERROR", Fore.RED)
                return None

    def add_finding(self, finding: dict) -> None:
        """Add a security finding with proper categorization"""
        severity = finding.get('severity', 'info').lower()
        if severity in self.results['security_findings']:
            self.results['security_findings'][severity].append(finding)
            
            if severity in ['critical', 'high']:
                self.log(
                    f"Found {severity.upper()} severity issue: {finding['name']}",
                    "CRITICAL" if severity == 'critical' else "HIGH",
                    Fore.RED if severity == 'critical' else Fore.YELLOW
                )

    async def check_paths_concurrently(self, paths: List[str]) -> None:
        """Check multiple paths concurrently"""
        async def check_single_path(path: str) -> None:
            response = await self.async_request(path)
            if response:
                if response.status == 200:
                    self.results['content_security']['exposed_paths'].append({
                        'path': path,
                        'status': response.status,
                        'content_type': response.headers.get('Content-Type', 'unknown')
                    })
                elif response.status in [401, 403]:
                    self.results['authentication']['auth_required_paths'].append({
                        'path': path,
                        'status': response.status
                    })

        await asyncio.gather(*[check_single_path(path) for path in paths])

    async def run_security_checks(self) -> None:
        """Run comprehensive security checks concurrently"""
        # Implement security checks here
        pass

    def generate_report(self) -> None:
        """Generate comprehensive security report"""
        # Create report directory
        report_dir = Path(self.output_dir) / datetime.now().strftime("%Y%m%d_%H%M%S")
        report_dir.mkdir(parents=True, exist_ok=True)
        
        # Save detailed JSON report
        json_report = report_dir / "detailed_report.json"
        with open(json_report, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate HTML report
        self.generate_html_report(report_dir)
        
        # Generate summary report
        self.generate_summary_report(report_dir)

    def generate_html_report(self, report_dir: Path) -> None:
        """Generate HTML report with enhanced visualization"""
        # Implement HTML report generation
        pass

    def generate_summary_report(self, report_dir: Path) -> None:
        """Generate executive summary report"""
        # Implement summary report generation
        pass

    async def run_audit(self, mode: str = 'full') -> dict:
        """Run the complete Sling audit with async support"""
        self.results['scan_info']['scan_mode'] = mode
        start_time = time.time()
        
        try:
            # Setup async session
            await self.setup_async_session()
            
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                # Run security checks based on mode
                if mode == 'quick':
                    await self.run_quick_scan(progress)
                elif mode == 'stealth':
                    await self.run_stealth_scan(progress)
                else:
                    await self.run_full_scan(progress)
            
        finally:
            if self.async_session:
                await self.async_session.close()
            
            # Record scan completion
            end_time = time.time()
            self.results['scan_info']['end_time'] = datetime.now().isoformat()
            self.results['scan_info']['duration'] = end_time - start_time
            
            # Generate reports
            self.generate_report()
        
        return self.results

    async def run_quick_scan(self, progress) -> None:
        """Run a quick scan with basic checks"""
        task1 = progress.add_task("Running quick scan...", total=3)
        
        # Version detection
        progress.update(task1, advance=1, description="Checking version...")
        await self.check_version()
        
        # Basic auth check
        progress.update(task1, advance=1, description="Checking basic auth...")
        await self.check_basic_auth()
        
        # Critical vulnerabilities
        progress.update(task1, advance=1, description="Checking critical vulnerabilities...")
        await self.check_critical_vulnerabilities()

    async def run_stealth_scan(self, progress) -> None:
        """Run a stealth scan with minimal footprint"""
        task1 = progress.add_task("Running stealth scan...", total=3)
        
        # Passive version detection
        progress.update(task1, advance=1, description="Passive version detection...")
        await self.check_version_passive()
        
        # Basic auth check with delays
        progress.update(task1, advance=1, description="Checking authentication...")
        await self.check_basic_auth(stealth=True)
        
        # Safe checks only
        progress.update(task1, advance=1, description="Running safe checks...")
        await self.run_safe_checks()

    async def run_full_scan(self, progress) -> None:
        """Run a comprehensive security scan"""
        # Create progress tasks for each major check category
        tasks = {
            'version': progress.add_task("Version detection...", total=100),
            'auth': progress.add_task("Authentication checks...", total=100),
            'vulns': progress.add_task("Vulnerability scanning...", total=100),
            'apis': progress.add_task("API enumeration...", total=100),
            'config': progress.add_task("Configuration audit...", total=100),
            'content': progress.add_task("Content security...", total=100)
        }
        
        # Run checks concurrently
        await asyncio.gather(
            self.check_version_full(tasks['version'], progress),
            self.check_authentication(tasks['auth'], progress),
            self.check_vulnerabilities_full(tasks['vulns'], progress),
            self.check_exposed_apis_full(tasks['apis'], progress),
            self.check_configuration_full(tasks['config'], progress),
            self.check_content_security(tasks['content'], progress)
        )

    async def check_version(self) -> None:
        """Basic version detection"""
        paths = [
            '/system/console/productinfo',
            '/libs/cq/core/content/welcome.html'
        ]
        
        for path in paths:
            response = await self.async_request(path)
            if response and response.status == 200:
                text = await response.text()
                # Check for version indicators
                version_match = re.search(r'Adobe Experience Manager \(([^)]+)\)', text)
                if version_match:
                    self.results['target_info']['version'] = version_match.group(1)
                    return

    async def check_version_passive(self) -> None:
        """Passive version detection without direct probing"""
        response = await self.async_request('/')
        if response:
            headers = response.headers
            server = headers.get('Server', '')
            powered_by = headers.get('X-Powered-By', '')
            
            if any(indicator in server + powered_by for indicator in ['Adobe', 'Day-Servlet', 'CQ']):
                self.results['target_info']['is_sling'] = True
                self.add_finding({
                    'name': 'Version Information Disclosure',
                    'severity': 'low',
                    'description': f'Server headers reveal technology: {server} {powered_by}'
                })

    async def check_version_full(self, task, progress) -> None:
        """Comprehensive version detection"""
        progress.update(task, advance=20, description="Checking product info...")
        await self.check_version()
        
        progress.update(task, advance=20, description="Analyzing response headers...")
        await self.check_version_passive()
        
        progress.update(task, advance=20, description="Checking additional endpoints...")
        # Add more version detection methods
        
        progress.update(task, advance=40, description="Version detection complete")

    async def check_basic_auth(self, stealth: bool = False) -> None:
        """Check for basic authentication issues"""
        if stealth:
            await asyncio.sleep(2)  # Add delay for stealth mode
        
        auth_paths = self.config.get('paths', {}).get('core_endpoints', [])
        for endpoint in auth_paths:
            response = await self.async_request(endpoint['path'])
            if response and response.status in [401, 403]:
                self.results['authentication']['auth_required_paths'].append({
                    'path': endpoint['path'],
                    'name': endpoint['name'],
                    'status': response.status
                })

    async def check_critical_vulnerabilities(self) -> None:
        """Check for critical vulnerabilities only"""
        critical_vulns = {k: v for k, v in self.config.get('vulnerabilities', {}).items() 
                         if v.get('severity') == 'critical'}
        
        for vuln_id, vuln_info in critical_vulns.items():
            response = await self.async_request(vuln_info['path'])
            if response and response.status == 200:
                self.add_finding({
                    'name': vuln_info['name'],
                    'severity': 'critical',
                    'vulnerability_id': vuln_id,
                    'path': vuln_info['path'],
                    'description': vuln_info['description'],
                    'remediation': vuln_info.get('remediation', '')
                })

    async def run_safe_checks(self) -> None:
        """Run only safe checks that won't impact the target"""
        safe_paths = [
            '/.json',
            '/libs/cq/core/content/welcome.html',
            '/content.json'
        ]
        
        for path in safe_paths:
            response = await self.async_request(path)
            if response and response.status == 200:
                self.add_finding({
                    'name': f'Exposed Endpoint: {path}',
                    'severity': 'low',
                    'description': f'The endpoint {path} is publicly accessible'
                })

    async def check_authentication(self, task, progress) -> None:
        """Comprehensive authentication checks"""
        progress.update(task, advance=20, description="Testing default credentials...")
        
        # Test default credentials
        for cred in self.config.get('credentials', []):
            if self.results['authentication']['auth_required_paths']:
                test_path = self.results['authentication']['auth_required_paths'][0]['path']
                response = await self.async_request(
                    test_path,
                    auth=aiohttp.BasicAuth(cred['username'], cred['password'])
                )
                if response and response.status == 200:
                    self.results['authentication']['valid_credentials'].append({
                        'username': cred['username'],
                        'password': cred['password'],
                        'description': cred['description']
                    })
        
        progress.update(task, advance=40, description="Checking session handling...")
        # Add session handling checks
        
        progress.update(task, advance=40, description="Authentication checks complete")

    async def check_vulnerabilities_full(self, task, progress) -> None:
        """Comprehensive vulnerability scanning"""
        progress.update(task, advance=30, description="Checking known vulnerabilities...")
        
        # Check all vulnerabilities from config
        for vuln_id, vuln_info in self.config.get('vulnerabilities', {}).items():
            response = await self.async_request(vuln_info['path'])
            if response and response.status == 200:
                self.add_finding({
                    'name': vuln_info['name'],
                    'severity': vuln_info['severity'],
                    'vulnerability_id': vuln_id,
                    'path': vuln_info['path'],
                    'description': vuln_info['description'],
                    'remediation': vuln_info.get('remediation', '')
                })
        
        progress.update(task, advance=70, description="Vulnerability scan complete")

    async def check_exposed_apis_full(self, task, progress) -> None:
        """Check for exposed APIs and services"""
        progress.update(task, advance=30, description="Checking API endpoints...")
        
        api_endpoints = self.config.get('paths', {}).get('api_endpoints', [])
        for endpoint in api_endpoints:
            response = await self.async_request(endpoint['path'])
            if response and response.status == 200:
                self.results['exposed_apis'].append({
                    'name': endpoint['name'],
                    'path': endpoint['path'],
                    'severity': endpoint['severity']
                })
        
        progress.update(task, advance=70, description="API enumeration complete")

    async def check_configuration_full(self, task, progress) -> None:
        """Check for configuration issues"""
        progress.update(task, advance=30, description="Checking OSGI configuration...")
        
        if self.config['security_checks']['configuration']['check_dispatcher']:
            # Check dispatcher configuration
            response = await self.async_request('/dispatcher/invalidate.cache')
            if response and response.status == 200:
                self.add_finding({
                    'name': 'Exposed Dispatcher Configuration',
                    'severity': 'high',
                    'description': 'Dispatcher invalidation endpoint is accessible'
                })
        
        progress.update(task, advance=70, description="Configuration audit complete")

    async def check_content_security(self, task, progress) -> None:
        """Check for content security issues"""
        progress.update(task, advance=30, description="Checking sensitive content...")
        
        sensitive_paths = self.config.get('paths', {}).get('sensitive_paths', [])
        for path_info in sensitive_paths:
            if path_info['path'] not in self.config['security_checks']['content_security']['exclude_paths']:
                response = await self.async_request(f"{path_info['path']}.json")
                if response and response.status == 200:
                    self.add_finding({
                        'name': f'Exposed Sensitive Content: {path_info["name"]}',
                        'severity': path_info['severity'],
                        'path': path_info['path'],
                        'description': f'Sensitive path {path_info["path"]} is publicly accessible'
                    })
        
        progress.update(task, advance=70, description="Content security scan complete")

def main():
    """Enhanced main entry point with better argument handling"""
    parser = argparse.ArgumentParser(
        description='Apache Sling Security Auditor',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Add command line arguments
    parser.add_argument('-t', '--target', required=True,
                      help='Target URL (e.g., http://example.com:4502)')
    parser.add_argument('-u', '--username',
                      help='Username for authentication')
    parser.add_argument('-p', '--password',
                      help='Password for authentication')
    parser.add_argument('-o', '--output',
                      help='Output directory for scan results')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                      help='Request timeout in seconds')
    parser.add_argument('-k', '--insecure', action='store_true',
                      help='Allow insecure SSL connections')
    parser.add_argument('-v', '--verbose', action='store_true',
                      help='Enable verbose output')
    parser.add_argument('--threads', type=int, default=5,
                      help='Number of concurrent threads')
    parser.add_argument('--proxy',
                      help='Proxy URL (e.g., http://127.0.0.1:8080)')
    parser.add_argument('--mode', choices=['quick', 'full', 'stealth'],
                      default='full',
                      help='Scan mode: quick, full, or stealth')
    parser.add_argument('--user-agent',
                      help='Custom User-Agent string')
    parser.add_argument('--cookies',
                      help='Cookies to include with requests')
    
    args = parser.parse_args()

    # Validate URL
    if not urlparse(args.target).scheme:
        print(f"{Fore.RED}Error: Target URL must include scheme (http:// or https://){Style.RESET_ALL}")
        sys.exit(1)

    # Display banner
    print(r"""
    ___   ____    _   __   ____       ___   __  __  ____   ____  ______  ____    ____  
   /   | / __ \  / | / /  / __ \     /   | / / / / / __ \ /  _/ /_  __/ / __ \  / __ \ 
  / /| |/ /_/ / /  |/ /  / /_/ /    / /| |/ / / / / / / / / /    / /   / / / / / /_/ / 
 / ___ / ____/ / /|  /  / _, _/    / ___ / /_/ / / /_/ /_/ /    / /   / /_/ / / _, _/  
/_/  |_/_/     /_/ |_/  /_/ |_|   /_/  |_\____/  \____//___/   /_/    \____/ /_/ |_|   
                                                                                        
  Apache Sling/AEM Security Auditor v2.0                             
    """)

    print(f"{Fore.CYAN}[*] Target: {args.target}")
    if args.username:
        print(f"[*] Authenticating as: {args.username}")
    if args.proxy:
        print(f"[*] Using proxy: {args.proxy}")
    print(f"[*] Scan mode: {args.mode}{Style.RESET_ALL}")
    
    try:
        # Create and run auditor
        auditor = SlingAuditor(
            target_url=args.target,
            username=args.username,
            password=args.password,
            timeout=args.timeout,
            verify_ssl=not args.insecure,
            verbose=args.verbose,
            threads=args.threads,
            user_agent=args.user_agent,
            cookies=args.cookies,
            proxy=args.proxy,
            output_dir=args.output
        )
        
        # Run audit using asyncio
        results = asyncio.run(auditor.run_audit(mode=args.mode))
        
        # Display summary
        print(f"\n{Fore.GREEN}=== Scan Complete ==={Style.RESET_ALL}")
        print(f"Duration: {results['scan_info']['duration']:.2f} seconds")
        print(f"Results saved to: {args.output or 'scan_results'}")
        
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}Scan interrupted by user{Style.RESET_ALL}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == '__main__':
    main()
