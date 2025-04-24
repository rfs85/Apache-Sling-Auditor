#!/usr/bin/env python3
"""
Security Header Testing Script for Apache Sling/AEM
This script tests various security headers and their combinations against a target.
"""

import asyncio
import json
from pathlib import Path
from typing import Dict, List, Optional
from urllib.parse import urljoin

import aiohttp
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table

class HeaderTester:
    def __init__(self, target_url: str, output_dir: str = 'scan_results/headers',
                 timeout: int = 10, verify_ssl: bool = False):
        self.target_url = target_url.rstrip('/')
        self.output_dir = Path(output_dir)
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        self.console = Console()
        self.results = {
            'missing_security_headers': [],
            'information_disclosure': [],
            'security_bypass_successful': [],
            'vulnerable_headers': [],
            'interesting_responses': []
        }
        
        # Create output directory
        self.output_dir.mkdir(parents=True, exist_ok=True)

    async def setup_session(self) -> aiohttp.ClientSession:
        """Setup aiohttp session with timeout"""
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        connector = aiohttp.TCPConnector(verify_ssl=self.verify_ssl)
        return aiohttp.ClientSession(connector=connector, timeout=timeout)

    def parse_headers_file(self) -> Dict[str, List[str]]:
        """Parse the security_headers.txt file"""
        headers = {}
        current_category = None
        
        headers_file = Path(__file__).parent / 'security_headers.txt'
        with open(headers_file, 'r') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    if line.startswith('# '):
                        current_category = line[2:].lower().replace(' ', '_')
                        headers[current_category] = []
                    continue
                
                if current_category and ':' in line:
                    header, value = map(str.strip, line.split(':', 1))
                    headers[current_category].append((header, value))
                elif current_category and line.startswith('  - '):
                    headers[current_category].append(line[4:])
        
        return headers

    async def test_header(self, session: aiohttp.ClientSession, 
                         header: str, value: str, path: str = '/') -> dict:
        """Test a single header"""
        url = urljoin(self.target_url, path)
        try:
            async with session.get(url, headers={header: value}) as response:
                return {
                    'header': header,
                    'value': value,
                    'status': response.status,
                    'response_headers': dict(response.headers),
                    'path': path
                }
        except Exception as e:
            return {
                'header': header,
                'value': value,
                'error': str(e),
                'path': path
            }

    async def test_header_injection(self, session: aiohttp.ClientSession, 
                                  injection: str, path: str = '/') -> dict:
        """Test header injection"""
        url = urljoin(self.target_url, path)
        headers = {}
        
        # Split the injection into lines and create headers
        for line in injection.split('\\r\\n'):
            if ':' in line:
                header, value = map(str.strip, line.split(':', 1))
                headers[header] = value
        
        try:
            async with session.get(url, headers=headers) as response:
                return {
                    'injection': injection,
                    'status': response.status,
                    'response_headers': dict(response.headers),
                    'path': path
                }
        except Exception as e:
            return {
                'injection': injection,
                'error': str(e),
                'path': path
            }

    def analyze_response_headers(self, response_headers: dict) -> List[dict]:
        """Analyze response headers for security issues"""
        issues = []
        
        # Check for missing security headers
        required_headers = {
            'X-Frame-Options',
            'X-Content-Type-Options',
            'X-XSS-Protection',
            'Content-Security-Policy',
            'Strict-Transport-Security'
        }
        
        for header in required_headers:
            if header not in response_headers:
                issues.append({
                    'type': 'missing_header',
                    'header': header,
                    'severity': 'medium',
                    'description': f'Missing security header: {header}'
                })
        
        # Check for information disclosure
        info_headers = {
            'Server',
            'X-Powered-By',
            'X-AspNet-Version',
            'X-AspNetMvc-Version'
        }
        
        for header in info_headers:
            if header in response_headers:
                issues.append({
                    'type': 'information_disclosure',
                    'header': header,
                    'value': response_headers[header],
                    'severity': 'low',
                    'description': f'Information disclosure through {header} header'
                })
        
        return issues

    async def run_tests(self) -> dict:
        """Run all header tests"""
        headers_config = self.parse_headers_file()
        
        async with await self.setup_session() as session:
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                console=self.console
            ) as progress:
                # Test standard security headers
                task1 = progress.add_task("Testing standard security headers...", total=100)
                for header, value in headers_config.get('standard_security_headers', []):
                    result = await self.test_header(session, header, value)
                    if 'error' not in result:
                        issues = self.analyze_response_headers(result['response_headers'])
                        self.results['missing_security_headers'].extend(issues)
                    progress.advance(task1)
                
                # Test AEM/Sling specific headers
                task2 = progress.add_task("Testing AEM/Sling headers...", total=100)
                for header, value in headers_config.get('aem_sling_specific_headers', []):
                    result = await self.test_header(session, header, value)
                    if 'error' not in result:
                        if result['status'] in [200, 401, 403]:
                            self.results['information_disclosure'].append(result)
                    progress.advance(task2)
                
                # Test security bypass headers
                task3 = progress.add_task("Testing security bypass headers...", total=100)
                for header, value in headers_config.get('security_bypass_headers_to_test', []):
                    result = await self.test_header(session, header, value, '/system/console')
                    if 'error' not in result and result['status'] == 200:
                        self.results['security_bypass_successful'].append(result)
                    progress.advance(task3)
                
                # Test header injection
                task4 = progress.add_task("Testing header injection...", total=100)
                for injection in headers_config.get('header_injection_tests', []):
                    result = await self.test_header_injection(session, injection)
                    if 'error' not in result and result['status'] == 200:
                        self.results['vulnerable_headers'].append(result)
                    progress.advance(task4)
        
        return self.results

    def generate_report(self) -> None:
        """Generate a detailed report of findings"""
        # Save JSON report
        report_file = self.output_dir / 'header_security_report.json'
        with open(report_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        # Generate console report
        self.console.print("\n[bold]Header Security Test Results[/bold]")
        
        # Missing Security Headers
        if self.results['missing_security_headers']:
            table = Table(title="Missing Security Headers")
            table.add_column("Header")
            table.add_column("Severity")
            table.add_column("Description")
            
            for issue in self.results['missing_security_headers']:
                table.add_row(
                    issue['header'],
                    issue['severity'],
                    issue['description']
                )
            self.console.print(table)
        
        # Information Disclosure
        if self.results['information_disclosure']:
            table = Table(title="Information Disclosure")
            table.add_column("Header")
            table.add_column("Value")
            
            for issue in self.results['information_disclosure']:
                table.add_row(
                    issue['header'],
                    issue['value']
                )
            self.console.print(table)
        
        # Security Bypass
        if self.results['security_bypass_successful']:
            table = Table(title="Successful Security Bypasses")
            table.add_column("Header")
            table.add_column("Value")
            table.add_column("Path")
            
            for issue in self.results['security_bypass_successful']:
                table.add_row(
                    issue['header'],
                    issue['value'],
                    issue['path']
                )
            self.console.print(table)
        
        self.console.print(f"\nDetailed report saved to: {report_file}")

async def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Test security headers against Apache Sling/AEM target'
    )
    parser.add_argument('-t', '--target', required=True,
                      help='Target URL (e.g., http://example.com:4502)')
    parser.add_argument('-o', '--output',
                      help='Output directory for results')
    parser.add_argument('-T', '--timeout', type=int, default=10,
                      help='Request timeout in seconds')
    parser.add_argument('-k', '--insecure', action='store_true',
                      help='Allow insecure SSL connections')
    
    args = parser.parse_args()
    
    tester = HeaderTester(
        target_url=args.target,
        output_dir=args.output or 'scan_results/headers',
        timeout=args.timeout,
        verify_ssl=not args.insecure
    )
    
    results = await tester.run_tests()
    tester.generate_report()

if __name__ == '__main__':
    asyncio.run(main()) 