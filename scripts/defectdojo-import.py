#!/usr/bin/env python3
"""
DefectDojo Integration Script

Imports security findings from various tools into DefectDojo for centralized
vulnerability management, tracking, and reporting.

Author: Sunanda Mandal
"""

import json
import os
import sys
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional


class DefectDojoImporter:
    """
    Imports security findings into DefectDojo.
    
    DefectDojo is an open-source vulnerability management tool that helps
    aggregate findings from multiple security tools, track remediation,
    and generate compliance reports.
    """
    
    def __init__(self, url: str, api_key: str, verify_ssl: bool = True):
        """
        Initialize DefectDojo client.
        
        Args:
            url: DefectDojo instance URL (e.g., https://defectdojo.example.com)
            api_key: API key for authentication
            verify_ssl: Whether to verify SSL certificates
        """
        self.url = url.rstrip('/')
        self.api_key = api_key
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Token {api_key}',
            'Content-Type': 'application/json'
        })
    
    def _request(self, method: str, endpoint: str, **kwargs) -> requests.Response:
        """Make API request to DefectDojo."""
        url = f"{self.url}/api/v2/{endpoint}"
        response = self.session.request(
            method, 
            url, 
            verify=self.verify_ssl,
            **kwargs
        )
        response.raise_for_status()
        return response
    
    def get_or_create_product(self, name: str, description: str = '') -> int:
        """
        Get existing product or create new one.
        
        Args:
            name: Product name
            description: Product description
            
        Returns:
            Product ID
        """
        # Search for existing product
        response = self._request('GET', 'products/', params={'name': name})
        results = response.json().get('results', [])
        
        if results:
            return results[0]['id']
        
        # Create new product
        response = self._request('POST', 'products/', json={
            'name': name,
            'description': description or f'Security scanning for {name}',
            'prod_type': 1  # Default product type
        })
        
        return response.json()['id']
    
    def get_or_create_engagement(
        self, 
        product_id: int, 
        name: str,
        target_start: str = None,
        target_end: str = None
    ) -> int:
        """
        Get existing engagement or create new one.
        
        Args:
            product_id: Product ID
            name: Engagement name
            target_start: Start date (ISO format)
            target_end: End date (ISO format)
            
        Returns:
            Engagement ID
        """
        # Search for existing engagement
        response = self._request(
            'GET', 
            'engagements/', 
            params={'product': product_id, 'name': name}
        )
        results = response.json().get('results', [])
        
        if results:
            return results[0]['id']
        
        # Create new engagement
        today = datetime.now().strftime('%Y-%m-%d')
        response = self._request('POST', 'engagements/', json={
            'name': name,
            'product': product_id,
            'target_start': target_start or today,
            'target_end': target_end or today,
            'engagement_type': 'CI/CD',
            'status': 'In Progress',
            'deduplication_on_engagement': True
        })
        
        return response.json()['id']
    
    def create_test(
        self,
        engagement_id: int,
        test_type: str,
        title: str,
        target_start: str = None,
        target_end: str = None
    ) -> int:
        """
        Create a new test within an engagement.
        
        Args:
            engagement_id: Engagement ID
            test_type: Type of test (e.g., 'SAST', 'SCA', 'DAST')
            title: Test title
            target_start: Start date
            target_end: End date
            
        Returns:
            Test ID
        """
        # Map test types to DefectDojo test types
        test_type_map = {
            'semgrep': 150,      # Semgrep JSON Report
            'bandit': 62,       # Bandit Scan
            'trivy': 199,       # Trivy Scan
            'safety': 90,       # Safety Scan
            'gitleaks': 163,    # Gitleaks Scan
            'checkov': 183,     # Checkov Scan
            'zap': 10,          # ZAP Scan
            'generic': 122      # Generic Findings Import
        }
        
        today = datetime.now().strftime('%Y-%m-%d')
        
        response = self._request('POST', 'tests/', json={
            'engagement': engagement_id,
            'test_type': test_type_map.get(test_type.lower(), 122),
            'title': title,
            'target_start': target_start or today,
            'target_end': target_end or today
        })
        
        return response.json()['id']
    
    def import_findings(
        self,
        test_id: int,
        findings: List[Dict[str, Any]],
        scan_type: str = 'Generic Findings Import'
    ) -> Dict[str, Any]:
        """
        Import findings into a test.
        
        Args:
            test_id: Test ID
            findings: List of finding dictionaries
            scan_type: Type of scan
            
        Returns:
            Import results
        """
        # Map severity levels
        severity_map = {
            'CRITICAL': 'Critical',
            'HIGH': 'High',
            'MEDIUM': 'Medium',
            'LOW': 'Low',
            'INFO': 'Info'
        }
        
        imported = 0
        errors = []
        
        for finding in findings:
            try:
                severity = severity_map.get(
                    finding.get('severity', 'MEDIUM').upper(), 
                    'Medium'
                )
                
                finding_data = {
                    'test': test_id,
                    'title': finding.get('title', 'Untitled Finding')[:200],
                    'description': self._build_description(finding),
                    'severity': severity,
                    'active': True,
                    'verified': False,
                    'duplicate': False,
                    'static_finding': finding.get('tool') in ['semgrep', 'bandit', 'checkov'],
                    'dynamic_finding': finding.get('tool') in ['zap', 'nuclei'],
                    'file_path': finding.get('file', ''),
                    'line': finding.get('line', 0),
                    'cwe': self._extract_cwe(finding),
                    'cvssv3': finding.get('cvss', {}).get('V3Score'),
                    'references': self._build_references(finding),
                    'mitigation': finding.get('remediation', ''),
                    'impact': self._build_impact(finding),
                    'unique_id_from_tool': finding.get('id', ''),
                    'vuln_id_from_tool': finding.get('rule_id', '')
                }
                
                self._request('POST', 'findings/', json=finding_data)
                imported += 1
                
            except Exception as e:
                errors.append({
                    'finding': finding.get('id', 'unknown'),
                    'error': str(e)
                })
        
        return {
            'imported': imported,
            'errors': errors,
            'total': len(findings)
        }
    
    def _build_description(self, finding: Dict[str, Any]) -> str:
        """Build finding description from various fields."""
        parts = []
        
        if finding.get('title'):
            parts.append(f"**Title:** {finding['title']}")
        
        if finding.get('description'):
            parts.append(f"\n**Description:**\n{finding['description']}")
        
        if finding.get('tool'):
            parts.append(f"\n**Detected by:** {finding['tool']}")
        
        if finding.get('rule_id'):
            parts.append(f"**Rule ID:** {finding['rule_id']}")
        
        if finding.get('file'):
            parts.append(f"\n**Location:** {finding['file']}")
            if finding.get('line'):
                parts[-1] += f" (line {finding['line']})"
        
        if finding.get('code_snippet'):
            parts.append(f"\n**Code:**\n```\n{finding['code_snippet'][:500]}\n```")
        
        if finding.get('package'):
            parts.append(f"\n**Package:** {finding['package']}")
            if finding.get('installed_version'):
                parts[-1] += f" v{finding['installed_version']}"
        
        if finding.get('fixed_version'):
            parts.append(f"**Fixed in:** {finding['fixed_version']}")
        
        return '\n'.join(parts)
    
    def _build_impact(self, finding: Dict[str, Any]) -> str:
        """Build impact description."""
        parts = []
        
        severity = finding.get('severity', 'MEDIUM')
        if severity in ['CRITICAL', 'HIGH']:
            parts.append("This vulnerability poses a significant risk and should be addressed immediately.")
        
        if finding.get('owasp'):
            parts.append(f"\nOWASP Category: {finding['owasp']}")
        
        if finding.get('cwe'):
            parts.append(f"CWE: {finding['cwe']}")
        
        return '\n'.join(parts) if parts else ''
    
    def _build_references(self, finding: Dict[str, Any]) -> str:
        """Build references string."""
        refs = []
        
        if finding.get('more_info'):
            refs.append(finding['more_info'])
        
        if finding.get('references'):
            refs.extend(finding['references'][:5])  # Limit to 5 references
        
        if finding.get('cve'):
            refs.append(f"https://nvd.nist.gov/vuln/detail/{finding['cve']}")
        
        return '\n'.join(refs)
    
    def _extract_cwe(self, finding: Dict[str, Any]) -> Optional[int]:
        """Extract CWE ID from finding."""
        cwe = finding.get('cwe', '')
        
        if isinstance(cwe, int):
            return cwe
        
        if isinstance(cwe, str):
            # Extract number from strings like "CWE-89" or "89"
            import re
            match = re.search(r'(\d+)', cwe)
            if match:
                return int(match.group(1))
        
        return None
    
    def reimport_scan(
        self,
        engagement_id: int,
        scan_type: str,
        file_path: str
    ) -> Dict[str, Any]:
        """
        Reimport scan results using DefectDojo's native import.
        
        This uses DefectDojo's built-in parsers for common tools.
        
        Args:
            engagement_id: Engagement ID
            scan_type: Type of scan (must match DefectDojo scan type name)
            file_path: Path to scan results file
            
        Returns:
            Import results
        """
        with open(file_path, 'rb') as f:
            response = self.session.post(
                f"{self.url}/api/v2/reimport-scan/",
                data={
                    'engagement': engagement_id,
                    'scan_type': scan_type,
                    'active': True,
                    'verified': False,
                    'close_old_findings': True,
                    'push_to_jira': False,
                    'minimum_severity': 'Info'
                },
                files={'file': f},
                verify=self.verify_ssl
            )
        
        response.raise_for_status()
        return response.json()


def main():
    parser = argparse.ArgumentParser(
        description='Import security findings into DefectDojo'
    )
    parser.add_argument(
        '--url',
        required=True,
        help='DefectDojo URL'
    )
    parser.add_argument(
        '--api-key',
        required=True,
        help='DefectDojo API key'
    )
    parser.add_argument(
        '--findings',
        required=True,
        help='Path to aggregated findings JSON file'
    )
    parser.add_argument(
        '--product',
        required=True,
        help='Product name in DefectDojo'
    )
    parser.add_argument(
        '--engagement',
        required=True,
        help='Engagement name'
    )
    parser.add_argument(
        '--no-verify-ssl',
        action='store_true',
        help='Disable SSL verification'
    )
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.findings, 'r') as f:
        data = json.load(f)
    
    findings = data.get('findings', [])
    
    if not findings:
        print("No findings to import")
        sys.exit(0)
    
    # Initialize importer
    importer = DefectDojoImporter(
        url=args.url,
        api_key=args.api_key,
        verify_ssl=not args.no_verify_ssl
    )
    
    try:
        # Get or create product
        print(f"Getting/creating product: {args.product}")
        product_id = importer.get_or_create_product(args.product)
        
        # Get or create engagement
        print(f"Getting/creating engagement: {args.engagement}")
        engagement_id = importer.get_or_create_engagement(
            product_id=product_id,
            name=args.engagement
        )
        
        # Group findings by tool
        findings_by_tool = {}
        for finding in findings:
            tool = finding.get('tool', 'generic')
            if tool not in findings_by_tool:
                findings_by_tool[tool] = []
            findings_by_tool[tool].append(finding)
        
        # Import findings for each tool
        total_imported = 0
        total_errors = 0
        
        for tool, tool_findings in findings_by_tool.items():
            print(f"\nImporting {len(tool_findings)} findings from {tool}...")
            
            # Create test for this tool
            test_id = importer.create_test(
                engagement_id=engagement_id,
                test_type=tool,
                title=f"{tool.title()} Scan - {datetime.now().strftime('%Y-%m-%d %H:%M')}"
            )
            
            # Import findings
            result = importer.import_findings(
                test_id=test_id,
                findings=tool_findings,
                scan_type=tool
            )
            
            total_imported += result['imported']
            total_errors += len(result['errors'])
            
            print(f"  ✓ Imported: {result['imported']}")
            if result['errors']:
                print(f"  ✗ Errors: {len(result['errors'])}")
        
        # Summary
        print(f"\n{'='*50}")
        print("IMPORT SUMMARY")
        print(f"{'='*50}")
        print(f"Total findings imported: {total_imported}")
        print(f"Total errors: {total_errors}")
        print(f"Product ID: {product_id}")
        print(f"Engagement ID: {engagement_id}")
        print(f"DefectDojo URL: {args.url}")
        
    except requests.exceptions.RequestException as e:
        print(f"Error communicating with DefectDojo: {e}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
