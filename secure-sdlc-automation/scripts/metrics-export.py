#!/usr/bin/env python3
"""
Security Metrics Export Script

Generates security metrics from aggregated findings for dashboards,
reporting, and trend analysis.

Author: Sunanda Mandal
"""

import json
import argparse
from datetime import datetime
from typing import Dict, Any, List
from collections import defaultdict


def calculate_metrics(findings: Dict[str, Any]) -> Dict[str, Any]:
    """
    Calculate security metrics from findings.
    
    Args:
        findings: Aggregated findings data
        
    Returns:
        Dictionary of calculated metrics
    """
    finding_list = findings.get('findings', [])
    base_metrics = findings.get('metrics', {})
    
    # Basic counts
    metrics = {
        'timestamp': datetime.now().isoformat(),
        'total': base_metrics.get('total', len(finding_list)),
        'critical': base_metrics.get('critical', 0),
        'high': base_metrics.get('high', 0),
        'medium': base_metrics.get('medium', 0),
        'low': base_metrics.get('low', 0),
        'info': base_metrics.get('info', 0),
        'new': base_metrics.get('new', 0),
        'fixed': base_metrics.get('fixed', 0),
    }
    
    # Findings by tool
    by_tool = defaultdict(int)
    for finding in finding_list:
        tool = finding.get('tool', 'unknown')
        by_tool[tool] += 1
    metrics['by_tool'] = dict(by_tool)
    
    # Findings by category/CWE
    by_cwe = defaultdict(int)
    for finding in finding_list:
        cwe = finding.get('cwe', 'unknown')
        if cwe:
            by_cwe[str(cwe)] += 1
    metrics['by_cwe'] = dict(by_cwe)
    
    # Top 10 most common CWEs
    metrics['top_cwes'] = sorted(
        by_cwe.items(), 
        key=lambda x: x[1], 
        reverse=True
    )[:10]
    
    # Findings by file
    by_file = defaultdict(int)
    for finding in finding_list:
        file_path = finding.get('file', 'unknown')
        if file_path:
            by_file[file_path] += 1
    
    # Top 10 files with most findings
    metrics['top_files'] = sorted(
        by_file.items(),
        key=lambda x: x[1],
        reverse=True
    )[:10]
    
    # OWASP Top 10 mapping
    owasp_mapping = defaultdict(int)
    for finding in finding_list:
        owasp = finding.get('owasp', '')
        if owasp:
            owasp_mapping[owasp] += 1
    metrics['owasp_distribution'] = dict(owasp_mapping)
    
    # SLA status
    sla_breached = 0
    sla_at_risk = 0
    now = datetime.now()
    
    for finding in finding_list:
        deadline = finding.get('sla_deadline')
        if deadline:
            try:
                deadline_dt = datetime.fromisoformat(deadline.replace('Z', '+00:00'))
                if deadline_dt.replace(tzinfo=None) < now:
                    sla_breached += 1
                elif (deadline_dt.replace(tzinfo=None) - now).days <= 2:
                    sla_at_risk += 1
            except (ValueError, TypeError):
                pass
    
    metrics['sla'] = {
        'breached': sla_breached,
        'at_risk': sla_at_risk,
        'compliant': len(finding_list) - sla_breached - sla_at_risk
    }
    
    # Risk score calculation
    # Simple weighted score: Critical=10, High=5, Medium=2, Low=1
    risk_score = (
        metrics['critical'] * 10 +
        metrics['high'] * 5 +
        metrics['medium'] * 2 +
        metrics['low'] * 1
    )
    metrics['risk_score'] = risk_score
    
    # Risk level based on score
    if risk_score == 0:
        metrics['risk_level'] = 'LOW'
    elif risk_score <= 10:
        metrics['risk_level'] = 'MEDIUM'
    elif risk_score <= 50:
        metrics['risk_level'] = 'HIGH'
    else:
        metrics['risk_level'] = 'CRITICAL'
    
    # Dependency vulnerabilities specifically
    dep_findings = [f for f in finding_list if f.get('tool') in ['safety', 'trivy', 'snyk']]
    metrics['dependency_vulnerabilities'] = {
        'total': len(dep_findings),
        'with_fix_available': sum(1 for f in dep_findings if f.get('fixed_version')),
        'packages_affected': len(set(f.get('package', '') for f in dep_findings if f.get('package')))
    }
    
    # Secret findings
    secret_findings = [f for f in finding_list if f.get('tool') == 'gitleaks']
    metrics['secrets'] = {
        'total': len(secret_findings),
        'types': list(set(f.get('secret_type', 'unknown') for f in secret_findings))
    }
    
    # Container vulnerabilities
    container_findings = [f for f in finding_list if f.get('tool') in ['trivy', 'grype']]
    metrics['container_vulnerabilities'] = len(container_findings)
    
    # IaC misconfigurations
    iac_findings = [f for f in finding_list if f.get('tool') in ['checkov', 'tfsec']]
    metrics['iac_misconfigurations'] = len(iac_findings)
    
    return metrics


def generate_prometheus_metrics(metrics: Dict[str, Any]) -> str:
    """
    Generate Prometheus-compatible metrics output.
    
    Args:
        metrics: Calculated metrics
        
    Returns:
        Prometheus format string
    """
    lines = []
    
    # Help and type definitions
    lines.append('# HELP security_findings_total Total number of security findings')
    lines.append('# TYPE security_findings_total gauge')
    lines.append(f'security_findings_total {metrics["total"]}')
    
    lines.append('# HELP security_findings_by_severity Findings by severity level')
    lines.append('# TYPE security_findings_by_severity gauge')
    for severity in ['critical', 'high', 'medium', 'low', 'info']:
        lines.append(f'security_findings_by_severity{{severity="{severity}"}} {metrics.get(severity, 0)}')
    
    lines.append('# HELP security_findings_by_tool Findings by scanning tool')
    lines.append('# TYPE security_findings_by_tool gauge')
    for tool, count in metrics.get('by_tool', {}).items():
        lines.append(f'security_findings_by_tool{{tool="{tool}"}} {count}')
    
    lines.append('# HELP security_risk_score Calculated risk score')
    lines.append('# TYPE security_risk_score gauge')
    lines.append(f'security_risk_score {metrics["risk_score"]}')
    
    lines.append('# HELP security_sla_breached Count of findings with breached SLA')
    lines.append('# TYPE security_sla_breached gauge')
    lines.append(f'security_sla_breached {metrics["sla"]["breached"]}')
    
    lines.append('# HELP security_secrets_detected Count of detected secrets')
    lines.append('# TYPE security_secrets_detected gauge')
    lines.append(f'security_secrets_detected {metrics["secrets"]["total"]}')
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Export security metrics from aggregated findings'
    )
    parser.add_argument(
        '--findings',
        required=True,
        help='Path to aggregated findings JSON file'
    )
    parser.add_argument(
        '--output',
        default='security-metrics.json',
        help='Output file path for JSON metrics'
    )
    parser.add_argument(
        '--prometheus',
        help='Output file path for Prometheus metrics'
    )
    parser.add_argument(
        '--format',
        choices=['json', 'prometheus', 'both'],
        default='json',
        help='Output format'
    )
    
    args = parser.parse_args()
    
    # Load findings
    with open(args.findings, 'r') as f:
        findings = json.load(f)
    
    # Calculate metrics
    metrics = calculate_metrics(findings)
    
    # Output JSON
    if args.format in ['json', 'both']:
        with open(args.output, 'w') as f:
            json.dump(metrics, f, indent=2, default=str)
        print(f"JSON metrics exported to: {args.output}")
    
    # Output Prometheus format
    if args.format in ['prometheus', 'both'] and args.prometheus:
        prometheus_output = generate_prometheus_metrics(metrics)
        with open(args.prometheus, 'w') as f:
            f.write(prometheus_output)
        print(f"Prometheus metrics exported to: {args.prometheus}")
    
    # Print summary
    print("\n" + "=" * 50)
    print("SECURITY METRICS SUMMARY")
    print("=" * 50)
    print(f"Risk Level: {metrics['risk_level']}")
    print(f"Risk Score: {metrics['risk_score']}")
    print(f"\nFindings by Severity:")
    print(f"  Critical: {metrics['critical']}")
    print(f"  High: {metrics['high']}")
    print(f"  Medium: {metrics['medium']}")
    print(f"  Low: {metrics['low']}")
    print(f"\nSLA Status:")
    print(f"  Breached: {metrics['sla']['breached']}")
    print(f"  At Risk: {metrics['sla']['at_risk']}")
    print(f"  Compliant: {metrics['sla']['compliant']}")
    print(f"\nSecrets Detected: {metrics['secrets']['total']}")
    print(f"Dependency Vulnerabilities: {metrics['dependency_vulnerabilities']['total']}")
    print(f"IaC Misconfigurations: {metrics['iac_misconfigurations']}")
    print("=" * 50)


if __name__ == '__main__':
    main()
