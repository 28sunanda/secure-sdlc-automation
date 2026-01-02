#!/usr/bin/env python3
"""
Security Gate Check Script

Evaluates aggregated security findings against a policy to determine
whether to pass or fail the security gate in CI/CD pipeline.

Author: Sunanda Mandal
"""

import json
import sys
import argparse
from typing import Dict, Any
import yaml


def load_policy(policy_path: str) -> Dict[str, Any]:
    """Load security gate policy from YAML file."""
    with open(policy_path, 'r') as f:
        return yaml.safe_load(f)


def load_findings(findings_path: str) -> Dict[str, Any]:
    """Load aggregated findings from JSON file."""
    with open(findings_path, 'r') as f:
        return json.load(f)


def evaluate_gate(findings: Dict[str, Any], policy: Dict[str, Any]) -> tuple:
    """
    Evaluate findings against security gate policy.
    
    Returns:
        Tuple of (passed: bool, violations: list, warnings: list)
    """
    metrics = findings.get('metrics', {})
    violations = []
    warnings = []
    
    # Get policy thresholds
    blocking = policy.get('blocking', {})
    warning = policy.get('warning', {})
    
    # Check blocking conditions
    if blocking.get('critical', 0) >= 0:
        if metrics.get('critical', 0) > blocking.get('critical', 0):
            violations.append(
                f"Critical findings ({metrics.get('critical', 0)}) exceed threshold ({blocking.get('critical', 0)})"
            )
    
    if blocking.get('high', 0) >= 0:
        if metrics.get('high', 0) > blocking.get('high', 0):
            violations.append(
                f"High findings ({metrics.get('high', 0)}) exceed threshold ({blocking.get('high', 0)})"
            )
    
    # Check for specific blocking rules
    for finding in findings.get('findings', []):
        rule_id = finding.get('rule_id', '')
        
        # Block on specific CWEs
        cwe = finding.get('cwe', '')
        blocked_cwes = blocking.get('cwe_ids', [])
        if cwe and str(cwe) in [str(c) for c in blocked_cwes]:
            violations.append(f"Blocked CWE found: {cwe} in {finding.get('file', 'unknown')}")
        
        # Block on specific rules
        blocked_rules = blocking.get('rule_ids', [])
        if rule_id in blocked_rules:
            violations.append(f"Blocked rule triggered: {rule_id}")
        
        # Block on secrets
        if blocking.get('secrets', True) and finding.get('tool') == 'gitleaks':
            violations.append(f"Secret detected: {finding.get('secret_type', 'unknown')}")
    
    # Check warning conditions
    if warning.get('medium', 0) >= 0:
        if metrics.get('medium', 0) > warning.get('medium', 0):
            warnings.append(
                f"Medium findings ({metrics.get('medium', 0)}) exceed threshold ({warning.get('medium', 0)})"
            )
    
    if warning.get('total', 0) >= 0:
        if metrics.get('total', 0) > warning.get('total', 0):
            warnings.append(
                f"Total findings ({metrics.get('total', 0)}) exceed threshold ({warning.get('total', 0)})"
            )
    
    passed = len(violations) == 0
    return passed, violations, warnings


def main():
    parser = argparse.ArgumentParser(
        description='Check security findings against gate policy'
    )
    parser.add_argument(
        '--findings',
        required=True,
        help='Path to aggregated findings JSON file'
    )
    parser.add_argument(
        '--policy',
        required=True,
        help='Path to security gate policy YAML file'
    )
    parser.add_argument(
        '--output',
        help='Path to output results JSON file'
    )
    
    args = parser.parse_args()
    
    # Load data
    findings = load_findings(args.findings)
    policy = load_policy(args.policy)
    
    # Evaluate gate
    passed, violations, warnings = evaluate_gate(findings, policy)
    
    # Output results
    result = {
        'passed': passed,
        'violations': violations,
        'warnings': warnings,
        'metrics': findings.get('metrics', {})
    }
    
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(result, f, indent=2)
    
    # Print summary
    print("\n" + "=" * 60)
    print("SECURITY GATE CHECK")
    print("=" * 60)
    
    metrics = findings.get('metrics', {})
    print(f"\nFindings Summary:")
    print(f"  🔴 Critical: {metrics.get('critical', 0)}")
    print(f"  🟠 High:     {metrics.get('high', 0)}")
    print(f"  🟡 Medium:   {metrics.get('medium', 0)}")
    print(f"  🟢 Low:      {metrics.get('low', 0)}")
    print(f"  ⚪ Info:     {metrics.get('info', 0)}")
    print(f"  📊 Total:    {metrics.get('total', 0)}")
    
    if violations:
        print(f"\n❌ GATE FAILED - {len(violations)} violation(s):")
        for v in violations:
            print(f"   • {v}")
    
    if warnings:
        print(f"\n⚠️  {len(warnings)} warning(s):")
        for w in warnings:
            print(f"   • {w}")
    
    if passed:
        print("\n✅ SECURITY GATE PASSED")
    else:
        print("\n❌ SECURITY GATE FAILED")
    
    print("=" * 60 + "\n")
    
    # Exit with appropriate code
    sys.exit(0 if passed else 1)


if __name__ == '__main__':
    main()
