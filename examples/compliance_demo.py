#!/usr/bin/env python3
"""
Demonstration of DockAudit-SCA Compliance Mapping
Shows how to use CIS Docker Benchmark and ISO/IEC 27001 compliance evaluation.
"""

from dockaudit.compliance.mapping import COMPLIANCE_MAPPING
from dockaudit.compliance.evaluator import ComplianceEvaluator
from dockaudit.reporting.compliance_report import ComplianceReportGenerator
import json


def demo_mapping():
    """Display some CIS controls and their ISO 27001 mappings."""
    print("=" * 80)
    print("DockAudit-SCA: CIS Docker Benchmark ↔ ISO/IEC 27001 Compliance Mapping")
    print("=" * 80)
    print()
    
    # Show a few example controls
    example_controls = ["CIS-2.1", "CIS-3.1", "CIS-4.7", "CIS-5.1"]
    
    for cis_id in example_controls:
        if cis_id in COMPLIANCE_MAPPING:
            control = COMPLIANCE_MAPPING[cis_id]
            print(f"\n📌 {cis_id}: {control['title']}")
            print(f"   Severity: {control['severity'].upper()}")
            print(f"   Category: {control['category']}")
            print(f"   Description: {control['description']}")
            print(f"   ISO/IEC 27001 Controls:")
            
            for iso_ctrl in control["iso27001_controls"]:
                print(f"      • {iso_ctrl['code']} ({iso_ctrl['domain']}): {iso_ctrl['title']}")
            
            print(f"   Remediation: {control['remediation']}")


def demo_evaluation():
    """Demonstrate compliance evaluation with sample audit results."""
    print("\n" + "=" * 80)
    print("COMPLIANCE EVALUATION EXAMPLE")
    print("=" * 80)
    print()
    
    # Sample audit results (simulating a real audit)
    sample_audit_results = {
        "host_audit": {
            "findings": ["Docker daemon is running as root"],
            "docker_version": "24.0.5"
        },
        "container_audit": {
            "containers": [
                {
                    "name": "web-app",
                    "user": "www-data",
                    "privileged": False,
                    "cap_drop": ["ALL"],
                    "apparmor_disabled": False,
                    "seccomp_profile": "default",
                    "volumes": []
                },
                {
                    "name": "admin-console",
                    "user": "root",
                    "privileged": True,
                    "cap_drop": None,
                    "volumes": ["/etc:/etc"]
                }
            ]
        },
        "image_analysis": {
            "images": [
                {
                    "name": "alpine:3.18",
                    "registry": "official",
                    "packages": 15
                }
            ],
            "binaries": [
                {"path": "/usr/bin/sudo", "setuid": True}
            ]
        },
        "vulnerabilities": []
    }
    
    # Run compliance evaluation
    evaluator = ComplianceEvaluator(sample_audit_results)
    compliance_findings = evaluator.evaluate()
    
    # Get summary
    summary = evaluator.get_summary()
    
    print(f"📊 Compliance Summary:")
    print(f"   Total Controls: {summary['total_controls']}")
    print(f"   ✅ Compliant: {summary['compliant']}")
    print(f"   ❌ Non-Compliant: {summary['non_compliant']}")
    print(f"   ❓ Unknown: {summary['unknown']}")
    print(f"   Compliance Rate: {summary['compliance_percentage']:.1f}%")
    
    print(f"\n📋 Critical Issues Found:")
    critical_findings = [f for f in compliance_findings if f["severity"] == "critical"]
    for finding in critical_findings[:3]:
        print(f"   • {finding['cis_control']}: {finding['title']}")
        if finding["status"] == "non_compliant":
            print(f"     Status: ⚠️  NON-COMPLIANT")
            print(f"     Details: {finding['details']}")
    
    print(f"\n🗂️  Findings by Category:")
    by_category = evaluator.get_by_category()
    for category, findings in by_category.items():
        compliant = sum(1 for f in findings if f["status"] == "compliant")
        non_compliant = sum(1 for f in findings if f["status"] == "non_compliant")
        print(f"   {category}: {compliant} ✅ / {non_compliant} ❌")
    
    print(f"\n🌐 ISO/IEC 27001 Coverage:")
    iso_coverage = evaluator.get_iso_coverage()
    for domain, data in sorted(iso_coverage.items())[:3]:
        coverage = (data["compliant"] / data["total"] * 100) if data["total"] > 0 else 0
        print(f"   {domain}: {data['compliant']}/{data['total']} ({coverage:.1f}%)")
    
    return compliance_findings


def demo_report_generation(compliance_findings):
    """Demonstrate report generation."""
    print("\n" + "=" * 80)
    print("REPORT GENERATION EXAMPLE")
    print("=" * 80)
    print()
    
    generator = ComplianceReportGenerator(compliance_findings)
    
    # Generate JSON report
    json_report = generator.to_json(pretty=False)
    print(f"✅ JSON Report Generated: {len(json_report)} bytes")
    
    # Generate HTML report
    html_report = generator.to_html(title="DockAudit-SCA - Sample Compliance Report")
    print(f"✅ HTML Report Generated: {len(html_report)} bytes")
    
    # Save reports
    with open("reports/compliance_sample.json", "w") as f:
        f.write(generator.to_json(pretty=True))
    print("💾 Saved: reports/compliance_sample.json")
    
    with open("reports/compliance_sample.html", "w") as f:
        f.write(html_report)
    print("💾 Saved: reports/compliance_sample.html")


def main():
    """Run all demonstrations."""
    demo_mapping()
    compliance_findings = demo_evaluation()
    demo_report_generation(compliance_findings)
    
    print("\n" + "=" * 80)
    print("✅ Demonstration Complete!")
    print("=" * 80)
    print("\nNext steps:")
    print("1. Review the mapping documentation: docs/compliance_mapping.md")
    print("2. Run the full audit with compliance: ./scripts/run_real_integration.sh")
    print("3. Check the generated compliance reports in 'reports/' directory")


if __name__ == "__main__":
    main()
