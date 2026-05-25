"""
Tests for compliance mapping and evaluation.
"""

import pytest
from dockaudit.compliance.mapping import COMPLIANCE_MAPPING
from dockaudit.compliance.evaluator import ComplianceEvaluator
from dockaudit.reporting.compliance_report import ComplianceReportGenerator


class TestComplianceMapping:
    """Test CIS to ISO/IEC 27001 mapping."""
    
    def test_mapping_has_required_controls(self):
        """Test that mapping contains expected CIS controls."""
        assert "CIS-2.1" in COMPLIANCE_MAPPING
        assert "CIS-3.1" in COMPLIANCE_MAPPING
        assert "CIS-4.3" in COMPLIANCE_MAPPING
    
    def test_control_structure(self):
        """Test that controls have required fields."""
        for cis_id, control in COMPLIANCE_MAPPING.items():
            assert "title" in control
            assert "description" in control
            assert "iso27001_controls" in control
            assert "severity" in control
            assert "implementation" in control
            assert "remediation" in control
            assert "category" in control
    
    def test_iso_controls_structure(self):
        """Test that ISO controls have required fields."""
        for control in COMPLIANCE_MAPPING.values():
            for iso_ctrl in control["iso27001_controls"]:
                assert "code" in iso_ctrl
                assert "domain" in iso_ctrl
                assert "title" in iso_ctrl


class TestComplianceEvaluator:
    """Test compliance evaluator."""
    
    def test_evaluator_initialization(self):
        """Test evaluator initialization."""
        audit_results = {"host_audit": {}, "container_audit": {}, "image_analysis": {}}
        evaluator = ComplianceEvaluator(audit_results)
        
        assert evaluator.audit_results == audit_results
        assert evaluator.mapping == COMPLIANCE_MAPPING
    
    def test_evaluator_with_privileged_container(self):
        """Test detection of privileged containers."""
        audit_results = {
            "container_audit": {
                "containers": [
                    {"name": "test-container", "privileged": True}
                ]
            }
        }
        
        evaluator = ComplianceEvaluator(audit_results)
        findings = evaluator.evaluate()
        
        # Find CIS-3.1 (privileged mode check)
        cis_3_1 = next((f for f in findings if f["cis_control"] == "CIS-3.1"), None)
        assert cis_3_1 is not None
        assert cis_3_1["status"] == "non_compliant"
    
    def test_evaluator_with_root_user(self):
        """Test detection of containers running as root."""
        audit_results = {
            "container_audit": {
                "containers": [
                    {"name": "test-container", "user": "root"}
                ]
            }
        }
        
        evaluator = ComplianceEvaluator(audit_results)
        findings = evaluator.evaluate()
        
        # Find CIS-3.2 (user not root check)
        cis_3_2 = next((f for f in findings if f["cis_control"] == "CIS-3.2"), None)
        assert cis_3_2 is not None
        assert cis_3_2["status"] == "non_compliant"
    
    def test_evaluator_summary(self):
        """Test compliance summary generation."""
        audit_results = {
            "container_audit": {"containers": []},
            "image_analysis": {"images": []}
        }
        
        evaluator = ComplianceEvaluator(audit_results)
        summary = evaluator.get_summary()
        
        assert "total_controls" in summary
        assert "compliant" in summary
        assert "non_compliant" in summary
        assert "compliance_percentage" in summary
    
    def test_evaluator_by_severity(self):
        """Test grouping findings by severity."""
        audit_results = {}
        evaluator = ComplianceEvaluator(audit_results)
        
        by_severity = evaluator.get_by_severity()
        
        assert "critical" in by_severity
        assert "high" in by_severity
        assert "medium" in by_severity
        # Note: "low" severity controls are not currently in the mapping
        # Verify the structure
        assert isinstance(by_severity, dict)
        for severity, controls in by_severity.items():
            assert isinstance(controls, list)
    
    def test_evaluator_by_category(self):
        """Test grouping findings by category."""
        audit_results = {}
        evaluator = ComplianceEvaluator(audit_results)
        
        by_category = evaluator.get_by_category()
        
        assert "Access Control" in by_category
        assert "Container Runtime" in by_category
        assert "Image Security" in by_category
    
    def test_evaluator_iso_coverage(self):
        """Test ISO/IEC 27001 coverage analysis."""
        audit_results = {}
        evaluator = ComplianceEvaluator(audit_results)
        
        iso_coverage = evaluator.get_iso_coverage()
        
        assert "Access Control" in iso_coverage
        assert "Operations Security" in iso_coverage
    
    def test_with_setuid_binaries(self):
        """Test SETUID binary detection."""
        audit_results = {
            "image_analysis": {
                "binaries": [
                    {"path": "/usr/bin/sudo", "setuid": True}
                ]
            }
        }
        
        evaluator = ComplianceEvaluator(audit_results)
        findings = evaluator.evaluate()
        
        cis_4_7 = next((f for f in findings if f["cis_control"] == "CIS-4.7"), None)
        assert cis_4_7 is not None
        assert cis_4_7["status"] == "non_compliant"


class TestComplianceReportGenerator:
    """Test compliance report generation."""
    
    def test_report_generator_json(self):
        """Test JSON report generation."""
        findings = [
            {
                "cis_control": "CIS-2.1",
                "title": "Test Control",
                "description": "Test Description",
                "severity": "high",
                "status": "compliant",
                "iso27001_controls": [],
                "category": "Access Control",
                "remediation": "Test",
                "details": {}
            }
        ]
        
        generator = ComplianceReportGenerator(findings)
        json_report = generator.to_json()
        
        assert '"cis_control": "CIS-2.1"' in json_report
        assert '"status": "compliant"' in json_report
        assert '"generated_at"' in json_report
    
    def test_report_generator_html(self):
        """Test HTML report generation."""
        findings = [
            {
                "cis_control": "CIS-2.1",
                "title": "Test Control",
                "description": "Test Description",
                "severity": "high",
                "status": "compliant",
                "iso27001_controls": [{"code": "A.9.2.1", "domain": "Access Control", "title": "Test"}],
                "category": "Access Control",
                "remediation": "Test",
                "details": {}
            }
        ]
        
        generator = ComplianceReportGenerator(findings)
        html_report = generator.to_html()
        
        assert "<!DOCTYPE html>" in html_report
        assert "CIS-2.1" in html_report
        assert "Compliance Report" in html_report
    
    def test_report_generator_summary(self):
        """Test report summary."""
        findings = [
            {
                "cis_control": "CIS-2.1",
                "title": "Test",
                "description": "Test",
                "severity": "high",
                "status": "compliant",
                "iso27001_controls": [],
                "category": "Access Control",
                "remediation": "Test",
                "details": {}
            },
            {
                "cis_control": "CIS-3.1",
                "title": "Test 2",
                "description": "Test",
                "severity": "critical",
                "status": "non_compliant",
                "iso27001_controls": [],
                "category": "Container Runtime",
                "remediation": "Test",
                "details": {}
            }
        ]
        
        generator = ComplianceReportGenerator(findings)
        json_report = generator.to_json()
        
        assert '"compliant": 1' in json_report
        assert '"non_compliant": 1' in json_report


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
