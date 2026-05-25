"""
Compliance report generator - Creates compliance reports in HTML and JSON formats.
"""

import json
from datetime import datetime


class ComplianceReportGenerator:
    """Generates compliance reports for CIS Docker Benchmark and ISO/IEC 27001."""
    
    def __init__(self, compliance_findings):
        """
        Initialize the compliance report generator.
        
        Args:
            compliance_findings (list): List of compliance findings from ComplianceEvaluator
        """
        self.compliance_findings = compliance_findings
        self.generated_at = datetime.now().isoformat()
    
    def to_json(self, pretty=True):
        """
        Generate compliance report in JSON format.
        
        Args:
            pretty (bool): Whether to pretty-print JSON
            
        Returns:
            str: JSON formatted compliance report
        """
        report = {
            "metadata": {
                "generated_at": self.generated_at,
                "report_type": "Compliance - CIS Docker Benchmark vs ISO/IEC 27001"
            },
            "summary": self._generate_summary(),
            "findings": self.compliance_findings,
            "analysis": {
                "by_severity": self._group_by_severity(),
                "by_category": self._group_by_category(),
                "iso_coverage": self._analyze_iso_coverage()
            }
        }
        
        if pretty:
            return json.dumps(report, indent=2, ensure_ascii=False)
        else:
            return json.dumps(report, ensure_ascii=False)
    
    def to_html(self, title="DockAudit-SCA Compliance Report"):
        """
        Generate compliance report in HTML format.
        
        Args:
            title (str): Report title
            
        Returns:
            str: HTML formatted compliance report
        """
        summary = self._generate_summary()
        by_severity = self._group_by_severity()
        by_category = self._group_by_category()
        iso_coverage = self._analyze_iso_coverage()
        
        html = f"""<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            background-color: #f5f5f5;
            color: #333;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }}
        header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px 20px;
            border-radius: 8px;
            margin-bottom: 30px;
            box-shadow: 0 4px 6px rgba(0,0,0,0.1);
        }}
        header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
        }}
        header p {{
            opacity: 0.9;
            font-size: 0.95em;
        }}
        .metadata {{
            background: white;
            padding: 15px 20px;
            border-radius: 4px;
            margin-bottom: 20px;
            border-left: 4px solid #667eea;
        }}
        .summary-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }}
        .summary-card {{
            background: white;
            padding: 20px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
            text-align: center;
            border-top: 4px solid #667eea;
        }}
        .summary-card.compliant {{ border-top-color: #4caf50; }}
        .summary-card.non-compliant {{ border-top-color: #f44336; }}
        .summary-card.unknown {{ border-top-color: #ff9800; }}
        .summary-card .number {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
            margin-bottom: 10px;
        }}
        .summary-card.compliant .number {{ color: #4caf50; }}
        .summary-card.non-compliant .number {{ color: #f44336; }}
        .summary-card.unknown .number {{ color: #ff9800; }}
        .summary-card .label {{
            color: #666;
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .compliance-percentage {{
            font-size: 2em;
            font-weight: bold;
            color: #667eea;
        }}
        .section {{
            background: white;
            padding: 25px;
            border-radius: 8px;
            margin-bottom: 25px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .section h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .section h3 {{
            color: #555;
            margin-top: 20px;
            margin-bottom: 15px;
            font-size: 1.1em;
        }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }}
        thead {{
            background-color: #f5f5f5;
        }}
        th {{
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #ddd;
        }}
        td {{
            padding: 12px;
            border-bottom: 1px solid #eee;
        }}
        tr:hover {{
            background-color: #f9f9f9;
        }}
        .status-badge {{
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .status-compliant {{
            background-color: #c8e6c9;
            color: #2e7d32;
        }}
        .status-non-compliant {{
            background-color: #ffcdd2;
            color: #c62828;
        }}
        .status-unknown {{
            background-color: #ffe0b2;
            color: #e65100;
        }}
        .severity-critical {{
            color: #c62828;
            font-weight: bold;
        }}
        .severity-high {{
            color: #f57c00;
            font-weight: bold;
        }}
        .severity-medium {{
            color: #f9a825;
        }}
        .severity-low {{
            color: #558b2f;
        }}
        .finding-detail {{
            background: #f9f9f9;
            padding: 15px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #ddd;
        }}
        .iso-controls {{
            display: flex;
            gap: 8px;
            flex-wrap: wrap;
            margin: 10px 0;
        }}
        .iso-badge {{
            background: #e8eaf6;
            color: #3f51b5;
            padding: 4px 10px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 500;
        }}
        .remediation {{
            background: #fff3cd;
            padding: 12px;
            border-radius: 4px;
            margin: 10px 0;
            border-left: 4px solid #ffc107;
        }}
        .chart {{
            margin: 20px 0;
            padding: 15px;
            background: #f9f9f9;
            border-radius: 4px;
        }}
        .bar {{
            display: flex;
            margin-bottom: 15px;
            align-items: center;
        }}
        .bar-label {{
            width: 150px;
            font-weight: 500;
        }}
        .bar-container {{
            flex: 1;
            background: #e0e0e0;
            border-radius: 4px;
            height: 25px;
            position: relative;
            overflow: hidden;
        }}
        .bar-fill {{
            height: 100%;
            display: flex;
            align-items: center;
            justify-content: flex-end;
            padding-right: 10px;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }}
        .bar-fill.compliant {{ background: #4caf50; }}
        .bar-fill.non-compliant {{ background: #f44336; }}
        .bar-fill.unknown {{ background: #ff9800; }}
        footer {{
            text-align: center;
            padding: 20px;
            color: #999;
            font-size: 0.9em;
        }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔐 Compliance Report</h1>
            <p>CIS Docker Benchmark & ISO/IEC 27001 Assessment</p>
        </header>
        
        <div class="metadata">
            <strong>Generated:</strong> {self.generated_at}<br>
            <strong>Report Type:</strong> Security Compliance Audit
        </div>
        
        {self._generate_summary_section(summary)}
        
        {self._generate_findings_section()}
        
        {self._generate_severity_analysis(by_severity)}
        
        {self._generate_category_analysis(by_category)}
        
        {self._generate_iso_coverage_section(iso_coverage)}
        
        <footer>
            <p>Generated by DockAudit-SCA | Security Audit & Compliance Tool</p>
        </footer>
    </div>
</body>
</html>"""
        
        return html
    
    def _generate_summary(self):
        """Generate summary statistics."""
        total = len(self.compliance_findings)
        compliant = sum(1 for f in self.compliance_findings if f["status"] == "compliant")
        non_compliant = sum(1 for f in self.compliance_findings if f["status"] == "non_compliant")
        unknown = sum(1 for f in self.compliance_findings if f["status"] == "unknown")
        
        compliance_percentage = (compliant / total * 100) if total > 0 else 0
        
        return {
            "total_controls": total,
            "compliant": compliant,
            "non_compliant": non_compliant,
            "unknown": unknown,
            "compliance_percentage": round(compliance_percentage, 2)
        }
    
    def _generate_summary_section(self, summary):
        """Generate HTML summary section."""
        return f"""
        <div class="summary-grid">
            <div class="summary-card compliant">
                <div class="number">{summary['compliant']}</div>
                <div class="label">Compliant Controls</div>
            </div>
            <div class="summary-card non-compliant">
                <div class="number">{summary['non_compliant']}</div>
                <div class="label">Non-Compliant Controls</div>
            </div>
            <div class="summary-card unknown">
                <div class="number">{summary['unknown']}</div>
                <div class="label">Unknown Status</div>
            </div>
            <div class="summary-card">
                <div class="compliance-percentage">{summary['compliance_percentage']:.1f}%</div>
                <div class="label">Compliance Rate</div>
            </div>
        </div>
"""
    
    def _generate_findings_section(self):
        """Generate HTML findings section."""
        html = '<div class="section"><h2>📋 Compliance Findings</h2>'
        html += '<table><thead><tr>'
        html += '<th>CIS Control</th><th>Title</th><th>Severity</th><th>Status</th><th>ISO Controls</th>'
        html += '</tr></thead><tbody>'
        
        for finding in self.compliance_findings:
            status_class = f"status-{finding['status']}"
            severity_class = f"severity-{finding['severity']}"
            
            iso_codes = ", ".join([c["code"] for c in finding.get("iso27001_controls", [])])
            
            html += f"""
            <tr>
                <td><strong>{finding['cis_control']}</strong></td>
                <td>{finding['title']}</td>
                <td><span class="{severity_class}">{finding['severity'].upper()}</span></td>
                <td><span class="status-badge {status_class}">{finding['status'].upper()}</span></td>
                <td>{iso_codes}</td>
            </tr>
            """
        
        html += '</tbody></table></div>'
        return html
    
    def _generate_severity_analysis(self, by_severity):
        """Generate severity analysis section."""
        html = '<div class="section"><h2>⚠️ Analysis by Severity</h2>'
        
        severity_order = ["critical", "high", "medium", "low"]
        total = sum(len(v) for v in by_severity.values())
        
        for severity in severity_order:
            if severity in by_severity:
                controls = by_severity[severity]
                percentage = (len(controls) / total * 100) if total > 0 else 0
                
                html += f'<h3>{severity.upper()} ({len(controls)} controls - {percentage:.1f}%)</h3>'
                html += '<ul>'
                
                for control in controls[:10]:  # Show first 10
                    html += f"<li>{control['cis_control']}: {control['title']}</li>"
                
                if len(controls) > 10:
                    html += f"<li>... and {len(controls) - 10} more</li>"
                
                html += '</ul>'
        
        html += '</div>'
        return html
    
    def _generate_category_analysis(self, by_category):
        """Generate category analysis section."""
        html = '<div class="section"><h2>📁 Analysis by Category</h2><div class="chart">'
        
        for category, controls in sorted(by_category.items()):
            compliant = sum(1 for c in controls if c["status"] == "compliant")
            percentage = (compliant / len(controls) * 100) if len(controls) > 0 else 0
            
            html += f"""
            <div class="bar">
                <div class="bar-label">{category}</div>
                <div class="bar-container">
                    <div class="bar-fill compliant" style="width: {percentage}%">
                        {percentage:.0f}%
                    </div>
                </div>
            </div>
            """
        
        html += '</div></div>'
        return html
    
    def _generate_iso_coverage_section(self, iso_coverage):
        """Generate ISO/IEC 27001 coverage section."""
        html = '<div class="section"><h2>🌐 ISO/IEC 27001 Coverage</h2>'
        html += '<table><thead><tr>'
        html += '<th>Domain</th><th>Compliant</th><th>Non-Compliant</th><th>Unknown</th><th>Coverage %</th>'
        html += '</tr></thead><tbody>'
        
        for domain, data in sorted(iso_coverage.items()):
            total = data["total"]
            compliant = data["compliant"]
            coverage = (compliant / total * 100) if total > 0 else 0
            
            html += f"""
            <tr>
                <td><strong>{domain}</strong></td>
                <td><span class="status-badge status-compliant">{compliant}</span></td>
                <td><span class="status-badge status-non-compliant">{data['non_compliant']}</span></td>
                <td><span class="status-badge status-unknown">{data['unknown']}</span></td>
                <td>{coverage:.1f}%</td>
            </tr>
            """
        
        html += '</tbody></table></div>'
        return html
    
    def _group_by_severity(self):
        """Group findings by severity."""
        by_severity = {}
        for finding in self.compliance_findings:
            severity = finding.get("severity", "unknown")
            if severity not in by_severity:
                by_severity[severity] = []
            by_severity[severity].append(finding)
        return by_severity
    
    def _group_by_category(self):
        """Group findings by category."""
        by_category = {}
        for finding in self.compliance_findings:
            category = finding.get("category", "General")
            if category not in by_category:
                by_category[category] = []
            by_category[category].append(finding)
        return by_category
    
    def _analyze_iso_coverage(self):
        """Analyze ISO/IEC 27001 coverage."""
        iso_coverage = {}
        for finding in self.compliance_findings:
            for iso_control in finding.get("iso27001_controls", []):
                domain = iso_control.get("domain", "Unknown")
                if domain not in iso_coverage:
                    iso_coverage[domain] = {
                        "total": 0,
                        "compliant": 0,
                        "non_compliant": 0,
                        "unknown": 0,
                        "controls": []
                    }
                
                iso_coverage[domain]["total"] += 1
                iso_coverage[domain]["controls"].append(iso_control["code"])
                
                status = finding.get("status")
                if status == "compliant":
                    iso_coverage[domain]["compliant"] += 1
                elif status == "non_compliant":
                    iso_coverage[domain]["non_compliant"] += 1
                else:
                    iso_coverage[domain]["unknown"] += 1
        
        return iso_coverage
