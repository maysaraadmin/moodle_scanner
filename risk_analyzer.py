"""
Risk analysis and compliance reporting module for Moodle Security Scanner.
Handles CVSS scoring, remediation recommendations, and compliance reporting.

This module can be used both as a library and as a standalone script.

Standalone usage:
    python risk_analyzer.py --findings findings.json --output report.pdf

Arguments:
    --findings: Path to JSON file containing scan findings
    --output: Output file path (default: security_report.pdf)
    --format: Output format - pdf, json, or text (default: pdf)
"""
from datetime import datetime
from typing import List, Dict, Any, Optional, Union
import logging
import os
import json
import sys

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

try:
    from cvss import CVSS3
except ImportError:
    logger.error("CVSS module not found. Please install it with: pip install cvss")
    CVSS3 = None

try:
    import pandas as pd
    import matplotlib.pyplot as plt
except ImportError:
    logger.warning("Pandas or Matplotlib not found. Some visualization features may be limited.")
    pd = None
    plt = None

class RiskAnalyzer:
    def __init__(self, findings: Optional[List[Dict[str, Any]]] = None):
        """
        Initialize the RiskAnalyzer with findings.
        
        Args:
            findings: List of vulnerability findings, where each finding is a dictionary
                     containing at least a 'type' field
        """
        self.findings = findings or []
        self._validate_findings()
        self.compliance_frameworks = {
            'ISO27001': {
                'A.12.6.1': 'Management of technical vulnerabilities',
                'A.14.1.2': 'Securing application services on public networks',
                'A.14.1.3': 'Protecting application services transactions',
            },
            'NIST_800_53': {
                'SI-2': 'Flaw Remediation',
                'SI-3': 'Malicious Code Protection',
                'SI-4': 'Information System Monitoring',
            },
            'OWASP_TOP_10_2021': {
                'A01': 'Broken Access Control',
                'A02': 'Cryptographic Failures',
                'A03': 'Injection',
                'A04': 'Insecure Design',
                'A05': 'Security Misconfiguration',
                'A06': 'Vulnerable and Outdated Components',
                'A07': 'Identification and Authentication Failures',
                'A08': 'Software and Data Integrity Failures',
                'A09': 'Security Logging and Monitoring Failures',
                'A10': 'Server-Side Request Forgery'
            }
        }
        self.remediation_guidance = {
            'SQL Injection': {
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'remediation': [
                    'Use prepared statements with parameterized queries',
                    'Implement proper input validation',
                    'Apply the principle of least privilege',
                    'Use ORM frameworks with built-in protection'
                ],
                'compliance': {
                    'ISO27001': ['A.14.1.2', 'A.14.1.3'],
                    'NIST_800_53': ['SI-2', 'SI-4'],
                    'OWASP_TOP_10_2021': ['A03']
                }
            },
            'XSS': {
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N',
                'remediation': [
                    'Implement Content Security Policy (CSP)',
                    'Encode data on output',
                    'Use framework\'s built-in XSS protection',
                    'Implement input validation'
                ],
                'compliance': {
                    'ISO27001': ['A.14.1.3'],
                    'NIST_800_53': ['SI-4'],
                    'OWASP_TOP_10_2021': ['A03']
                }
            },
            'CSRF': {
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H',
                'remediation': [
                    'Implement CSRF tokens',
                    'Use SameSite cookie attribute',
                    'Verify request origin',
                    'Implement double submit cookie pattern'
                ],
                'compliance': {
                    'ISO27001': ['A.14.1.3'],
                    'NIST_800_53': ['SI-4'],
                    'OWASP_TOP_10_2021': ['A01']
                }
            },
            'Authentication Bypass': {
                'cvss_vector': 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H',
                'remediation': [
                    'Implement multi-factor authentication',
                    'Enforce strong password policies',
                    'Implement account lockout mechanisms',
                    'Monitor for brute force attempts'
                ],
                'compliance': {
                    'ISO27001': ['A.9.4.2', 'A.9.4.3'],
                    'NIST_800_53': ['AC-2', 'AC-7'],
                    'OWASP_TOP_10_2021': ['A07']
                }
            }
        }

    def calculate_cvss_score(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Calculate CVSS score for a finding.
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            Dictionary with CVSS scores and metadata, or None if calculation fails
        """
        if not isinstance(finding, dict):
            logger.error("Invalid finding: must be a dictionary")
            return None
            
        vuln_type = finding.get('type', 'Unknown')
        
        try:
            if not CVSS3:
                logger.warning("CVSS3 module not available. Install with: pip install cvss")
                return None
                
            if vuln_type in self.remediation_guidance:
                cvss_vector = self.remediation_guidance[vuln_type].get('cvss_vector')
                if not cvss_vector:
                    logger.warning("No CVSS vector found for vulnerability type: %s", vuln_type)
                    return None
                    
                c = CVSS3(cvss_vector)
                return {
                    'base_score': c.base_score,
                    'temporal_score': c.temporal_score,
                    'environmental_score': c.environmental_score,
                    'severity': c.severities()[0],
                    'vector': cvss_vector
                }
            return None
        except Exception as e:
            logger.error("Error calculating CVSS score: %s", str(e), exc_info=True)
            return None

    def generate_remediation(self, finding: Dict[str, Any]) -> List[str]:
        """
        Generate remediation recommendations for a finding.
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            List of remediation steps
        """
        vuln_type = finding.get('type', 'Unknown')
        if vuln_type in self.remediation_guidance:
            return self.remediation_guidance[vuln_type]['remediation']
        return ["Review the finding and consult security best practices"]

    def map_to_compliance(self, finding: Dict[str, Any]) -> Dict[str, List[str]]:
        """
        Map finding to compliance frameworks.
        
        Args:
            finding: Dictionary containing finding details
            
        Returns:
            Dictionary with compliance frameworks and controls
        """
        vuln_type = finding.get('type', 'Unknown')
        if vuln_type in self.remediation_guidance:
            return self.remediation_guidance[vuln_type]['compliance']
        return {}

    def analyze_trends(self, historical_data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyze vulnerability trends over time.
        
        Args:
            historical_data: List of dictionaries containing historical vulnerability data
            
        Returns:
            Dictionary with trend analysis results
        """
        if not historical_data:
            return {}
            
        df = pd.DataFrame(historical_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        
        # Group by vulnerability type and calculate statistics
        trends = {
            'by_severity': df.groupby('severity').size().to_dict(),
            'by_type': df.groupby('type').size().sort_values(ascending=False).head(10).to_dict(),
            'over_time': df.groupby(df['timestamp'].dt.to_period('M')).size().to_dict(),
            'new_vs_recurring': {
                'new': len(df[df['status'] == 'new']),
                'recurring': len(df[df['status'] == 'recurring'])
            }
        }
        return trends

    def _validate_findings(self) -> None:
        """
        Validate the structure of findings.
        
        Raises:
            ValueError: If findings is not a list or contains invalid items
        """
        if not isinstance(self.findings, list):
            raise ValueError("Findings must be a list of dictionaries")
            
        for i, finding in enumerate(self.findings):
            if not isinstance(finding, dict):
                raise ValueError(f"Finding at index {i} must be a dictionary")
            if 'type' not in finding:
                logger.warning("Finding at index %d is missing 'type' field", i)

    def generate_report(self, output_format: str = 'pdf', output_file: str = 'security_report') -> str:
        """
        Generate a security report in the specified format.
        
        Args:
            output_format: Output format ('pdf', 'json', or 'text')
            output_file: Base name of the output file (without extension)
            
        Returns:
            Status message indicating success or failure
        """
        output_format = output_format.lower()
        
        # Validate output format
        if output_format not in ['pdf', 'json', 'text']:
            error_msg = f"Unsupported output format: {output_format}. Must be 'pdf', 'json', or 'text'"
            logger.error(error_msg)
            return f"Error: {error_msg}"
            
        # Check if there are findings to report
        if not self.findings:
            logger.info("No findings to generate report")
            return "No findings to report"
            
        try:
            # Generate the appropriate report type
            if output_format == 'pdf':
                return self._generate_pdf_report(output_file)
            elif output_format == 'json':
                return self._generate_json_report(output_file)
            else:  # text
                return self._generate_text_report(output_file)
                
        except ImportError as e:
            error_msg = f"Required package not found: {str(e)}. "
            if 'reportlab' in str(e).lower():
                error_msg += "Please install it with: pip install reportlab"
            elif 'cvss' in str(e).lower():
                error_msg += "Please install it with: pip install cvss"
            else:
                error_msg += "Please install the required dependencies."
                
            logger.error(error_msg)
            return f"Error: {error_msg}"
            
        except Exception as e:
            error_msg = f"Error generating {output_format} report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"

    def _generate_pdf_report(self, output_file: str) -> str:
        """
        Generate a PDF report with the scan findings.
        
        Args:
            output_file: Base name for the output file (without extension)
            
        Returns:
            Status message indicating success or failure
        """
        try:
            # Import required modules with error handling
            try:
                from reportlab.lib.pagesizes import letter
                from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
                from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
                from reportlab.lib import colors
            except ImportError as e:
                error_msg = f"Required PDF generation module not found: {str(e)}. Install with: pip install reportlab"
                logger.error(error_msg)
                return f"Error: {error_msg}"
            
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_file) or '.'
            try:
                os.makedirs(output_dir, exist_ok=True)
            except OSError as e:
                error_msg = f"Failed to create output directory '{output_dir}': {str(e)}"
                logger.error(error_msg)
                return f"Error: {error_msg}"
            
            output_path = f"{output_file}.pdf"
            
            try:
                doc = SimpleDocTemplate(
                    output_path,
                    pagesize=letter,
                    rightMargin=72,
                    leftMargin=72,
                    topMargin=72,
                    bottomMargin=72
                )
                
                styles = getSampleStyleSheet()
                elements = []
                
                # Add title
                title_style = ParagraphStyle(
                    'Title',
                    parent=styles['Heading1'],
                    fontSize=18,
                    spaceAfter=20,
                    alignment=1
                )
                elements.append(Paragraph("Moodle Security Assessment Report", title_style))
                
                # Add metadata
                elements.append(Paragraph(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
                elements.append(Spacer(1, 12))
                
                # Add findings summary
                if not self.findings:
                    elements.append(Paragraph("No findings to report.", styles['Normal']))
                    doc.build(elements)
                    return f"PDF report generated: {output_path}"
                
                # Group findings by severity
                findings_by_severity = {}
                for finding in self.findings:
                    severity = finding.get('severity', 'Unknown')
                    if severity not in findings_by_severity:
                        findings_by_severity[severity] = []
                    findings_by_severity[severity].append(finding)
                
                # Add summary section
                elements.append(Paragraph("Summary", styles['Heading2']))
                
                # Prepare summary data
                summary_data = [
                    ["Severity", "Count"],
                    ["Critical", str(len(findings_by_severity.get('Critical', [])))],
                    ["High", str(len(findings_by_severity.get('High', [])))],
                    ["Medium", str(len(findings_by_severity.get('Medium', [])))],
                    ["Low", str(len(findings_by_severity.get('Low', [])))],
                    ["Info", str(len(findings_by_severity.get('Info', [])))],
                    ["Total", str(len(self.findings))]
                ]
                
                # Create summary table
                summary_table = Table(summary_data, colWidths=[200, 100])
                summary_table.setStyle(TableStyle([
                    ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#4472C4')),
                    ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                    ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                    ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                    ('FONTSIZE', (0, 0), (-1, 0), 10),
                    ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                    ('BACKGROUND', (0, 1), (-1, -1), colors.HexColor('#D9E1F2')),
                    ('TEXTCOLOR', (0, 1), (-1, -1), colors.black),
                    ('FONTNAME', (0, 1), (-1, -1), 'Helvetica'),
                    ('FONTSIZE', (0, 1), (-1, -1), 10),
                    ('BOTTOMPADDING', (0, 1), (-1, -1), 6),
                    ('GRID', (0, 0), (-1, -1), 1, colors.white),
                    ('BOX', (0, 0), (-1, -1), 1, colors.black)
                ]))
                
                elements.append(summary_table)
                elements.append(Spacer(1, 20))
                
                # Add detailed findings
                elements.append(Paragraph("Detailed Findings", styles['Heading2']))
                
                # Process each finding
                for i, finding in enumerate(self.findings, 1):
                    if i > 1:
                        elements.append(PageBreak())
                    
                    # Add finding header
                    elements.append(Paragraph(f"Finding {i}: {finding.get('type', 'Unknown')}", styles['Heading3']))
                    
                    # Add finding details
                    details = [
                        ["Severity", finding.get('severity', 'N/A')],
                        ["URL", finding.get('url', 'N/A')],
                        ["Description", finding.get('description', 'No description available')],
                        ["Risk", finding.get('risk', 'N/A')]
                    ]
                    
                    # Add CVSS score if available
                    cvss = self.calculate_cvss_score(finding)
                    if cvss:
                        details.append(["CVSS Score", f"{cvss['base_score']} ({cvss['severity']})"])
                        details.append(["CVSS Vector", cvss['vector']])
                    
                    # Create details table
                    details_table = Table(details, colWidths=[150, 350])
                    details_table.setStyle(TableStyle([
                        ('BACKGROUND', (0, 0), (0, -1), colors.HexColor('#E7E6E6')),
                        ('TEXTCOLOR', (0, 0), (0, -1), colors.black),
                        ('ALIGN', (0, 0), (0, -1), 'LEFT'),
                        ('FONTNAME', (0, 0), (0, -1), 'Helvetica-Bold'),
                        ('FONTSIZE', (0, 0), (0, -1), 9),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                        ('BACKGROUND', (1, 0), (1, -1), colors.white),
                        ('TEXTCOLOR', (1, 0), (1, -1), colors.black),
                        ('ALIGN', (1, 0), (1, -1), 'LEFT'),
                        ('FONTNAME', (1, 0), (1, -1), 'Helvetica'),
                        ('FONTSIZE', (1, 0), (1, -1), 9),
                        ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                        ('BOX', (0, 0), (-1, -1), 1, colors.black)
                    ]))
                    
                    elements.append(details_table)
                    elements.append(Spacer(1, 10))
                    
                    # Add remediation if available
                    vuln_type = finding.get('type')
                    if vuln_type and vuln_type in self.remediation_guidance:
                        elements.append(Paragraph("Remediation", styles['Heading4']))
                        for step in self.remediation_guidance[vuln_type].get('remediation', []):
                            elements.append(Paragraph(f"• {step}", styles['Normal']))
                        
                        # Add compliance information
                        compliance = self.remediation_guidance[vuln_type].get('compliance', {})
                        if compliance:
                            elements.append(Spacer(1, 10))
                            elements.append(Paragraph("Compliance", styles['Heading4']))
                            for framework, controls in compliance.items():
                                elements.append(Paragraph(f"{framework}:", styles['Italic']))
                                for control in controls:
                                    elements.append(Paragraph(f"  • {control}", styles['Normal']))
                    
                    elements.append(Spacer(1, 10))
                
                # Build the PDF
                doc.build(elements)
                logger.info(f"Successfully generated PDF report: {output_path}")
                return f"PDF report generated: {output_path}"
                
            except Exception as e:
                error_msg = f"Error building PDF document: {str(e)}"
                logger.error(error_msg, exc_info=True)
                return f"Error: {error_msg}"
                
        except Exception as e:
            error_msg = f"Error generating PDF report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"

    def _generate_json_report(self, output_file: str) -> str:
        """
        Generate a JSON report with the scan findings.
        
        Args:
            output_file: Base name for the output file (without extension)
            
        Returns:
            Status message indicating success or failure
        """
        try:
            if not self.findings:
                logger.warning("No findings to generate JSON report")
                return "Warning: No findings to report"

            # Prepare report data
            report = {
                'metadata': {
                    'generated_at': datetime.now().isoformat(),
                    'target': self.findings[0].get('target', 'N/A'),
                    'total_findings': len(self.findings),
                    'summary': {
                        'critical': 0,
                        'high': 0,
                        'medium': 0,
                        'low': 0,
                        'info': 0,
                        'unknown': 0
                    }
                },
                'findings': []
            }

            # Calculate severity counts and prepare findings
            for finding in self.findings:
                # Update severity counts
                severity = finding.get('severity', 'unknown').lower()
                if severity in report['metadata']['summary']:
                    report['metadata']['summary'][severity] += 1
                else:
                    report['metadata']['summary']['unknown'] += 1

                # Prepare finding data
                finding_data = finding.copy()
                
                # Add CVSS score if available
                cvss = self.calculate_cvss_score(finding)
                if cvss:
                    finding_data['cvss'] = cvss
                
                # Add remediation and compliance if available
                vuln_type = finding.get('type')
                if vuln_type and vuln_type in self.remediation_guidance:
                    finding_data['remediation'] = self.remediation_guidance[vuln_type].get('remediation', [])
                    finding_data['compliance'] = self.remediation_guidance[vuln_type].get('compliance', {})
                
                report['findings'].append(finding_data)

            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_file) or '.'
            os.makedirs(output_dir, exist_ok=True)
            
            # Ensure the output file has .json extension
            if not output_file.lower().endswith('.json'):
                output_file = f"{output_file}.json"
            
            # Write JSON file with pretty printing
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False, default=str)
                
            logger.info(f"Successfully generated JSON report: {output_file}")
            return f"JSON report generated: {output_file}"
            
        except (IOError, OSError) as e:
            error_msg = f"Error writing to file {output_file}: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except json.JSONEncodeError as e:
            error_msg = f"Error encoding JSON data: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
        except Exception as e:
            error_msg = f"Unexpected error generating JSON report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"

    def _generate_text_report(self, output_file: str) -> str:
        """
        Generate a plain text report with the scan findings.
        
        Args:
            output_file: Base name for the output file (without extension)
            
        Returns:
            Status message indicating success or failure
        """
        try:
            # Prepare report header
            report_lines = [
                "Moodle Security Assessment Report",
                "=" * 50,
                f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
                f"Target: {self.findings[0].get('target', 'N/A') if self.findings else 'N/A'}",
                "\nSummary",
                "-" * 50,
                f"Total Findings: {len(self.findings)}",
                f"Critical: {len([f for f in self.findings if f.get('severity') == 'Critical'])}",
                f"High: {len([f for f in self.findings if f.get('severity') == 'High'])}",
                f"Medium: {len([f for f in self.findings if f.get('severity') == 'Medium'])}",
                f"Low: {len([f for f in self.findings if f.get('severity') == 'Low'])}",
                f"Info: {len([f for f in self.findings if f.get('severity') == 'Info'])}",
                "\n" + "Detailed Findings".ljust(50, '-'),
            ]
            
            # Process each finding
            for i, finding in enumerate(self.findings, 1):
                try:
                    # Add finding header
                    report_lines.extend([
                        f"\n{i}. {finding.get('type', 'Finding')} - {finding.get('severity', 'Unspecified')}",
                        f"   URL: {finding.get('url', 'N/A')}",
                        f"   Description: {finding.get('description', 'No description')}",
                        f"   Risk: {finding.get('risk', 'N/A')}"
                    ])
                    
                    # Add CVSS score if available
                    cvss = self.calculate_cvss_score(finding)
                    if cvss and 'base_score' in cvss and 'severity' in cvss:
                        report_lines.append(f"   CVSS Score: {cvss['base_score']} ({cvss['severity']})")
                        if 'vector' in cvss:
                            report_lines.append(f"   CVSS Vector: {cvss['vector']}")
                    
                    # Add remediation if available
                    vuln_type = finding.get('type')
                    if vuln_type and vuln_type in self.remediation_guidance:
                        report_lines.append("\n   Remediation:")
                        for step in self.remediation_guidance[vuln_type].get('remediation', []):
                            report_lines.append(f"     • {step}")
                        
                        # Add compliance information
                        compliance = self.remediation_guidance[vuln_type].get('compliance', {})
                        if compliance:
                            report_lines.append("\n   Compliance:")
                            for framework, controls in compliance.items():
                                report_lines.append(f"     {framework}:")
                                for control in controls:
                                    report_lines.append(f"       • {control}")
                    
                    report_lines.append("\n" + "-" * 50)
                    
                except Exception as e:
                    logger.error(f"Error processing finding {i}: {str(e)}", exc_info=True)
                    report_lines.append(f"\n   [Error processing finding: {str(e)}]")
            
            # Create output directory if it doesn't exist
            output_dir = os.path.dirname(output_file) or '.'
            os.makedirs(output_dir, exist_ok=True)
            
            # Write the text report
            output_path = f"{output_file}.txt"
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write("\n".join(report_lines))
                
            logger.info(f"Successfully generated text report: {output_path}")
            return f"Text report generated: {output_path}"
            
        except (IOError, OSError) as e:
            error_msg = f"Error writing text report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"
            
        except Exception as e:
            error_msg = f"Error generating text report: {str(e)}"
            logger.error(error_msg, exc_info=True)
            return f"Error: {error_msg}"

    def plot_trends(self, historical_data, output_file='trends.png'):
        """Generate trend visualization"""
        if not historical_data:
            return "No historical data available for trend analysis"
            
        if pd is None or plt is None:
            return "Pandas or Matplotlib not installed. Cannot generate trend plot."
            
        df = pd.DataFrame(historical_data)
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['date'] = df['timestamp'].dt.date
        
        # Group by date and severity
        trends = df.groupby(['date', 'severity']).size().unstack(fill_value=0)
        
        # Plot
        plt.figure(figsize=(12, 6))
        trends.plot(kind='line', marker='o')
        plt.title('Vulnerability Trends Over Time')
        plt.xlabel('Date')
        plt.ylabel('Number of Findings')
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(output_file)
        plt.close()
        
        return f"Trend visualization saved as {output_file}"
