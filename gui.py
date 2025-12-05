# gui.py
import sys
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, 
                             QHBoxLayout, QLabel, QLineEdit, QPushButton, 
                             QTextEdit, QTableWidget, QTableWidgetItem,
                             QProgressBar, QTabWidget, QGroupBox, QHeaderView,
                             QMessageBox, QSplitter, QComboBox, QCheckBox, QFileDialog)
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QFont, QColor
import json
from datetime import datetime

from scanner_core import MoodleScanner
from risk_analyzer import RiskAnalyzer

class ScanThread(QThread):
    update_progress = pyqtSignal(str, int)
    scan_finished = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self, target_url, scan_types):
        super().__init__()
        self.target_url = target_url
        self.scan_types = scan_types
        self.scanner = None
        self._is_running = True
        
    def run(self):
        try:
            self.scanner = MoodleScanner(self.target_url)
            self.update_progress.emit("Starting scan...", 10)
            
            # Run the scan and get results as a dictionary
            results = self.scanner.comprehensive_scan()
            
            if self._is_running:  # Only proceed if not stopped
                self.update_progress.emit("Processing results...", 90)
                self.scan_finished.emit(results)
                self.update_progress.emit("Scan completed!", 100)
            
        except Exception as e:
            if self._is_running:  # Only emit error if not stopped
                self.error_occurred.emit(str(e))
    
    def stop(self):
        """Safely stop the scan thread"""
        self._is_running = False
        if self.scanner:
            # Add any cleanup for the scanner if needed
            pass
        self.quit()

class MoodleScannerGUI(QMainWindow):
    def __init__(self):
        super().__init__()
        self.init_ui()
        self.scan_thread = None
        
    def init_ui(self):
        self.setWindowTitle("Moodle Vulnerability Scanner")
        self.setGeometry(100, 100, 1200, 800)
        
        # Central widget
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        
        # Main layout
        layout = QVBoxLayout(central_widget)
        
        # Target input section
        target_group = QGroupBox("Scan Target")
        target_layout = QHBoxLayout(target_group)
        
        target_layout.addWidget(QLabel("Moodle URL:"))
        self.target_input = QLineEdit()
        self.target_input.setPlaceholderText("https://your-moodle-site.com")
        target_layout.addWidget(self.target_input)
        
        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        target_layout.addWidget(self.scan_button)
        
        self.stop_button = QPushButton("Stop Scan")
        self.stop_button.clicked.connect(self.stop_scan)
        self.stop_button.setEnabled(False)
        target_layout.addWidget(self.stop_button)
        
        layout.addWidget(target_group)
        
        # Progress section
        self.progress_label = QLabel("Ready to scan")
        layout.addWidget(self.progress_label)
        
        self.progress_bar = QProgressBar()
        layout.addWidget(self.progress_bar)
        
        # Results tabs
        self.tabs = QTabWidget()
        layout.addWidget(self.tabs)
        
        # Results table
        self.results_table = QTableWidget()
        self.results_table.setColumnCount(6)
        self.results_table.setHorizontalHeaderLabels([
            "Severity", "Type", "URL", "Description", "Timestamp", "Details"
        ])
        self.results_table.horizontalHeader().setSectionResizeMode(QHeaderView.Interactive)
        self.results_table.setColumnWidth(0, 80)  # Severity
        self.results_table.setColumnWidth(1, 120)  # Type
        self.results_table.setColumnWidth(2, 250)  # URL
        self.results_table.setColumnWidth(3, 400)  # Description
        self.results_table.setColumnWidth(4, 150)  # Timestamp
        self.results_table.setColumnWidth(5, 80)   # Details button
        self.tabs.addTab(self.results_table, "Scan Results")
        
        # Details text area
        self.details_text = QTextEdit()
        self.details_text.setReadOnly(True)
        self.tabs.addTab(self.details_text, "Detailed Report")
        
        # Actions layout
        actions_layout = QHBoxLayout()
        self.export_button = QPushButton("Export Report")
        self.export_button.clicked.connect(self.export_report)
        actions_layout.addWidget(self.export_button)
        
        self.analyze_button = QPushButton("Analyze Risks")
        self.analyze_button.clicked.connect(self.run_risk_analysis)
        self.analyze_button.setEnabled(False)  # Disabled until scan completes
        actions_layout.addWidget(self.analyze_button)
        
        self.clear_button = QPushButton("Clear Results")
        self.clear_button.clicked.connect(self.clear_results)
        actions_layout.addWidget(self.clear_button)
        
        layout.addLayout(actions_layout)
        
        # Connect table selection
        self.results_table.itemSelectionChanged.connect(self.show_finding_details)
        
    def start_scan(self):
        target_url = self.target_input.text().strip()
        if not target_url:
            QMessageBox.warning(self, "Error", "Please enter a target URL")
            return
            
        # Disable scan button, enable stop button
        self.scan_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        
        # Clear previous results
        self.clear_results()
        
        # Start scan thread
        self.scan_thread = ScanThread(target_url, [])
        self.scan_thread.update_progress.connect(self.update_progress)
        self.scan_thread.scan_finished.connect(self.scan_completed)
        self.scan_thread.error_occurred.connect(self.scan_error)
        self.scan_thread.start()
        
    def stop_scan(self):
        if self.scan_thread and self.scan_thread.isRunning():
            self.scan_thread.terminate()
            self.scan_thread.wait()
            self.update_progress("Scan stopped by user", 0)
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            
    def update_progress(self, message, value):
        self.progress_label.setText(message)
        self.progress_bar.setValue(value)
        
    def scan_completed(self, results):
        """Handle scan completion with results in dictionary format"""
        try:
            # Extract findings from results dictionary
            findings = results.get('findings', [])
            
            # Display the findings in the table
            self.display_findings(findings)
            
            # Update UI state
            self.scan_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.analyze_button.setEnabled(True)
            self.update_progress("Scan completed successfully!", 100)
            
            # Store complete results for later analysis
            self.current_results = results
            self.current_findings = findings
            
            # Get summary from results or calculate it
            if 'summary' in results and 'by_severity' in results['summary']:
                summary = results['summary']['by_severity']
                critical = summary.get('Critical', 0)
                high = summary.get('High', 0)
                medium = summary.get('Medium', 0)
                low = summary.get('Low', 0)
                info = summary.get('Info', 0)
            else:
                # Fallback to calculating from findings
                critical = len([f for f in findings if f.get('severity') == 'Critical'])
                high = len([f for f in findings if f.get('severity') == 'High'])
                medium = len([f for f in findings if f.get('severity') == 'Medium'])
                low = len([f for f in findings if f.get('severity') == 'Low'])
                info = len([f for f in findings if f.get('severity') == 'Info'])
            
            # Show scan summary
            scan_time = ""
            if 'start_time' in results and 'end_time' in results:
                try:
                    from datetime import datetime
                    start = datetime.fromisoformat(results['start_time'])
                    end = datetime.fromisoformat(results['end_time'])
                    duration = end - start
                    scan_time = f"\nDuration: {duration.total_seconds():.1f} seconds"
                except (ValueError, TypeError):
                    pass
            
            QMessageBox.information(
                self, 
                "Scan Complete",
                f"Scan of {results.get('target', 'target')} completed!{scan_time}\n\n"
                f"Findings Summary:\n"
                f" Critical: {critical}\n"
                f" High: {high}\n"
                f" Medium: {medium}\n"
                f" Low: {low}\n"
                f" Info: {info}"
            )
            
        except Exception as e:
            self.scan_error(f"Error processing scan results: {str(e)}")
        
    def scan_error(self, error_message):
        QMessageBox.critical(self, "Scan Error", f"An error occurred during scanning:\n{error_message}")
        self.scan_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.update_progress("Scan failed", 0)
        
    def display_findings(self, findings):
        self.results_table.setRowCount(len(findings))
        
        if len(findings) == 0:
            self.generate_detailed_report(findings)
            return
        
        severity_colors = {
            'Critical': QColor(255, 200, 200),  # Light red
            'High': QColor(255, 220, 180),      # Light orange
            'Medium': QColor(255, 255, 180),    # Light yellow
            'Low': QColor(200, 230, 255),       # Light blue
            'Info': QColor(240, 240, 240),      # Light gray
            'Error': QColor(255, 180, 180)      # Light red for errors
        }
        
        text_colors = {
            'Critical': QColor(200, 0, 0),      # Dark red
            'High': QColor(180, 90, 0),         # Dark orange
            'Medium': QColor(180, 180, 0),      # Dark yellow
            'Low': QColor(0, 0, 200),           # Dark blue
            'Info': QColor(80, 80, 80),         # Dark gray
            'Error': QColor(200, 0, 0)          # Dark red for errors
        }
        
        # Sort findings by severity
        severity_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3, 'Info': 4, 'Error': 0}
        findings_sorted = sorted(findings, key=lambda x: severity_order.get(x.get('severity', 'Info'), 4))
        
        for row, finding in enumerate(findings_sorted):
            severity = finding.get('severity', 'Info')
            
            # Severity
            severity_item = QTableWidgetItem(severity)
            severity_item.setBackground(severity_colors.get(severity, QColor(255, 255, 255)))
            severity_item.setForeground(text_colors.get(severity, QColor(0, 0, 0)))
            severity_item.setFlags(severity_item.flags() & ~Qt.ItemIsEditable)
            self.results_table.setItem(row, 0, severity_item)
            
            # Type
            type_item = QTableWidgetItem(finding.get('type', 'N/A'))
            type_item.setFlags(type_item.flags() & ~Qt.ItemIsEditable)
            self.results_table.setItem(row, 1, type_item)
            
            # URL
            url = finding.get('url', 'N/A')
            url_item = QTableWidgetItem(url[:100] + '...' if len(url) > 100 else url)
            url_item.setToolTip(url)
            url_item.setFlags(url_item.flags() & ~Qt.ItemIsEditable)
            self.results_table.setItem(row, 2, url_item)
            
            # Description
            description = finding.get('description', 'No description')
            desc_item = QTableWidgetItem(description)
            desc_item.setToolTip(description)
            desc_item.setFlags(desc_item.flags() & ~Qt.ItemIsEditable)
            self.results_table.setItem(row, 3, desc_item)
            
            # Timestamp
            timestamp = finding.get('timestamp', 'N/A')
            time_item = QTableWidgetItem(timestamp)
            time_item.setFlags(time_item.flags() & ~Qt.ItemIsEditable)
            self.results_table.setItem(row, 4, time_item)
            
            # Details button
            details_btn = QPushButton('View')
            details_btn.setProperty('row', row)
            details_btn.clicked.connect(lambda _, r=row: self.show_finding_details(r))
            self.results_table.setCellWidget(row, 5, details_btn)
        # Generate detailed report
        self.generate_detailed_report(findings)
        
    def generate_detailed_report(self, findings):
        report = f"Moodle Security Assessment Report\n"
        report += "=" * 50 + "\n\n"
        report += f"Target: {self.target_input.text()}\n"
        report += f"Scan Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        
        if len(findings) == 0:
            report += "No security vulnerabilities were detected during this scan.\n"
            report += "The target appears to be secure or may not be a Moodle installation.\n\n"
            report += "Note: This scan checks for common vulnerabilities but may not detect\n"
            report += "all possible security issues. Regular security assessments are recommended.\n"
        else:
            # Group by severity
            by_severity = {}
            for finding in findings:
                severity = finding['severity']
                if severity not in by_severity:
                    by_severity[severity] = []
                by_severity[severity].append(finding)
                
            for severity in ['Critical', 'High', 'Medium', 'Low', 'Info']:
                if severity in by_severity:
                    report += f"\n{severity} Severity Findings ({len(by_severity[severity])}):\n"
                    report += "-" * 40 + "\n"
                    for finding in by_severity[severity]:
                        report += f"Type: {finding['type']}\n"
                        report += f"URL: {finding['url']}\n"
                        report += f"Description: {finding['description']}\n\n"
                    
        self.details_text.setText(report)
        
    def show_finding_details(self, row=None):
        """Show details for a finding, either from table selection or button click"""
        if row is None:
            # Called from table selection
            selected_items = self.results_table.selectedItems()
            if not selected_items:
                return
            row = selected_items[0].row()
        
        # Get finding details from the table
        severity_item = self.results_table.item(row, 0)
        type_item = self.results_table.item(row, 1)
        url_item = self.results_table.item(row, 2)
        desc_item = self.results_table.item(row, 3)
        
        if not all([severity_item, type_item, url_item, desc_item]):
            return
            
        finding_type = type_item.text()
        url = url_item.text()
        description = desc_item.text()
        severity = severity_item.text()
        
        details = f"Finding Details:\n\n"
        details += f"Severity: {severity}\n"
        details += f"Type: {finding_type}\n"
        details += f"URL: {url}\n"
        details += f"Description: {description}\n\n"
        details += f"Recommendation: {self.get_recommendation(finding_type)}"
        
        # Show in the details tab
        self.tabs.setCurrentIndex(1)  # Switch to details tab
        self.details_text.setText(details)
            
    def get_recommendation(self, finding_type):
        recommendations = {
            'SQL Injection': 'Implement proper input validation and use prepared statements.',
            'Cross-Site Scripting (XSS)': 'Implement output encoding and content security policy.',
            'Directory Listing': 'Disable directory listing in web server configuration.',
            'Information Disclosure': 'Restrict access to sensitive files and directories.',
            'Exposed Files': 'Remove or restrict access to backup and configuration files.'
        }
        return recommendations.get(finding_type, 'Review the finding and implement appropriate security measures.')
        
    def run_risk_analysis(self):
        if not hasattr(self, 'current_findings') or not self.current_findings:
            QMessageBox.warning(self, "No Data", "No scan results available for analysis")
            return
            
        try:
            self.update_progress("Running risk analysis...", 0)
            analyzer = RiskAnalyzer(self.current_findings)
            
            # Generate and display risk analysis
            report = analyzer.generate_report(output_format='txt', output_file='risk_analysis')
            
            # Show analysis in the details tab
            self.tabs.setCurrentIndex(1)  # Switch to details tab
            self.details_text.clear()
            self.details_text.append("=== RISK ANALYSIS REPORT ===\n")
            
            # Add summary
            risk_scores = [f.get('cvss', {}).get('base_score', 0) for f in self.current_findings 
                          if f.get('cvss') and f['cvss'].get('base_score')]
            
            if risk_scores:
                avg_risk = sum(risk_scores) / len(risk_scores)
                self.details_text.append(f"Average CVSS Score: {avg_risk:.1f}/10")
                
                # Count by severity
                severities = {}
                for f in self.current_findings:
                    sev = f.get('severity', 'Unknown')
                    severities[sev] = severities.get(sev, 0) + 1
                
                self.details_text.append("\nSeverity Distribution:")
                for sev, count in severities.items():
                    self.details_text.append(f"- {sev}: {count} findings")
            
            # Add top recommendations
            self.details_text.append("\n=== TOP RECOMMENDATIONS ===")
            analyzer = RiskAnalyzer(self.current_findings)
            for finding in self.current_findings[:5]:  # Show top 5 findings
                recs = analyzer.generate_remediation(finding)
                if recs:
                    self.details_text.append(f"\n{finding.get('type', 'Finding')} (Severity: {finding.get('severity', 'N/A')})")
                    for rec in recs[:3]:  # Show top 3 recommendations per finding
                        self.details_text.append(f"- {rec}")
            
            self.update_progress("Risk analysis completed", 100)
            
        except Exception as e:
            QMessageBox.critical(self, "Analysis Error", f"Error during risk analysis: {str(e)}")
            self.update_progress("Risk analysis failed", 0)
    
    def run_tests(self):
        """Run test cases for the scanner"""
        from unittest.mock import patch, MagicMock
        import unittest
        from io import StringIO
        import sys
        
        class TestMoodleScanner(unittest.TestCase):
            @classmethod
            def setUpClass(cls):
                cls.test_url = "http://test-moodle.local"
                cls.scanner = MoodleScanner(cls.test_url)
                
            def test_initialization(self):
                self.assertEqual(self.scanner.target_url, self.test_url)
                self.assertIsNotNone(self.scanner.session)
                
            @patch('scanner_core.requests.Session')
            def test_scan_sql_injection(self, mock_session):
                # Mock response for SQL injection test
                mock_response = MagicMock()
                mock_response.status_code = 200
                mock_response.text = "You have an error in your SQL syntax"
                mock_session.return_value.get.return_value = mock_response
                
                findings = self.scanner.scan_sql_injection()
                self.assertGreater(len(findings), 0)
                self.assertEqual(findings[0]['type'], 'SQL Injection')
        
        # Redirect stdout to capture test output
        old_stdout = sys.stdout
        sys.stdout = StringIO()
        
        # Run tests
        suite = unittest.TestLoader().loadTestsFromTestCase(TestMoodleScanner)
        test_result = unittest.TextTestRunner(stream=sys.stdout, verbosity=2).run(suite)
        
        # Get test output
        test_output = sys.stdout.getvalue()
        sys.stdout = old_stdout
        
        # Show test results in details tab
        self.tabs.setCurrentIndex(1)
        self.details_text.clear()
        self.details_text.append("=== TEST RESULTS ===\n")
        self.details_text.append(test_output)
        
        # Show summary message
        if test_result.wasSuccessful():
            QMessageBox.information(self, "Tests Passed", "All tests completed successfully!")
            self.update_progress("Tests completed successfully", 100)
        else:
            QMessageBox.warning(self, "Tests Failed", 
                              f"{len(test_result.failures)} test(s) failed. See details in the report.")
            self.update_progress("Some tests failed", 100)
    
    def export_report(self):
        """Export the current scan results to a file"""
        if not hasattr(self, 'current_findings') or not self.current_findings:
            QMessageBox.warning(self, "No Data", "No scan results to export")
            return
            
        try:
            options = QFileDialog.Options()
            file_name, _ = QFileDialog.getSaveFileName(
                self,
                "Save Report",
                "moodle_scan_report.html",
                "HTML Files (*.html);;Text Files (*.txt);;All Files (*)",
                options=options
            )
            
            if file_name:
                analyzer = RiskAnalyzer(self.current_findings)
                
                # Determine format from file extension
                if file_name.lower().endswith('.json'):
                    report_format = 'json'
                elif file_name.lower().endswith('.txt'):
                    report_format = 'txt'
                else:
                    report_format = 'pdf'
                    if not file_name.lower().endswith('.pdf'):
                        file_name += '.pdf'
                
                # Generate report
                analyzer.generate_report(
                    output_format=report_format,
                    output_file=file_name
                )
                
                QMessageBox.information(self, "Export Successful", 
                                      f"Report saved to:\n{file_name}")
                
        except Exception as e:
            QMessageBox.critical(self, "Export Failed", 
                               f"Error exporting report: {str(e)}")
    
    def clear_results(self):
        self.results_table.setRowCount(0)
        self.details_text.clear()
        
        self.current_findings = []
        self.current_results = None
        self.progress_bar.setValue(0)
        self.progress_label.setText("Ready to scan")
        self.analyze_button.setEnabled(False)  # Disable analyze button when results are cleared

if __name__ == "__main__":
    app = QApplication(sys.argv)
    scanner_gui = MoodleScannerGUI()
    scanner_gui.show()
    sys.exit(app.exec_())