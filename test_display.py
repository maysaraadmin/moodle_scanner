#!/usr/bin/env python3
"""
Test script to verify scan results display functionality
"""
import sys
from PyQt5.QtWidgets import QApplication
from gui import MoodleScannerGUI
from scanner_core import MoodleScanner

def test_scan_display():
    """Test that scan results are properly displayed"""
    app = QApplication(sys.argv)
    
    # Create GUI instance
    scanner_gui = MoodleScannerGUI()
    
    # Create test scan results
    test_findings = [
        {
            'type': 'SQL Injection',
            'severity': 'High',
            'url': 'https://example.com/test',
            'description': 'Potential SQL injection vulnerability',
            'timestamp': '2025-12-05 13:30:00'
        },
        {
            'type': 'Information Disclosure',
            'severity': 'Medium',
            'url': 'https://example.com/info',
            'description': 'Sensitive information exposed',
            'timestamp': '2025-12-05 13:31:00'
        }
    ]
    
    # Test display_findings method
    scanner_gui.display_findings(test_findings)
    
    # Verify table has correct number of rows
    assert scanner_gui.results_table.rowCount() == len(test_findings), "Table row count mismatch"
    
    # Verify table content
    for row, finding in enumerate(test_findings):
        # Check severity
        severity_item = scanner_gui.results_table.item(row, 0)
        assert severity_item is not None, f"Severity item missing at row {row}"
        assert severity_item.text() == finding['severity'], f"Severity mismatch at row {row}"
        
        # Check type
        type_item = scanner_gui.results_table.item(row, 1)
        assert type_item is not None, f"Type item missing at row {row}"
        assert type_item.text() == finding['type'], f"Type mismatch at row {row}"
        
        # Check URL
        url_item = scanner_gui.results_table.item(row, 2)
        assert url_item is not None, f"URL item missing at row {row}"
        assert finding['url'] in url_item.text(), f"URL mismatch at row {row}"
        
        # Check description
        desc_item = scanner_gui.results_table.item(row, 3)
        assert desc_item is not None, f"Description item missing at row {row}"
        assert desc_item.text() == finding['description'], f"Description mismatch at row {row}"
    
    # Test empty findings
    scanner_gui.display_findings([])
    assert scanner_gui.results_table.rowCount() == 0, "Table should be empty with no findings"
    
    print("Display test passed!")
    print(f"Successfully displayed {len(test_findings)} findings")

if __name__ == "__main__":
    test_scan_display()
