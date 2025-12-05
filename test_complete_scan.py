#!/usr/bin/env python3
"""
Test script to verify complete scan flow
"""
import sys
from PyQt5.QtWidgets import QApplication
from gui import MoodleScannerGUI, ScanThread
from PyQt5.QtCore import QCoreApplication

def test_complete_scan():
    """Test the complete scan flow with a real target"""
    app = QApplication(sys.argv)
    
    # Create GUI instance
    scanner_gui = MoodleScannerGUI()
    
    # Set test URL
    test_url = "https://httpbin.org"
    scanner_gui.target_input.setText(test_url)
    
    # Create and start scan thread
    scan_thread = ScanThread(test_url, [])
    
    # Track scan completion
    scan_completed = False
    scan_results = None
    
    def on_scan_completed(results):
        nonlocal scan_completed, scan_results
        scan_completed = True
        scan_results = results
        print(f"Scan completed with {len(results.get('findings', []))} findings")
        
        # Display results
        scanner_gui.display_findings(results.get('findings', []))
        
        # Verify results are displayed
        row_count = scanner_gui.results_table.rowCount()
        print(f"Table has {row_count} rows")
        
        # Verify summary dialog would show correct counts
        findings = results.get('findings', [])
        critical = len([f for f in findings if f.get('severity') == 'Critical'])
        high = len([f for f in findings if f.get('severity') == 'High'])
        medium = len([f for f in findings if f.get('severity') == 'Medium'])
        low = len([f for f in findings if f.get('severity') == 'Low'])
        info = len([f for f in findings if f.get('severity') == 'Info'])
        
        print(f"Findings summary: Critical={critical}, High={high}, Medium={medium}, Low={low}, Info={info}")
    
    def on_scan_error(error):
        print(f"Scan error: {error}")
        scan_completed = True
    
    # Connect signals
    scan_thread.scan_finished.connect(on_scan_completed)
    scan_thread.error_occurred.connect(on_scan_error)
    
    # Start scan
    print(f"Starting scan of {test_url}...")
    scan_thread.start()
    
    # Wait for scan to complete (with timeout)
    timeout = 30  # seconds
    for i in range(timeout * 10):  # Check every 0.1 seconds
        app.processEvents()
        if scan_completed:
            break
        if i % 10 == 0:  # Print progress every second
            print(f"Waiting... ({i//10}s)")
    
    # Clean up
    if scan_thread.isRunning():
        scan_thread.terminate()
        scan_thread.wait()
    
    if scan_completed and scan_results:
        print("Complete scan test passed!")
        return True
    else:
        print("Scan did not complete within timeout")
        return False

if __name__ == "__main__":
    success = test_complete_scan()
    sys.exit(0 if success else 1)
