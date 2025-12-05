#!/usr/bin/env python3
"""
Test script to verify GUI functionality
"""
import sys
from PyQt5.QtWidgets import QApplication
from gui import MoodleScannerGUI

def test_gui():
    """Test the GUI initialization"""
    app = QApplication(sys.argv)
    
    # Create GUI instance
    scanner_gui = MoodleScannerGUI()
    
    # Test that all widgets are initialized
    assert scanner_gui.target_input is not None, "Target input not initialized"
    assert scanner_gui.scan_button is not None, "Scan button not initialized"
    assert scanner_gui.stop_button is not None, "Stop button not initialized"
    assert scanner_gui.results_table is not None, "Results table not initialized"
    assert scanner_gui.details_text is not None, "Details text not initialized"
    assert scanner_gui.analyze_button is not None, "Analyze button not initialized"
    
    # Test initial states
    assert scanner_gui.stop_button.isEnabled() == False, "Stop button should be disabled initially"
    assert scanner_gui.analyze_button.isEnabled() == False, "Analyze button should be disabled initially"
    
    print("GUI test passed!")
    
    # Show the GUI
    scanner_gui.show()
    
    # Uncomment to run the GUI interactively
    # sys.exit(app.exec_())

if __name__ == "__main__":
    test_gui()
