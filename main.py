# main.py
import sys
import traceback
from PyQt5.QtWidgets import QApplication, QMessageBox

def handle_exception(exc_type, exc_value, exc_traceback):
    """Handle uncaught exceptions"""
    error_msg = ""
    error_msg += f"Error Type: {exc_type.__name__}\n"
    error_msg += f"Error Value: {str(exc_value)}\n\n"
    error_msg += "Traceback (most recent call last):\n"
    
    # Get the traceback as a list of strings
    tb_list = traceback.format_tb(exc_traceback)
    error_msg += "".join(tb_list)
    
    # Log to console
    print("\n" + "="*50 + " ERROR " + "="*50)
    print(error_msg)
    print("="*108 + "\n")
    
    # Show error dialog
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Critical)
    msg.setWindowTitle("Error")
    msg.setText("An error occurred in the application.")
    msg.setDetailedText(error_msg)
    msg.setStandardButtons(QMessageBox.Ok)
    msg.exec_()

def main():
    # Set up exception handling
    sys.excepthook = handle_exception
    
    try:
        # Initialize QApplication
        app = QApplication(sys.argv)
        app.setApplicationName("Moodle Vulnerability Scanner")
        app.setApplicationVersion("1.0")
        
        # Import GUI after QApplication is created
        from gui import MoodleScannerGUI
        
        # Create and show main window
        window = MoodleScannerGUI()
        window.show()
        
        # Start the application event loop
        sys.exit(app.exec_())
        
    except Exception as e:
        # This will be caught by the excepthook
        print(f"Fatal error in main: {str(e)}")
        raise

if __name__ == "__main__":
    main()