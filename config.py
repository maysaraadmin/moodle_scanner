"""
Configuration settings for Moodle Security Scanner.
"""

import json
import os
from pathlib import Path

class Config:
    # Application settings
    APP_NAME = "Moodle Security Scanner"
    VERSION = "1.1.0"
    
    # Scanner settings
    DEFAULT_TIMEOUT = 15  # Increased from 10 to 15 seconds for slow servers
    MAX_RETRIES = 3
    REQUEST_DELAY = 1.0  # Delay between requests in seconds
    MAX_CONCURRENT_REQUESTS = 5
    
    # User agent settings
    USER_AGENT = f"{APP_NAME}/{VERSION} (Security Assessment Tool; +https://example.com/security)"
    
    # Common Moodle paths to scan (expanded list)
    COMMON_PATHS = [
        "/admin", "/admin/tool/securitycheck/",
        "/login", "/login/index.php",
        "/user", "/user/profile.php", "/user/edit.php",
        "/course", "/course/view.php", "/course/edit.php",
        "/pluginfile.php",
        "/webservice", "/webservice/rest/server.php",
        "/lib/ajax/service.php",
        "/badges", "/badges/mybadges.php",
        "/grade", "/grade/report/grader/index.php",
        "/message", "/message/index.php",
        "/backup", "/backup/backupfiles.html",
        "/config.php", "/config-dist.php",
        "/install.php",
        "/phpunit/",
        "/vendor/",
        "/node_modules/"
    ]
    
    # File extensions to check for information disclosure
    SENSITIVE_FILE_EXTENSIONS = [
        '.sql', '.bak', '.old', '.swp', '.swo', '.log',
        '.inc', '.conf', '.config', '.ini', '.env',
        '.pem', '.key', '.crt', '.csr', '.p12',
        '.git', '.svn', '.DS_Store', '.htaccess', '.htpasswd'
    ]
    
    # Vulnerability detection patterns
    VULNERABILITY_SIGNATURES = {
        "sql_injection": [
            r"(mysql|mysqli|pdo|postgres|sqlite)_",
            r"SQL syntax.*MySQL",
            r"Warning: mysql",
            r"Unclosed quotation mark",
            r"quoted string not properly terminated",
            r"You have an error in your SQL syntax"
        ],
        "xss": [
            r"<script[^>]*>alert\([^<]*</script>",
            r"onerror=\"[^\"]*\"",
            r"javascript:",
            r"<iframe",
            r"<img[^>]*onerror="
        ],
        "path_traversal": [
            r"\.\./" * 3,  # Matches ../../..
            r"%2e%2e%2f" * 3,  # URL-encoded ../
            r"\\..\\..\\..\\"  # Windows-style path traversal
        ],
        "file_inclusion": [
            r"(include|require)(_once)?\s*\([^)]*\$[^)]*\)",
            r"fopen\s*\([^)]*\$[^)]*\)",
            r"file_get_contents\s*\([^)]*\$[^)]*\)"
        ]
    }
    
    # Default report settings
    REPORT_SETTINGS = {
        'output_dir': 'reports',
        'format': 'txt',  # txt, html, json, pdf
        'include_timestamp': True,
        'include_request_response': False
    }
    
    # Logging configuration
    LOGGING = {
        'level': 'INFO',  # DEBUG, INFO, WARNING, ERROR, CRITICAL
        'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        'file': 'moodle_scanner.log',
        'max_size': 10485760,  # 10MB
        'backup_count': 5
    }
    
    @classmethod
    def load_from_file(cls, filename):
        """Load configuration from a JSON file.
        
        Args:
            filename (str): Path to the configuration file.
            
        Raises:
            FileNotFoundError: If the configuration file does not exist.
            json.JSONDecodeError: If the configuration file is not valid JSON.
        """
        if not os.path.exists(filename):
            raise FileNotFoundError(f"Configuration file not found: {filename}")
            
        with open(filename, 'r', encoding='utf-8') as f:
            try:
                data = json.load(f)
                for key, value in data.items():
                    if hasattr(cls, key.upper()):
                        setattr(cls, key.upper(), value)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid configuration file: {e}")
    
    @classmethod
    def save_to_file(cls, filename):
        """Save current configuration to a JSON file.
        
        Args:
            filename (str): Path where to save the configuration.
        """
        config_data = {
            key: getattr(cls, key) 
            for key in dir(cls) 
            if key.isupper() and not key.startswith('__')
        }
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(os.path.abspath(filename)), exist_ok=True)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(config_data, f, indent=4, sort_keys=True)
    
    @classmethod
    def get_default_config_path(cls):
        """Get the default configuration file path.
        
        Returns:
            str: Path to the default configuration file.
        """
        return os.path.join(os.path.expanduser('~'), '.moodle_scanner', 'config.json')
    
    @classmethod
    def setup_default_config(cls):
        """Set up default configuration file if it doesn't exist."""
        config_path = cls.get_default_config_path()
        if not os.path.exists(config_path):
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            cls.save_to_file(config_path)
            return config_path
        return None