#!/usr/bin/env python3
"""
Configuration management module
"""

import json
import os
from pathlib import Path

class ConfigManager:
    def __init__(self, config_path=None):
        self.config_path = config_path or "config/bugbounty_config.json"
        self.default_config = {
            "telegram_notifications": False,
            "telegram_bot_token": " ",
            "telegram_chat_id": " ",
            "threads": 50,
            "timeout": 300,
            "rate_limit": 5,
            "waf_detection": True,
            "nuclei_scan": True,
            "nuclei_timeout": 120,
            "nuclei_rate_limit": 5,
            "nuclei_process_timeout": 1800,
            "gau_timeout": 300,
            "waybackurls_timeout": 300,
            "katana_timeout": 300,
            "nmap_timeout": 120,
            "nmap_top_ports": 1000,
            "filter_extensions": True,
            "extensions_to_exclude": [".png", ".jpg", ".jpeg", ".gif", ".css", ".js", ".svg", ".woff", ".woff2", ".ico"],
            "filter_status_codes": True,
            "interesting_status_codes": [200, 301, 302, 403, 404, 500, 503]
        }
    
    def load_config(self):
        """Load configuration from file or return defaults"""
        config = self.default_config.copy()
        
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, 'r') as f:
                    user_config = json.load(f)
                    config.update(user_config)
                print(f"\n[+] Loaded configuration from {self.config_path}")
            except Exception as e:
                print(f"[-] Error loading config: {e}, using defaults")
        else:
            print("[*] No config file found, using default configuration")
            # Create default config if directory exists
            config_dir = os.path.dirname(self.config_path)
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            
        return config
    
    def save_config(self, config):
        """Save configuration to file"""
        try:
            with open(self.config_path, 'w') as f:
                json.dump(config, f, indent=4)
            print(f"[+] Configuration saved to {self.config_path}")
        except Exception as e:
            print(f"[-] Error saving config: {e}")
