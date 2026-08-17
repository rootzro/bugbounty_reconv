#!/usr/bin/env python3
"""
File operations module
"""

import os
import shutil
from pathlib import Path

class FileHandler:
    def __init__(self, base_path):
        self.base_path = base_path
        self.create_directory_structure()
        
    def create_directory_structure(self):
        """Create the standard directory structure for results"""
        directories = [
            "",
            "subdomains",
            "web_servers",
            "endpoints",
            "vulnerabilities",
            "waf",
            "ports",
            "reports",
            "temp"
        ]
        
        for dir_name in directories:
            dir_path = os.path.join(self.base_path, dir_name)
            os.makedirs(dir_path, exist_ok=True)
    
    def save_list(self, items, filename):
        """Save a list of items to a file"""
        filepath = os.path.join(self.base_path, filename)
        
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            for item in items:
                f.write(f"{item}\n")
        
        return filepath
    
    def save_content(self, content, filename):
        """Save raw content to a file"""
        filepath = os.path.join(self.base_path, filename)
        
        # Create parent directory if it doesn't exist
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        return filepath
    
    def cleanup_temp(self):
        """Remove temporary files"""
        temp_dir = os.path.join(self.base_path, "temp")
        if os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)