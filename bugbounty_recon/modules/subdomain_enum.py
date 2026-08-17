#!/usr/bin/env python3
"""
Subdomain enumeration module
"""

import subprocess
import threading
from queue import Queue

class SubdomainEnumerator:
    def __init__(self, config, file_handler):
        self.config = config
        self.file_handler = file_handler
        self.threads = config.get('threads', 20)
        self.timeout = config.get('timeout', 30)
        
    def enumerate(self, domain):
        """Run multiple subdomain enumeration tools"""
        subdomains = set()
        
        # Run subfinder
        try:
            print(f"[*] Running subfinder on {domain}")
            result = subprocess.run(
                ['subfinder', '-d', domain, '-silent'],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    if line.strip():
                        subdomains.add(line.strip())
        except Exception as e:
            print(f"[-] subfinder error: {e}")
        
        # Run assetfinder
        try:
            print(f"[*] Running assetfinder on {domain}")
            result = subprocess.run(
                ['assetfinder', '--subs-only', domain],
                capture_output=True,
                text=True,
                timeout=self.timeout
            )
            if result.stdout:
                for line in result.stdout.splitlines():
                    if line.strip():
                        subdomains.add(line.strip())
        except Exception as e:
            print(f"[-] assetfinder error: {e}")
        
        # Save results
        if subdomains:
            self.file_handler.save_list(
                sorted(list(subdomains)),
                "subdomains/raw_subdomains.txt"
            )
            print(f"[+] Found {len(subdomains)} unique subdomains")
        else:
            print("[!] No subdomains found")
        
        return sorted(list(subdomains))