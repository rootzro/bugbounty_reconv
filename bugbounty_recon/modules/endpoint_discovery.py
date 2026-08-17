#!/usr/bin/env python3
"""
Endpoint discovery module using gau, waybackurls, and katana
"""

import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError
import time
from modules.utils import ProgressBar

class EndpointDiscoverer:
    def __init__(self, config, file_handler):
        self.config = config
        self.file_handler = file_handler
        self.threads = config.get('threads', 20)
        self.timeout = config.get('timeout', 60)
        self.rate_limit = config.get('rate_limit', 50)
        
        # Timeouts
        self.gau_timeout = config.get('gau_timeout', 120)
        self.waybackurls_timeout = config.get('waybackurls_timeout', 120)
        self.katana_timeout = config.get('katana_timeout', 600)
        
    def discover(self, urls):
        """Discover endpoints using multiple tools"""
        if not urls:
            return []
        
        endpoints = set()  # set 
        
        # Create input file for domain-based tools
        domains = set()
        for url in urls:
            if url.startswith(('http://', 'https://')):
                domain = url.split('/')[2]
            else:
                domain = url
            domains.add(domain)
        
        domain_list = sorted(list(domains))
        print(f"[*] Processing {len(domain_list)} domains for endpoint discovery")
        
        # Run tools
        print("[*] Gathering URLs with gau")
        gau_endpoints = self._run_gau(domain_list)
        endpoints.update(gau_endpoints)
        print(f"  → gau found {len(gau_endpoints)} URLs")
        
        print("[*] Gathering URLs with waybackurls")
        wayback_endpoints = self._run_waybackurls(domain_list)
        endpoints.update(wayback_endpoints)
        print(f"  → waybackurls found {len(wayback_endpoints)} URLs")
        
        print("[*] Gathering URLs with katana")
        katana_endpoints = self._run_katana(urls)
        endpoints.update(katana_endpoints)
        print(f"  → katana found {len(katana_endpoints)} URLs")
        
        # Filter and save results
        filtered_endpoints = self.apply_filters(list(endpoints))
        
        if filtered_endpoints:
            self.file_handler.save_list(
                filtered_endpoints,
                "endpoints/all_endpoints.txt"
            )
            
            print(f"[+] Total discovered: {len(filtered_endpoints)} unique endpoints")
        else:
            print("[!] No endpoints discovered")
        
        return filtered_endpoints
    
    def _run_gau(self, domains):
        """Run gau with progress bar"""
        endpoints = set()
        domains_to_scan = domains[:30]  # Limit for performance
        
        progress = ProgressBar(len(domains_to_scan), prefix='gau:', suffix='domains')
        
        for domain in domains_to_scan:
            try:
                cmd = ['gau', '--threads', '5', domain]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.gau_timeout
                )
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if self.filter_url(line):
                            endpoints.add(line.strip())
                time.sleep(0.3)  # Rate limiting
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            progress.update()
        
        return endpoints
    
    def _run_waybackurls(self, domains):
        """Run waybackurls with progress bar"""
        endpoints = set()
        domains_to_scan = domains[:30]  # Limit for performance
        
        progress = ProgressBar(len(domains_to_scan), prefix='waybackurls:', suffix='domains')
        
        for domain in domains_to_scan:
            try:
                cmd = ['waybackurls', domain]
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.waybackurls_timeout
                )
                if result.stdout:
                    for line in result.stdout.splitlines():
                        if self.filter_url(line):
                            endpoints.add(line.strip())
                time.sleep(0.3)
            except subprocess.TimeoutExpired:
                pass
            except Exception:
                pass
            progress.update()
        
        return endpoints
    
    def _run_katana(self, urls):
        """Run katana with progress bar"""
        endpoints = set()
        
        # Create temporary file with URLs
        url_file = self.file_handler.save_list(
            urls[:10],  # Limit to first 10 URLs
            "temp/urls_for_katana.txt"
        )
        
        try:
            cmd = [
                'katana', '-list', url_file,
                '-silent',
                '-c', '5',
                '-timeout', '10',
                '-rate-limit', '2',
                '-f', 'qurl',
                '-jc',
                '-d', '2'
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=self.katana_timeout
            )
            
            if result.stdout:
                lines = result.stdout.splitlines()
                progress = ProgressBar(len(lines), prefix='katana processing:', suffix='URLs')
                
                for line in lines:
                    if self.filter_url(line):
                        endpoints.add(line.strip())
                    progress.update()
                        
        except subprocess.TimeoutExpired:
            print("  [katana timed out]")
        except Exception as e:
            print(f"  [katana error: {str(e)[:50]}]")
        
        return endpoints
    
    def filter_url(self, url):
        """Basic URL filtering"""
        if not url or len(url) < 4:
            return False
        return True
    
    def apply_filters(self, urls):
        """Apply extension filters"""
        filtered = urls.copy()
        
        # Filter by extension
        if self.config.get('filter_extensions', True):
            exclude_exts = self.config.get('extensions_to_exclude', [])
            filtered = [
                url for url in filtered
                if not any(url.lower().endswith(ext) for ext in exclude_exts)
            ]
        
        # Limit to first 10000
        if len(filtered) > 10000:
            print(f"[!] Limiting to 10000 endpoints (from {len(filtered)})")
            filtered = filtered[:10000]
        
        return filtered