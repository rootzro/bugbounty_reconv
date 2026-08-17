#!/usr/bin/env python3
"""
Web server detection and WAF identification module
"""

import subprocess
import json
import re
from modules.utils import ProgressBar

class WebServerChecker:
    def __init__(self, config, file_handler):
        self.config = config
        self.file_handler = file_handler
        self.threads = config.get('threads', 20)
        self.timeout = config.get('timeout', 30)
        self.rate_limit = config.get('rate_limit', 50)
        
    def check(self, subdomains):
        """Check which subdomains have active web servers"""
        if not subdomains:
            return []
        
        # Create input file
        input_file = self.file_handler.save_list(
            subdomains,
            "temp/subdomains_for_httpx.txt"
        )
        
        active_webservers = []
        
        try:
            # Run httpx
            print("[*] Probing for active web servers with httpx")
            cmd = [
                'httpx', '-l', input_file,
                '-silent',
                '-threads', str(self.threads),
                '-timeout', str(self.timeout),
                '-status-code',
                '-title',
                '-tech-detect',
                '-follow-redirects',
                '-json'  # Get JSON output for better parsing
            ]
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.stdout:
                # Save raw httpx output
                self.file_handler.save_content(
                    result.stdout,
                    "web_servers/httpx_raw.txt"
                )
                
                # Create readable summary
                self._create_webserver_summary(result.stdout)
                
                # Extract just the URLs
                for line in result.stdout.splitlines():
                    if line.strip():
                        try:
                            # Try to parse as JSON
                            data = json.loads(line)
                            if 'url' in data:
                                active_webservers.append(data['url'])
                        except:
                            # Fallback to simple parsing
                            if line.startswith(('http://', 'https://')):
                                active_webservers.append(line.split()[0])
            
            # WAF Detection with progress bar
            if self.config.get('waf_detection', True) and active_webservers:
                self.detect_waf(active_webservers)
                
        except subprocess.TimeoutExpired:
            print("[-] httpx scan timed out")
        except Exception as e:
            print(f"[-] httpx error: {e}")
        
        print(f"[+] Found {len(active_webservers)} active web servers")
        return active_webservers
    
    def _create_webserver_summary(self, httpx_output):
        """Create a readable summary of web servers"""
        servers = []
        
        for line in httpx_output.splitlines():
            if not line.strip():
                continue
                
            try:
                data = json.loads(line)
                server_info = {
                    'url': data.get('url', ''),
                    'status_code': data.get('status_code', ''),
                    'title': data.get('title', ''),
                    'tech': data.get('tech', []),
                    'webserver': data.get('webserver', '')
                }
                servers.append(server_info)
            except:
                # Simple parsing for non-JSON output
                parts = line.split()
                if parts:
                    server_info = {
                        'url': parts[0] if parts else '',
                        'status_code': parts[1] if len(parts) > 1 else '',
                        'title': ' '.join(parts[2:]) if len(parts) > 2 else ''
                    }
                    servers.append(server_info)
        
        # Create summary
        summary = []
        summary.append("=" * 80)
        summary.append("ACTIVE WEB SERVERS SUMMARY")
        summary.append("=" * 80)
        summary.append(f"Total active web servers: {len(servers)}")
        summary.append("")
        summary.append("URL                                 STATUS    TITLE")
        summary.append("-" * 60)
        
        for s in servers[:100]:  # Limit to first 100 for readability
            url = s.get('url', '')[:40]
            status = str(s.get('status_code', ''))
            title = s.get('title', '')[:30]
            summary.append(f"{url:<40} {status:<8} {title}")
        
        if len(servers) > 100:
            summary.append(f"\n... and {len(servers) - 100} more (see full list in httpx_raw.txt)")
        
        summary.append("\n" + "=" * 80)
        
        self.file_handler.save_list(
            summary,
            "web_servers/webserver_summary.txt"
        )
        print("[+] Web server summary created")
    
    def detect_waf(self, urls):
        """Detect WAF for active web servers with progress bar"""
        if not urls:
            return
        
        print("[*] Detecting WAF with wafw00f")
        
        waf_results = []
        scan_urls = urls[:20]  # Limit to first 20 to avoid rate limiting
        
        # Create progress bar
        progress = ProgressBar(len(scan_urls), prefix='WAF detection:', suffix='urls')
        
        for url in scan_urls:
            try:
                result = subprocess.run(
                    ['wafw00f', url, '-v'],
                    capture_output=True,
                    text=True,
                    timeout=30
                )
                
                if result.stdout:
                    # Parse and format WAF info
                    waf_info = self._parse_waf_output(url, result.stdout)
                    waf_results.append(waf_info)
                    
            except subprocess.TimeoutExpired:
                waf_results.append(f"URL: {url}\n  Scan timed out\n{'-'*40}")
            except Exception as e:
                waf_results.append(f"URL: {url}\n  Error: {str(e)[:100]}\n{'-'*40}")
            
            progress.update()
        
        if waf_results:
            # Create summary
            summary = []
            summary.append("=" * 80)
            summary.append("WAF DETECTION RESULTS")
            summary.append("=" * 80)
            
            waf_detected = 0
            for result in waf_results:
                summary.append("")
                summary.append(result)
                if 'WAF detected' in result or 'is behind' in result:
                    waf_detected += 1
            
            summary.append("\n" + "=" * 80)
            summary.append(f"SUMMARY: {waf_detected} WAFs detected out of {len(scan_urls)} scanned")
            summary.append("=" * 80)
            
            self.file_handler.save_list(
                summary,
                "waf/waf_detection_results.txt"
            )
            print(f"[+] WAF detection complete ({waf_detected} WAFs found)")
    
    def _parse_waf_output(self, url, raw_output):
        """Parse wafw00f output to be more readable"""
        lines = raw_output.split('\n')
        parsed = [f"\n{'='*40}", f" WAF SCAN: {url}", f"{'='*40}"]
        
        in_results = False
        for line in lines:
            if 'is behind' in line or 'WAF detected' in line:
                parsed.append(f"\n✓ {line.strip()}")
                in_results = True
            elif 'Number of requests' in line:
                parsed.append(f"  {line.strip()}")
            elif '>>' in line and 'WAF' in line:
                parsed.append(f"  • {line.strip().replace('>>', '').strip()}")
            elif 'None of the WAFs' in line:
                parsed.append(f"\n✗ No WAF detected")
                
        return '\n'.join(parsed)