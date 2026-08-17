#!/usr/bin/env python3
"""
Port scanning module using nmap
"""

import subprocess
import socket
from modules.utils import ProgressBar

class PortScanner:
    def __init__(self, config, file_handler):
        self.config = config
        self.file_handler = file_handler
        self.threads = config.get('threads', 20)
        self.nmap_timeout = config.get('nmap_timeout', 300)
        
    def _clean_host(self, host):
        """Remove protocols and paths from host string"""
        if not host:
            return None
        if '://' in str(host):
            host = host.split('://')[1]
        if '/' in str(host):
            host = host.split('/')[0]
        if ':' in str(host):
            host = host.split(':')[0]
        return str(host).strip()
    
    def _resolve_host(self, host):
        """Quick DNS check"""
        try:
            return socket.gethostbyname(host)
        except:
            return None
        
    def scan(self, hosts):
        """Scan for open ports using nmap"""
        if not hosts:
            return []
        
        # Compact header
        print(f"Targets: {len(hosts)} hosts")
        
        # Validate hosts
        valid_hosts = []
        for host in hosts[:200]:
            cleaned = self._clean_host(host)
            if cleaned and self._resolve_host(cleaned):
                valid_hosts.append(cleaned)
        
        if not valid_hosts:
            print("[!] No reachable hosts")
            return []
        
        print(f"Scanning: {len(valid_hosts)} hosts")
        
        results = []
        progress = ProgressBar(len(valid_hosts), prefix='Progress:', suffix='', length=30)
        
        # Common ports by category
        ports = {
            'web': '80,443,8080,8443,8000,8001,8081,3000,5000',
            'admin': '22,21,25,3389,5900,5901',
            'db': '3306,5432,27017,6379,9200,5601,1433,1521',
            'other': '389,636,445,139,135,993,995'
        }
        port_list = f"{ports['web']},{ports['admin']},{ports['db']},{ports['other']}"
        
        for host in valid_hosts:
            try:
                # Quiet nmap scan
                cmd = [
                    'nmap', '-Pn', '-T4', '--open',
                    '-p', port_list,
                    '--min-rate', '300',
                    '--max-retries', '1',
                    '--host-timeout', '60s',
                    '-oG', '-',
                    host
                ]
                
                result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
                
                # Parse only open ports
                host_ports = []
                for line in result.stdout.splitlines():
                    if '/open/' in line:
                        parts = line.split('Ports: ')[-1] if 'Ports: ' in line else ''
                        for port_info in parts.split(', '):
                            if '/open/' in port_info:
                                p = port_info.split('/')
                                if len(p) >= 2:
                                    port = p[0]
                                    service = p[4] if len(p) > 4 else 'unknown'
                                    host_ports.append(f"{port}/{service}")
                
                if host_ports:
                    results.append(f"{host}: {', '.join(host_ports)}")
                    
            except:
                pass  # Silent fail
            progress.update()
        
        # Compact output
        if results:
            print(f"\n[+] Open ports found on {len(results)} hosts:")
            for r in results[:10]:  # Show max 10 lines
                print(f"  • {r}")
            if len(results) > 10:
                print(f"  ... and {len(results)-10} more (see ports/nmap_results.txt)")
            
            # Save full results
            self.file_handler.save_list(results, "ports/nmap_results.txt")
        else:
            print("[!] No open ports found")
        
        return results