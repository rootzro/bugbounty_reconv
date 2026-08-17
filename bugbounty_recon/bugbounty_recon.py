#!/usr/bin/env python3
"""
Bug Bounty Recon - Main Orchestrator
"""

import os
import sys
import argparse
import logging
from datetime import datetime
from pathlib import Path
from colorama import Fore, Style, init

# Inicializar colorama
init(autoreset=True)

from modules.config_manager import ConfigManager
from modules.subdomain_enum import SubdomainEnumerator
from modules.web_server_check import WebServerChecker
from modules.port_scanner import PortScanner
from modules.endpoint_discovery import EndpointDiscoverer
from modules.vulnerability_scanner import VulnerabilityScanner
from modules.file_handler import FileHandler
from modules.notifier import Notifier
from modules.utils import setup_logging, print_banner, print_step, print_success, print_info, print_warning, print_error, ProgressBar

class BugBountyRecon:
    def __init__(self, domain, config_path=None, telegram_bot_token=None, telegram_chat_id=None):
        self.domain = domain
        self.start_time = datetime.now()
        self.timestamp = self.start_time.strftime("%Y%m%d_%H%M%S")
        
        # Initialize components
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load_config()
        
        # Override Telegram settings if provided via environment
        if telegram_bot_token:
            self.config['telegram_bot_token'] = telegram_bot_token
        if telegram_chat_id:
            self.config['telegram_chat_id'] = telegram_chat_id
        if telegram_bot_token and telegram_chat_id:
            self.config['telegram_notifications'] = True
            
        # Setup output directory
        self.output_dir = f"output/recon_{domain}_{self.timestamp}"
        self.file_handler = FileHandler(self.output_dir)
        
        # Setup logging
        self.logger = setup_logging(self.output_dir)
        
        # Initialize notifier
        self.notifier = Notifier(self.config)
        
        # Initialize scanners
        self.subdomain_enum = SubdomainEnumerator(self.config, self.file_handler)
        self.web_checker = WebServerChecker(self.config, self.file_handler)
        self.port_scanner = PortScanner(self.config, self.file_handler)
        self.endpoint_discoverer = EndpointDiscoverer(self.config, self.file_handler)
        self.vuln_scanner = VulnerabilityScanner(self.config, self.file_handler)
        
    def run(self):
        """Execute the complete reconnaissance pipeline"""
        try:
            print_banner(self.domain, self.start_time)
            self.logger.info(f"Starting reconnaissance for {self.domain}")
            self.notifier.send_phase(self.domain, 'start')
            
            # Step 1: Subdomain Enumeration
            print_step(1, "Enumerating subdomains")
            self.notifier.send_phase(self.domain, 'subdomains', "Starting subdomain enumeration")
            
            subdomains = self.subdomain_enum.enumerate(self.domain)
            
            if not subdomains:
                print_warning("No subdomains found, using target domain only")
                subdomains = [self.domain]
            else:
                print_success(f"Found {len(subdomains)} unique subdomains")
                self.notifier.send_result(self.domain, 'subdomains', len(subdomains))
            
            # Save subdomains
            subdomain_file = self.file_handler.save_list(
                subdomains, 
                "subdomains/all_subdomains.txt"
            )
            
            # Step 2: Port Scanning with progress bar
            print_step(2, "Scanning for open ports")
            self.notifier.send_phase(self.domain, 'ports', "Scanning for open ports")
            
            hosts_with_ports = self.port_scanner.scan(subdomains)
            if hosts_with_ports:
                self.notifier.send_result(self.domain, 'ports', len(hosts_with_ports))
            
            # Step 3: Web Server Detection
            print_step(3, "Identifying active web servers")
            self.notifier.send_phase(self.domain, 'webservers', "Probing for active web servers")
            
            active_webservers = self.web_checker.check(subdomains)
            
            if active_webservers:
                self.file_handler.save_list(
                    active_webservers,
                    "web_servers/active_webservers.txt"
                )
                print_success(f"Found {len(active_webservers)} active web servers")
                self.notifier.send_result(self.domain, 'webservers', len(active_webservers))
                
                # Step 4: Endpoint Discovery
                print_step(4, "Discovering endpoints")
                self.notifier.send_phase(self.domain, 'endpoints', "Gathering URLs from various sources")
                
                endpoints = self.endpoint_discoverer.discover(active_webservers)
                
                if endpoints:
                    # Solo guardamos un archivo, no duplicados
                    self.file_handler.save_list(
                        endpoints,
                        "endpoints/all_endpoints.txt"
                    )
                    print_success(f"Discovered {len(endpoints)} unique endpoints\n")
                    self.notifier.send_result(self.domain, 'endpoints', len(endpoints))
                
                # Step 5: Vulnerability Scanning
                if self.config.get('nuclei_scan', True):
                    print_step(5, "Scanning for vulnerabilities")
                    self.notifier.send_phase(self.domain, 'vulnerabilities', "Running Nuclei vulnerability scan")
                    
                    vulnerabilities = self.vuln_scanner.scan(active_webservers)
                    
                    if vulnerabilities:
                        self.file_handler.save_list(
                            vulnerabilities,
                            "vulnerabilities/nuclei_results.txt"
                        )
                        print_success(f"Found {len(vulnerabilities)} potential vulnerabilities")
                        self.notifier.send_result(self.domain, 'vulnerabilities', len(vulnerabilities))
                    else:
                        print_info("No vulnerabilities found")
            
            # Generate final report
            self.generate_report()
            
            # Completion
            elapsed_time = datetime.now() - self.start_time
            self.logger.info(f"Scan completed in {elapsed_time}")
            
            # Final summary
            print(f"\n{Fore.GREEN}SCAN COMPLETED SUCCESSFULLY{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{''*60}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Domain:     {Fore.LIGHTYELLOW_EX}{self.domain}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Duration:   {Fore.LIGHTYELLOW_EX}{elapsed_time}{Style.RESET_ALL}")
            print(f"{Fore.WHITE}Results:    {Fore.LIGHTYELLOW_EX}{self.output_dir}{Style.RESET_ALL}")
            print(f"{Fore.GREEN}{''*60}{Style.RESET_ALL}")
            
            self.notifier.send_phase(self.domain, 'complete', f"Scan completed in {elapsed_time}")
            
        except Exception as e:
            print_error(f"Scan failed: {str(e)}")
            self.logger.error(f"Scan failed: {str(e)}")
            self.notifier.send_error(self.domain, 'main', str(e))
            sys.exit(1)
    
    def generate_report(self):
        """Generate final scan report"""
        report = []
        report.append("=" * 60)
        report.append("BUGBOUNTY RECON REPORT")
        report.append("=" * 60)
        report.append(f"Target: {self.domain}")
        report.append(f"Scan started: {self.start_time}")
        report.append(f"Scan completed: {datetime.now()}")
        report.append(f"Output directory: {self.output_dir}")
        report.append("")
        
        # Add file listings
        report.append("Generated Files:")
        for root, dirs, files in os.walk(self.output_dir):
            level = root.replace(self.output_dir, '').count(os.sep)
            indent = ' ' * 2 * level
            report.append(f"{indent}{os.path.basename(root)}/")
            subindent = ' ' * 2 * (level + 1)
            for file in files:
                if not file.endswith('.log'):
                    report.append(f"{subindent}{file}")
        
        report_path = self.file_handler.save_list(
            report,
            "reports/final_report.txt"
        )
        
        self.logger.info(f"Report generated: {report_path}")

def main():
    parser = argparse.ArgumentParser(description='BugBounty_Recon')
    parser.add_argument('domain', help='Target domain to scan')
    parser.add_argument('--config', help='Path to config file')
    
    args = parser.parse_args()
    
    # Get Telegram credentials from environment if available
    telegram_token = os.environ.get('TELEGRAM_BOT_TOKEN')
    telegram_chat_id = os.environ.get('TELEGRAM_CHAT_ID')
    
    # Run scanner
    scanner = BugBountyRecon(
        domain=args.domain,
        config_path=args.config,
        telegram_bot_token=telegram_token,
        telegram_chat_id=telegram_chat_id
    )
    scanner.run()

if __name__ == "__main__":
    main()