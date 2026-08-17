#!/usr/bin/env python3
"""
Common utility functions
"""

import os
import sys
import logging
from datetime import datetime
from colorama import init, Fore, Back, Style

# Initialize colorama for cross-platform colored output
init(autoreset=True)

class ProgressBar:
    """Progress bar for long operations"""
    
    def __init__(self, total, prefix='Progress:', suffix='', length=50, fill='█'):
        self.total = total
        self.prefix = prefix
        self.suffix = suffix
        self.length = length
        self.fill = fill
        self.current = 0
        
    def update(self, current=None):
        """Update progress bar"""
        if current:
            self.current = current
        else:
            self.current += 1
            
        percent = (self.current / self.total) * 100
        filled_length = int(self.length * self.current // self.total)
        bar = self.fill * filled_length + '-' * (self.length - filled_length)
        
        sys.stdout.write(f'\r{self.prefix} |{Fore.GREEN}{bar}{Style.RESET_ALL}| {percent:.1f}% {self.suffix}')
        sys.stdout.flush()
        
        if self.current == self.total:
            print()

class ColoredFormatter(logging.Formatter):
    """Custom formatter with colors"""
    
    # Color mapping for log levels
    COLORS = {
        'DEBUG': Fore.CYAN,
        'INFO': Fore.GREEN,
        'WARNING': Fore.YELLOW,
        'ERROR': Fore.RED,
        'CRITICAL': Fore.RED + Back.WHITE
    }
    
    def format(self, record):
        # Add color to level name
        levelname = record.levelname
        if levelname in self.COLORS:
            record.levelname = self.COLORS[levelname] + levelname + Style.RESET_ALL
        
        # Color the timestamp
        timestamp = datetime.fromtimestamp(record.created).strftime('%Y-%m-%d %H:%M:%S')
        record.asctime = Fore.LIGHTBLACK_EX + timestamp + Style.RESET_ALL
        
        # Color the message based on content
        msg = record.getMessage()
        if 'Found' in msg or 'discovered' in msg:
            record.msg = Fore.GREEN + msg + Style.RESET_ALL
        elif 'Error' in msg or 'failed' in msg or 'timed out' in msg:
            record.msg = Fore.RED + msg + Style.RESET_ALL
        elif 'Step' in msg:
            record.msg = Fore.MAGENTA + msg + Style.RESET_ALL
        elif 'Running' in msg:
            record.msg = Fore.YELLOW + msg + Style.RESET_ALL
            
        return super().format(record)

def setup_logging(output_dir):
    """Setup logging configuration with colors"""
    log_file = os.path.join(output_dir, 'recon.log')
    
    # Create formatter for file (no colors)
    file_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup file handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setFormatter(file_formatter)
    file_handler.setLevel(logging.DEBUG)
    
    # Setup console handler with colors
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(ColoredFormatter('%(asctime)s - %(levelname)s - %(message)s'))
    console_handler.setLevel(logging.INFO)
    
    # Setup logger
    logger = logging.getLogger('bugbounty_recon')
    logger.setLevel(logging.DEBUG)
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger

def print_banner(domain, start_time):
    """Print start banner"""
    banner = f""" 

{Fore.WHITE}Target:   {Fore.LIGHTYELLOW_EX}{domain}{Style.RESET_ALL}
{Fore.WHITE}Started:  {Fore.LIGHTYELLOW_EX}{start_time.strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}
{Fore.WHITE}Results:  {Fore.LIGHTYELLOW_EX}output/recon_{domain}_{start_time.strftime('%Y%m%d_%H%M%S')}/{Style.RESET_ALL}

"""
    print(banner)

def print_step(step_num, description):
    """Print a colored step header"""
    print(f"\n{Fore.MAGENTA}▸ Step {step_num}: {description}{Style.RESET_ALL}")

def print_success(message):
    """Print success message in green"""
    print(f"{Fore.GREEN}✓ {message}{Style.RESET_ALL}")

def print_info(message):
    """Print info message in cyan"""
    print(f"{Fore.CYAN}ℹ {message}{Style.RESET_ALL}")

def print_warning(message):
    """Print warning message in yellow"""
    print(f"{Fore.YELLOW}⚠ {message}{Style.RESET_ALL}")

def print_error(message):
    """Print error message in red"""
    print(f"{Fore.RED}✗ {message}{Style.RESET_ALL}")

def check_tools():
    """Verify that required tools are installed"""
    required_tools = [
        'subfinder', 'assetfinder', 'httpx', 'nmap', 'gau', 'waybackurls', 'katana', 'nuclei', 'wafw00f'
    ]
    
    missing_tools = []
    
    print_info("Checking required tools...")
    for tool in required_tools:
        if os.system(f'which {tool} > /dev/null 2>&1') == 0:
            print_success(f"{tool} found")
        else:
            print_error(f"{tool} missing")
            missing_tools.append(tool)
    
    if missing_tools:
        print_error("Missing required tools:")
        for tool in missing_tools:
            print(f"    - {tool}")
        print_warning("Please install missing tools and try again.")
        return False
    
    print_success("All tools are available")
    return True