#!/usr/bin/env python3
"""
Telegram notification module
"""

import requests
import logging

class Notifier:
    def __init__(self, config):
        self.config = config
        self.enabled = config.get('telegram_notifications', False)
        self.bot_token = config.get('telegram_bot_token', '')
        self.chat_id = config.get('telegram_chat_id', '')
        
        # Setup logger
        self.logger = logging.getLogger('bugbounty_recon')
        
    def send_phase(self, domain, phase, details=""):
        """Send phase update notification"""
        if not self.enabled or not self.bot_token or not self.chat_id:
            return
        
        # Text indicators
        phase_map = {
            'start': '[START]',
            'subdomains': '[SUBDOMAINS]',
            'ports': '[PORTS]',
            'webservers': '[WEB]',
            'endpoints': '[ENDPOINTS]',
            'vulnerabilities': '[VULNS]',
            'complete': '[DONE]',
            'error': '[ERROR]'
        }
        
        indicator = phase_map.get(phase, '[INFO]')
        
        message = f"{indicator} {domain} - {phase.upper()}\n"
        if details:
            message += f"{details}"
        
        self._send(message)
    
    def send_result(self, domain, phase, count):
        """Send result summary (no emojis)"""
        if not self.enabled or not self.bot_token or not self.chat_id:
            return
        
        messages = {
            'subdomains': f"[RESULT] {domain} - Found {count} subdomains",
            'ports': f"[RESULT] {domain} - Discovered {count} open ports",
            'webservers': f"[RESULT] {domain} - Identified {count} active web servers",
            'endpoints': f"[RESULT] {domain} - Collected {count} endpoints",
            'vulnerabilities': f"[RESULT] {domain} - Detected {count} potential vulnerabilities"
        }
        
        if phase in messages:
            self._send(messages[phase])
    
    def send_error(self, domain, phase, error):
        """Send error notification"""
        if not self.enabled or not self.bot_token or not self.chat_id:
            return
        
        message = f"[ERROR] {domain} - Error in {phase}\n{error[:200]}..."
        self._send(message)
    
    def _send(self, message):
        """Internal method to send message"""
        try:
            url = f"https://api.telegram.org/bot{self.bot_token}/sendMessage"
            data = {
                'chat_id': self.chat_id,
                'text': message,
                'parse_mode': 'Markdown'
            }
            
            response = requests.post(url, data=data, timeout=10)
            if response.status_code == 200:
                self.logger.debug(f"Notification sent: {message[:50]}...")
            else:
                self.logger.error(f"Failed to send notification: {response.status_code}")
                
        except Exception as e:
            self.logger.error(f"Telegram notification error: {e}")