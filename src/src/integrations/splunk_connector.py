"""
Splunk integration module for sending events and alerts
"""

import logging
import json
import time
import requests
from datetime import datetime
from typing import Dict, List, Any, Optional
from splunk_hec_handler import SplunkHecHandler


class SplunkConnector:
    """
    Connector for Splunk integration to send events and alerts
    """
    
    def __init__(self, config: Dict):
        """
        Initialize Splunk connector
        
        Args:
            config: Splunk connection and configuration settings
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # HEC settings
        self.hec_url = config.get('hec_url')
        self.hec_token = config.get('hec_token')
        self.hec_index = config.get('index', 'main')
        self.hec_source = config.get('source', 'ai_threat_detection')
        self.hec_sourcetype = config.get('sourcetype', 'ai_threat_detection:json')
        
        # REST API settings
        self.api_url = config.get('api_url')
        self.api_username = config.get('api_username')
        self.api_password = config.get('api_password')
        self.api_session = None
        
        # Validate configuration
        if not (self.hec_url and self.hec_token):
            self.logger.warning("Incomplete Splunk HEC configuration")
        
        self.logger.info("Splunk connector initialized")
    
    def send_events(self, events: List[Dict]) -> bool:
        """
        Send events to Splunk via HEC
        
        Args:
            events: List of event dictionaries
            
        Returns:
            True if successful, False otherwise
        """
        if not events:
            return True
        
        if not (self.hec_url and self.hec_token):
            self.logger.error("Cannot send events: Splunk HEC not configured")
            return False
        
        try:
            # Prepare headers
            headers = {
                'Authorization': f'Splunk {self.hec_token}',
                'Content-Type': 'application/json'
            }
            
            # Batch events to avoid oversized requests
            batch_size = 100
            success = True
            
            for i in range(0, len(events), batch_size):
                batch = events[i:i+batch_size]
                payload = []
                
                for event in batch:
                    # Add metadata for Splunk
                    event_data = {
                        'event': event,
                        'time': event.get('timestamp', time.time()),
                        'host': event.get('host', 'ai_threat_detection'),
                        'source': self.hec_source,
                        'sourcetype': self.hec_sourcetype,
                        'index': self.hec_index
                    }
                    payload.append(event_data)
                
                # Send batch to Splunk
                response = requests.post(
                    self.hec_url,
                    headers=headers,
                    data=json.dumps(payload),
                    timeout=10
                )
                
                if response.status_code not in (200, 201):
                    self.logger.error(f"Failed to send events to Splunk: {response.status_code} {response.text}")
                    success = False
                else:
                    self.logger.debug(f"Successfully sent {len(batch)} events to Splunk")
            
            return success
        
        except Exception as e:
            self.logger.error(f"Error sending events to Splunk: {e}")
            return False
    
    def create_alert(self, name: str, severity: str, description: str, 
                    event_data: Dict, ttl: int = 86400) -> bool:
        """
        Create an alert in Splunk
        
        Args:
            name: Alert name
            severity: Alert severity (low, medium, high, critical)
            description: Alert description
            event_data: Event data that triggered the alert
            ttl: Time to live in seconds (default 24 hours)
            
        Returns:
            True if successful, False otherwise
        """
        if not self.api_url:
            self.logger.error("Cannot create alert: Splunk API not configured")
            return False
        
        try:
            # Login to Splunk if needed
            if not self._ensure_session():
                return False
            
            # Prepare alert data
            alert_data = {
                'name': name,
                'severity': severity,
                'description': description,
                'ttl': ttl,
                'time': datetime.now().isoformat(),
                'event_data': event_data
            }
            
            # Send to Splunk notable event endpoint
            endpoint = f"{self.api_url}/services/notable_event"
            
            response = self.api_session.post(
                endpoint,
                json=alert_data,
                timeout=10
            )
