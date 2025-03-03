"""
Feature extraction module for the ML-based threat detection system
"""

import logging
import numpy as np
import pandas as pd
from typing import Dict, List, Set, Tuple, Any, Union
from datetime import datetime, timedelta
import re
import ipaddress
import json


class FeatureExtractor:
    """
    Extracts and transforms features from cloud logs and events
    for machine learning model input
    """
    
    def __init__(self, config: Dict = None):
        """
        Initialize feature extractor
        
        Args:
            config: Configuration dictionary for feature extraction
        """
        self.logger = logging.getLogger(__name__)
        self.config = config or {}
        
        # Load feature configuration
        self.enabled_features = self.config.get('enabled_features', [
            'time_features', 'ip_features', 'user_features', 
            'action_features', 'resource_features'
        ])
        
        # Configure known malicious IP ranges (example)
        self.known_malicious_ranges = [
            ipaddress.ip_network('185.159.128.0/22'),
            ipaddress.ip_network('91.243.192.0/22'),
            # Add more known malicious ranges as needed
        ]
        
        # Load feature normalization parameters
        self.normalization = self.config.get('normalization', {})
        
        self.logger.info(f"Feature extractor initialized with {len(self.enabled_features)} feature types")
    
    def extract_features(self, events: List[Dict]) -> np.ndarray:
        """
        Extract features from a list of events
        
        Args:
            events: List of preprocessed event dictionaries
            
        Returns:
            Numpy array of features for model input
        """
        if not events:
            return np.array([])
        
        features_list = []
        
        for event in events:
            # Extract individual feature groups
            event_features = []
            
            if 'time_features' in self.enabled_features:
                time_feats = self._extract_time_features(event)
                event_features.extend(time_feats)
            
            if 'ip_features' in self.enabled_features:
                ip_feats = self._extract_ip_features(event)
                event_features.extend(ip_feats)
            
            if 'user_features' in self.enabled_features:
                user_feats = self._extract_user_features(event)
                event_features.extend(user_feats)
            
            if 'action_features' in self.enabled_features:
                action_feats = self._extract_action_features(event)
                event_features.extend(action_feats)
            
            if 'resource_features' in self.enabled_features:
                resource_feats = self._extract_resource_features(event)
                event_features.extend(resource_feats)
            
            features_list.append(event_features)
        
        # Convert to numpy array
        features_array = np.array(features_list, dtype=np.float32)
        
        # Apply normalization if configured
        if self.normalization.get('enabled', False):
            features_array = self._normalize_features(features_array)
        
        return features_array
    
    def _extract_time_features(self, event: Dict) -> List[float]:
        """
        Extract time-based features
        
        Args:
            event: Event dictionary
            
        Returns:
            List of time-based features
        """
        features = []
        
        try:
            # Parse timestamp
            timestamp_str = event.get('timestamp')
            if not timestamp_str:
                # Default values if timestamp not available
                return [0.0, 0.0, 0.0, 0.0]
            
            timestamp = None
            if isinstance(timestamp_str, str):
                try:
                    # Try ISO format
                    timestamp = datetime.fromisoformat(timestamp_str.replace('Z', '+00:00'))
                except ValueError:
                    try:
                        # Try Unix timestamp
                        timestamp = datetime.fromtimestamp(float(timestamp_str))
                    except:
                        self.logger.warning(f"Unable to parse timestamp: {timestamp_str}")
                        return [0.0, 0.0, 0.0, 0.0]
            elif isinstance(timestamp_str, (int, float)):
                timestamp = datetime.fromtimestamp(timestamp_str)
            
            if not timestamp:
                return [0.0, 0.0, 0.0, 0.0]
            
            # Hour of day (normalized to 0-1)
            hour = timestamp.hour / 24.0
            features.append(hour)
            
            # Day of week (normalized to 0-1)
            day_of_week = timestamp.weekday() / 6.0
            features.append(day_of_week)
            
            # Is weekend
            is_weekend = 1.0 if timestamp.weekday() >= 5 else 0.0
            features.append(is_weekend)
            
            # Is business hours (8am-6pm)
            is_business_hours = 1.0 if 8 <= timestamp.hour < 18 else 0.0
            features.append(is_business_hours)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting time features: {e}")
            return [0.0, 0.0, 0.0, 0.0]
    
    def _extract_ip_features(self, event: Dict) -> List[float]:
        """
        Extract IP-based features
        
        Args:
            event: Event dictionary
            
        Returns:
            List of IP-based features
        """
        features = []
        
        try:
            # Get source IP
            source_ip = event.get('sourceIPAddress', event.get('source_ip', ''))
            
            if not source_ip or not isinstance(source_ip, str):
                return [0.0, 0.0, 0.0]
            
            try:
                ip = ipaddress.ip_address(source_ip)
                
                # Is private IP
                is_private = 1.0 if ip.is_private else 0.0
                features.append(is_private)
                
                # Check if IP is in known malicious ranges
                is_malicious = 0.0
                for bad_range in self.known_malicious_ranges:
                    if ip in bad_range:
                        is_malicious = 1.0
                        break
                features.append(is_malicious)
                
                # IPv4 vs IPv6 (0 for IPv4, 1 for IPv6)
                is_ipv6 = 1.0 if isinstance(ip, ipaddress.IPv6Address) else 0.0
                features.append(is_ipv6)
                
            except ValueError:
                # Invalid IP address
                features.extend([0.0, 0.0, 0.0])
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting IP features: {e}")
            return [0.0, 0.0, 0.0]
    
    def _extract_user_features(self, event: Dict) -> List[float]:
        """
        Extract user-based features
        
        Args:
            event: Event dictionary
            
        Returns:
            List of user-based features
        """
        features = []
        
        try:
            # Get user info
            user_identity = event.get('userIdentity', {})
            user_type = user_identity.get('type', '')
            user_name = user_identity.get('userName', '')
            
            # Is root user
            is_root = 1.0 if user_type.lower() == 'root' or 'root' in user_name.lower() else 0.0
            features.append(is_root)
            
            # Is IAM user
            is_iam = 1.0 if user_type.lower() == 'iamuser' else 0.0
            features.append(is_iam)
            
            # Is service account
            is_service = 1.0 if 'service' in user_name.lower() or user_type.lower() == 'service' else 0.0
            features.append(is_service)
            
            # Is temporary credentials
            session_context = user_identity.get('sessionContext', {})
            is_temp_creds = 1.0 if session_context and 'attributes' in session_context else 0.0
            features.append(is_temp_creds)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting user features: {e}")
            return [0.0, 0.0, 0.0, 0.0]
    
    def _extract_action_features(self, event: Dict) -> List[float]:
        """
        Extract action-based features
        
        Args:
            event: Event dictionary
            
        Returns:
            List of action-based features
        """
        features = []
        
        try:
            # Get action info
            event_name = event.get('eventName', '').lower()
            event_source = event.get('eventSource', '').lower()
            
            # Is write/modification action
            is_write = 0.0
            write_patterns = ['create', 'update', 'modify', 'delete', 'remove', 'put', 'attach']
            for pattern in write_patterns:
                if pattern in event_name:
                    is_write = 1.0
                    break
            features.append(is_write)
            
            # Is permission/IAM related
            is_permission = 0.0
            permission_patterns = ['iam', 'role', 'policy', 'permission', 'auth', 'token']
            if any(pattern in event_source for pattern in permission_patterns) or \
               any(pattern in event_name for pattern in permission_patterns):
                is_permission = 1.0
            features.append(is_permission)
            
            # Is security related
            is_security = 0.0
            security_patterns = ['security', 'encrypt', 'decrypt', 'certificate', 'password', 'key']
            if any(pattern in event_source for pattern in security_patterns) or \
               any(pattern in event_name for pattern in security_patterns):
                is_security = 1.0
            features.append(is_security)
            
            # Is data access
            is_data_access = 0.0
            data_patterns = ['get', 'list', 'describe', 'read', 'select', 'download']
            if any(pattern in event_name for pattern in data_patterns):
                is_data_access = 1.0
            features.append(is_data_access)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting action features: {e}")
            return [0.0, 0.0, 0.0, 0.0]
    
    def _extract_resource_features(self, event: Dict) -> List[float]:
        """
        Extract resource-based features
        
        Args:
            event: Event dictionary
            
        Returns:
            List of resource-based features
        """
        features = []
        
        try:
            # Get resource info
            resources = event.get('resources', [])
            resource_types = [r.get('type', '').lower() for r in resources]
            
            # Is sensitive resource
            is_sensitive = 0.0
            sensitive_patterns = ['secret', 'password', 'key', 'certificate', 'credential', 'token']
            for resource_type in resource_types:
                if any(pattern in resource_type for pattern in sensitive_patterns):
                    is_sensitive = 1.0
                    break
            features.append(is_sensitive)
            
            # Is database resource
            is_database = 0.0
            db_patterns = ['database', 'db', 'rds', 'dynamodb', 'sql', 'redis', 'cache']
            for resource_type in resource_types:
                if any(pattern in resource_type for pattern in db_patterns):
                    is_database = 1.0
                    break
            features.append(is_database)
            
            # Is network resource
            is_network = 0.0
            network_patterns = ['vpc', 'subnet', 'security group', 'acl', 'route', 'gateway']
            for resource_type in resource_types:
                if any(pattern in resource_type for pattern in network_patterns):
                    is_network = 1.0
                    break
            features.append(is_network)
            
            return features
            
        except Exception as e:
            self.logger.error(f"Error extracting resource features: {e}")
            return [0.0, 0.0, 0.0]
    
    def _normalize_features(self, features: np.ndarray) -> np.ndarray:
        """
        Normalize features based on configured parameters
        
        Args:
            features: Feature array
            
        Returns:
            Normalized feature array
        """
        # If normalization parameters are provided, use them
        if 'means' in self.normalization and 'stds' in self.normalization:
            means = np.array(self.normalization['means'])
            stds = np.array(self.normalization['stds'])
            
            # Apply standard scaling: (x - mean) / std
            normalized = (features - means) / stds
            
            # Replace NaNs with 0
            normalized = np.nan_to_num(normalized)
            
            return normalized
        
        # Otherwise, just return the original features
        return features
