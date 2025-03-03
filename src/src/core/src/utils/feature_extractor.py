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
            
            if
