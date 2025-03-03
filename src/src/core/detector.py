"""
Core threat detection module that implements ML-based detection algorithms
"""

import logging
import numpy as np
import tensorflow as tf
import json
import os
from datetime import datetime
from typing import Dict, List, Tuple, Any, Optional

from src.utils.feature_extractor import FeatureExtractor
from src.utils.preprocessor import Preprocessor
from src.models.model_loader import load_model
from src.core.rules_engine import RulesEngine


class ThreatDetector:
    """
    Main threat detection class that combines ML model inference with rule-based detection
    """
    
    def __init__(self, model_path: str, threshold: float = 0.7, feature_config: Dict = None):
        """
        Initialize the threat detector with ML model and rules
        
        Args:
            model_path: Path to the TensorFlow model
            threshold: Confidence threshold for threat detection
            feature_config: Configuration for feature extraction
        """
        self.logger = logging.getLogger(__name__)
        self.threshold = threshold
        self.feature_config = feature_config or {}
        
        # Load TensorFlow model
        self.logger.info(f"Loading model from {model_path}")
        self.model = load_model(model_path)
        
        # Initialize preprocessor and feature extractor
        self.preprocessor = Preprocessor()
        self.feature_extractor = FeatureExtractor(self.feature_config)
        
        # Initialize rules engine for rule-based detection
        self.rules_engine = RulesEngine()
        
        self.logger.info("Threat detector initialized successfully")
    
    def detect(self, events: List[Dict]) -> List[Dict]:
        """
        Process events and detect threats using both ML and rules
        
        Args:
            events: List of event dictionaries from cloud environment
            
        Returns:
            List of detection results with threat scores and classifications
        """
        self.logger.debug(f"Processing {len(events)} events for threat detection")
        
        # Preprocess events
        preprocessed_events = self.preprocessor.process(events)
        
        # Extract features for ML model
        features = self.feature_extractor.extract_features(preprocessed_events)
        
        # Get ML predictions
        ml_results = self._get_ml_predictions(features, preprocessed_events)
        
        # Get rule-based detections
        rule_results = self.rules_engine.evaluate(preprocessed_events)
        
        # Combine results
        combined_results = self._combine_results(ml_results, rule_results)
        
        # Log detection summary
        threats_found = sum(1 for result in combined_results if result['is_threat'])
        self.logger.info(f"Detected {threats_found} potential threats in {len(events)} events")
        
        return combined_results
    
    def _get_ml_predictions(self, features: np.ndarray, events: List[Dict]) -> List[Dict]:
        """
        Run inference on the ML model
        
        Args:
            features: Extracted feature array
            events: Preprocessed events
            
        Returns:
            List of ML detection results
        """
        if len(features) == 0:
            return []
        
        # Perform prediction with the model
        try:
            predictions = self.model.predict(features)
            
            # Format results
            results = []
            for i, prediction in enumerate(predictions):
                score = float(prediction[0])
                is_threat = score >= self.threshold
                
                results.append({
                    'event_id': events[i].get('id', f"event_{i}"),
                    'timestamp': events[i].get('timestamp', datetime.now().isoformat()),
                    'source': events[i].get('source', 'unknown'),
                    'ml_score': score,
                    'is_threat': is_threat,
                    'confidence': score if is_threat else 1 - score,
                    'detection_method': 'ml_model',
                    'raw_event': events[i]
                })
            
            return results
            
        except Exception as e:
            self.logger.error(f"Error during model prediction: {e}")
            return []
    
    def _combine_results(self, ml_results: List[Dict], rule_results: List[Dict]) -> List[Dict]:
        """
        Combine ML and rule-based detection results
        
        Args:
            ml_results: Results from ML model
            rule_results: Results from rules engine
            
        Returns:
            Combined threat detection results
        """
        # Create a dictionary for fast lookup by event_id
        combined = {}
        
        # Process ML results
        for result in ml_results:
            event_id = result['event_id']
            combined[event_id] = result
        
        # Integrate rule results
        for result in rule_results:
            event_id = result['event_id']
            
            if event_id in combined:
                # If we have both ML and rule detections, use the higher confidence
                existing = combined[event_id]
                
                # If either detection method identifies as threat, mark as threat
                is_threat = existing['is_threat'] or result['is_threat']
                
                # Take the higher confidence score
                if result['is_threat'] and (not existing['is_threat'] or result['confidence'] > existing['confidence']):
                    combined[event_id] = {
                        **existing,
                        'is_threat': True,
                        'confidence': result['confidence'],
                        'detection_method': 'rule_engine',
                        'rule_id': result.get('rule_id'),
                        'rule_description': result.get('rule_description')
                    }
                
                # If both methods detect a threat, mark as hybrid detection with higher confidence
                if existing['is_threat'] and result['is_threat']:
                    combined[event_id]['detection_method'] = 'hybrid'
                    combined[event_id]['rule_id'] = result.get('rule_id')
                    combined[event_id]['rule_description'] = result.get('rule_description')
            else:
                # Only rule detection exists
                combined[event_id] = result
        
        return list(combined.values())
    
    def analyze_event(self, event: Dict) -> Dict:
        """
        Analyze a single event for threat detection
        
        Args:
            event: Single event dictionary
            
        Returns:
            Detection result for the event
        """
        return self.detect([event])[0]
        
    def update_model(self, new_model_path: str) -> bool:
        """
        Update the ML model with a new version
        
        Args:
            new_model_path: Path to the new model
            
        Returns:
            True if update was successful, False otherwise
        """
        try:
            new_model = load_model(new_model_path)
            self.model = new_model
            self.logger.info(f"Model updated successfully from {new_model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to update model: {e}")
            return False
