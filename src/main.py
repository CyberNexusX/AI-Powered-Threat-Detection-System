#!/usr/bin/env python3
"""
AI-Powered Threat Detection System
Main entry point for the application
"""

import argparse
import logging
import os
import sys
import yaml
from datetime import datetime

# Add the project root directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.detector import ThreatDetector
from src.core.controller import SystemController
from src.utils.logger import setup_logging
from src.integrations.splunk_connector import SplunkConnector
from src.integrations.aws_connector import AWSConnector


def parse_args():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description='AI-Powered Threat Detection System')
    parser.add_argument('--config', type=str, default='config/config.yaml',
                        help='Path to configuration file')
    parser.add_argument('--log-level', type=str, default='INFO',
                        choices=['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL'],
                        help='Set the logging level')
    parser.add_argument('--mode', type=str, default='monitor',
                        choices=['monitor', 'analyze', 'train', 'test'],
                        help='Operation mode')
    return parser.parse_args()


def load_config(config_path):
    """Load configuration from YAML file."""
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        logging.error(f"Configuration file not found: {config_path}")
        sys.exit(1)
    except yaml.YAMLError as e:
        logging.error(f"Error parsing configuration file: {e}")
        sys.exit(1)


def main():
    """Main entry point for the application."""
    # Parse command line arguments
    args = parse_args()
    
    # Setup logging
    setup_logging(args.log_level)
    
    # Load configuration
    config = load_config(args.config)
    
    logging.info("Starting AI-Powered Threat Detection System")
    logging.info(f"Mode: {args.mode}")
    
    try:
        # Initialize connectors
        aws_connector = AWSConnector(config['aws'])
        splunk_connector = SplunkConnector(config['splunk'])
        
        # Initialize the threat detector
        detector = ThreatDetector(
            model_path=config['ml']['model_path'],
            threshold=config['ml']['threshold'],
            feature_config=config['ml']['features']
        )
        
        # Initialize the system controller
        controller = SystemController(
            detector=detector,
            aws_connector=aws_connector,
            splunk_connector=splunk_connector,
            config=config
        )
        
        # Run the system in the specified mode
        if args.mode == 'monitor':
            controller.start_monitoring()
        elif args.mode == 'analyze':
            controller.analyze_logs()
        elif args.mode == 'train':
            controller.train_models()
        elif args.mode == 'test':
            controller.run_tests()
        
    except KeyboardInterrupt:
        logging.info("System shutdown requested by user")
    except Exception as e:
        logging.error(f"Unexpected error: {e}", exc_info=True)
        sys.exit(1)
    finally:
        logging.info("AI-Powered Threat Detection System shutting down")


if __name__ == "__main__":
    main()
