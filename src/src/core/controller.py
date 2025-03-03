"""
System controller for managing the threat detection workflow
"""

import logging
import time
import threading
import queue
from typing import Dict, List, Optional, Any
from datetime import datetime, timedelta

from src.core.detector import ThreatDetector
from src.integrations.aws_connector import AWSConnector
from src.integrations.splunk_connector import SplunkConnector
from src.core.responder import ThreatResponder


class SystemController:
    """
    Controls the overall system operation, coordinates components,
    and manages the detection workflow
    """
    
    def __init__(self, detector: ThreatDetector, 
                 aws_connector: AWSConnector,
                 splunk_connector: SplunkConnector,
                 config: Dict):
        """
        Initialize the system controller
        
        Args:
            detector: The threat detector instance
            aws_connector: AWS integration connector
            splunk_connector: Splunk integration connector
            config: System configuration
        """
        self.logger = logging.getLogger(__name__)
        self.detector = detector
        self.aws_connector = aws_connector
        self.splunk_connector = splunk_connector
        self.config = config
        
        # Initialize the threat responder
        self.responder = ThreatResponder(
            aws_connector=self.aws_connector,
            config=self.config.get('response', {})
        )
        
        # Setup event queue for asynchronous processing
        self.event_queue = queue.Queue(maxsize=10000)
        self.result_queue = queue.Queue(maxsize=10000)
        
        # Control flags
        self.running = False
        self.worker_threads = []
        
        # Configure detection parameters
        self.poll_interval = self.config.get('system', {}).get('poll_interval_seconds', 60)
        self.batch_size = self.config.get('system', {}).get('batch_size', 100)
        self.worker_count = self.config.get('system', {}).get('worker_count', 4)
        
        self.logger.info("System controller initialized")
    
    def start_monitoring(self):
        """Start real-time monitoring of cloud environment"""
        self.logger.info("Starting real-time monitoring")
        self.running = True
        
        # Start worker threads for event processing
        for i in range(self.worker_count):
            worker = threading.Thread(
                target=self._detection_worker,
                name=f"detection-worker-{i}",
                daemon=True
            )
            worker.start()
            self.worker_threads.append(worker)
        
        # Start result processor thread
        result_processor = threading.Thread(
            target=self._result_processor,
            name="result-processor",
            daemon=True
        )
        result_processor.start()
        self.worker_threads.append(result_processor)
        
        try:
            while self.running:
                # Collect events from AWS
                self.logger.debug("Collecting events from cloud environment")
                events = self.aws_connector.collect_events(max_events=self.batch_size)
                
                if events:
                    self.logger.debug(f"Collected {len(events)} events, adding to queue")
                    # Add events to queue for processing
                    for event in events:
                        self.event_queue.put(event)
                
                # Sleep before next polling
                time.sleep(self.poll_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Monitoring interrupted by user")
            self.stop_monitoring()
        except Exception as e:
            self.logger.error(f"Error in monitoring loop: {e}", exc_info=True)
            self.stop_monitoring()
    
    def stop_monitoring(self):
        """Stop the monitoring process"""
        self.logger.info("Stopping monitoring")
        self.running = False
        
        # Wait for queues to empty
        while not self.event_queue.empty():
            time.sleep(0.5)
        
        # Wait for all threads to complete
        for thread in self.worker_threads:
            if thread.is_alive():
                thread.join(timeout=5.0)
        
        self.logger.info("Monitoring stopped")
    
    def _detection_worker(self):
        """Worker thread function for threat detection"""
        logger = logging.getLogger(f"{__name__}.worker")
        
        logger.info("Detection worker started")
        
        while self.running:
            try:
                # Collect batch of events from queue
                events = []
                try:
                    # Get at least one event (blocking)
                    event = self.event_queue.get(block=True, timeout=1.0)
                    events.append(event)
                    
                    # Try to get more events up to batch size (non-blocking)
                    for _ in range(self.batch_size - 1):
                        if not self.event_queue.empty():
                            event = self.event_queue.get(block=False)
                            events.append(event)
                        else:
                            break
                except queue.Empty:
                    # Timeout occurred, continue to next iteration
                    continue
                
                if events:
                    # Process batch of events
                    logger.debug(f"Processing batch of {len(events)} events")
                    detection_results = self.detector.detect(events)
                    
                    # Put results in result queue
                    for result in detection_results:
                        self.result_queue.put(result)
                        
                    # Mark tasks as done
                    for _ in range(len(events)):
                        self.event_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in detection worker: {e}", exc_info=True)
    
    def _result_processor(self):
        """Worker thread for processing detection results"""
        logger = logging.getLogger(f"{__name__}.results")
        
        logger.info("Result processor started")
        
        while self.running:
            try:
                # Get detection results from queue
                results = []
                try:
                    # Get at least one result (blocking)
                    result = self.result_queue.get(block=True, timeout=1.0)
                    results.append(result)
                    
                    # Try to get more results up to batch size (non-blocking)
                    for _ in range(self.batch_size - 1):
                        if not self.result_queue.empty():
                            result = self.result_queue.get(block=False)
                            results.append(result)
                        else:
                            break
                except queue.Empty:
                    # Timeout occurred, continue to next iteration
                    continue
                
                if results:
                    # Process detection results
                    threats = [r for r in results if r['is_threat']]
                    
                    if threats:
                        logger.info(f"Processing {len(threats)} threats out of {len(results)} results")
                        
                        # Send threats to Splunk
                        self.splunk_connector.send_events(threats)
                        
                        # Execute automated responses for threats
                        for threat in threats:
                            self.responder.respond(threat)
                    
                    # Mark tasks as done
                    for _ in range(len(results)):
                        self.result_queue.task_done()
                
            except Exception as e:
                logger.error(f"Error in result processor: {e}", exc_info=True)
    
    def analyze_logs(self, timeframe: Optional[str] = "1d"):
        """
        Analyze historical logs for a specific timeframe
        
        Args:
            timeframe: Time period to analyze (e.g., "1d", "6h", "1w")
        """
        self.logger.info(f"Starting historical log analysis for past {timeframe}")
        
        # Parse timeframe
        unit = timeframe[-1]
        value = int(timeframe[:-1])
        
        # Calculate time range
        end_time = datetime.now()
        
        if unit == 'd':
            start_time = end_time - timedelta(days=value)
        elif unit == 'h':
            start_time = end_time - timedelta(hours=value)
        elif unit == 'w':
            start_time = end_time - timedelta(weeks=value)
        else:
            self.logger.error(f"Invalid timeframe format: {timeframe}")
            return
        
        # Collect historical events
        events = self.aws_connector.collect_historical_events(
            start_time=start_time,
            end_time=end_time
        )
        
        if not events:
            self.logger.info(f"No events found for timeframe {timeframe}")
            return
        
        self.logger.info(f"Analyzing {len(events)} events from {start_time} to {end_time}")
        
        # Process events in batches
        batch_size = self.batch_size
        results = []
        
        for i in range(0, len(events), batch_size):
            batch = events[i:i+batch_size]
            batch_results = self.detector.detect(batch)
            results.extend(batch_results)
            
            # Log progress
            self.logger.info(f"Processed {min(i+batch_size, len(events))}/{len(events)} events")
        
        # Filter threats
        threats = [r for r in results if r['is_threat']]
        
        # Send threats to Splunk
        if threats:
            self.logger.info(f"Found {len(threats)} potential threats in historical analysis")
            self.splunk_connector.send_events(threats)
        else:
            self.logger.info("No threats found in historical analysis")
        
        return results
    
    def train_models(self):
        """Train or retrain the ML models"""
        self.logger.info("Starting model training")
        
        # Import training module here to avoid circular imports
        from src.training.trainer import ModelTrainer
        
        trainer = ModelTrainer(config=self.config.get('training', {}))
        
        # Start training
        new_model_path = trainer.train()
        
        if new_model_path:
            # Update the detector with new model
            success = self.detector.update_model(new_model_path)
            if success:
                self.logger.info(f"Detector updated with new model: {new_model_path}")
            else:
                self.logger.error("Failed to update detector with new model")
        else:
            self.logger.error("Model training failed")
    
    def run_tests(self):
        """Run system tests"""
        self.logger.info("Starting system tests")
        
        from src.testing.system_tester import SystemTester
        
        tester = SystemTester(
            detector=self.detector,
            aws_connector=self.aws_connector,
            splunk_connector=self.splunk_connector,
            config=self.config.get('testing', {})
        )
        
        test_results = tester.run_tests()
        
        if test_results.get('success'):
            self.logger.info(f"System tests passed: {test_results.get('passed')} of {test_results.get('total')}")
        else:
            self.logger.error(f"System tests failed: {test_results.get('passed')} of {test_results.get('total')}")
