"""
AWS integration module for collecting events and executing responses
"""

import logging
import boto3
import json
import time
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from botocore.exceptions import ClientError


class AWSConnector:
    """
    Connector for AWS services to collect logs and execute actions
    """
    
    def __init__(self, config: Dict):
        """
        Initialize AWS connector
        
        Args:
            config: AWS connection and configuration settings
        """
        self.logger = logging.getLogger(__name__)
        self.config = config
        
        # AWS region
        self.region = config.get('region', 'us-east-1')
        
        # Configure AWS session
        self.session = self._create_session()
        
        # Initialize service clients
        self.cloudtrail = self.session.client('cloudtrail', region_name=self.region)
        self.cloudwatch = self.session.client('cloudwatch', region_name=self.region)
        self.logs = self.session.client('logs', region_name=self.region)
        self.ec2 = self.session.client('ec2', region_name=self.region)
        self.iam = self.session.client('iam', region_name=self.region)
        self.s3 = self.session.client('s3', region_name=self.region)
        
        # Get CloudTrail settings
        self.trail_name = config.get('cloudtrail', {}).get('trail_name')
        
        # Get CloudWatch Logs settings
        self.log_groups = config.get('logs', {}).get('log_groups', [])
        
        self.logger.info(f"AWS connector initialized for region {self.region}")
    
    def _create_session(self) -> boto3.Session:
        """
        Create AWS session with credentials
        
        Returns:
            Configured boto3 session
        """
        # Check if profile is specified
        profile = self.config.get('profile')
        if profile:
            return boto3.Session(profile_name=profile)
        
        # Otherwise use access keys or instance profile
        access_key = self.config.get('access_key')
        secret_key = self.config.get('secret_key')
        
        if access_key and secret_key:
            return boto3.Session(
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                region_name=self.region
            )
        
        # Use default credential provider chain
        return boto3.Session(region_name=self.region)
    
    def collect_events(self, max_events: int = 100) -> List[Dict]:
        """
        Collect recent events from CloudTrail and CloudWatch Logs
        
        Args:
            max_events: Maximum number of events to collect
            
        Returns:
            List of event dictionaries
        """
        events = []
        
        try:
            # Get CloudTrail events
            if self.trail_name:
                trail_events = self._get_cloudtrail_events(max_events=max_events // 2)
                events.extend(trail_events)
            
            # Get CloudWatch Logs events
            if self.log_groups:
                log_events = self._get_cloudwatch_logs(max_events=max_events // 2)
                events.extend(log_events)
            
            # Limit to max_events
            if len(events) > max_events:
                events = events[:max_events]
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error collecting AWS events: {e}")
            return []
    
    def _get_cloudtrail_events(self, max_events: int = 50) -> List[Dict]:
        """
        Get recent events from CloudTrail
        
        Args:
            max_events: Maximum number of events to retrieve
            
        Returns:
            List of CloudTrail events
        """
        events = []
        
        try:
            # Set time range to past hour
            end_time = datetime.now()
            start_time = end_time - timedelta(hours=1)
            
            response = self.cloudtrail.lookup_events(
                LookupAttributes=[],
                StartTime=start_time,
                EndTime=end_time,
                MaxResults=max_events
            )
            
            for event in response.get('Events', []):
                try:
                    # Parse the CloudTrail event
                    event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                    events.append(event_data)
                except json.JSONDecodeError:
                    self.logger.warning(f"Failed to parse CloudTrail event: {event.get('EventId')}")
            
            return events
        
        except ClientError as e:
            self.logger.error(f"AWS API error getting CloudTrail events: {e}")
            return []
        except Exception as e:
            self.logger.error(f"Error getting CloudTrail events: {e}")
            return []
    
    def _get_cloudwatch_logs(self, max_events: int = 50) -> List[Dict]:
        """
        Get recent events from CloudWatch Logs
        
        Args:
            max_events: Maximum number of events to retrieve
            
        Returns:
            List of CloudWatch Log events
        """
        events = []
        events_per_group = max(1, max_events // len(self.log_groups))
        
        try:
            for log_group in self.log_groups:
                try:
                    # List log streams
                    streams_response = self.logs.describe_log_streams(
                        logGroupName=log_group,
                        orderBy='LastEventTime',
                        descending=True,
                        limit=5  # Get 5 most recent streams
                    )
                    
                    # Get events from each stream
                    for stream in streams_response.get('logStreams', []):
                        stream_name = stream.get('logStreamName')
                        
                        logs_response = self.logs.get_log_events(
                            logGroupName=log_group,
                            logStreamName=stream_name,
                            limit=events_per_group,
                            startFromHead=False  # Get most recent events
                        )
                        
                        for log_event in logs_response.get('events', []):
                            try:
                                # Parse log message as JSON if possible
                                message = log_event.get('message', '{}')
                                event_data = json.loads(message)
                                
                                # Add metadata
                                event_data['logGroup'] = log_group
                                event_data['logStream'] = stream_name
                                event_data['timestamp'] = log_event.get('timestamp', 0) / 1000  # Convert to seconds
                                
                                events.append(event_data)
                            except json.JSONDecodeError:
                                # If not JSON, create a simple event structure
                                events.append({
                                    'logGroup': log_group,
                                    'logStream': stream_name,
                                    'timestamp': log_event.get('timestamp', 0) / 1000,
                                    'message': log_event.get('message', ''),
                                    'raw': True
                                })
                        
                        # Stop if we have enough events
                        if len(events) >= max_events:
                            break
                    
                except ClientError as e:
                    self.logger.error(f"AWS API error getting logs from {log_group}: {e}")
                
                # Stop if we have enough events
                if len(events) >= max_events:
                    break
            
            return events[:max_events]
        
        except Exception as e:
            self.logger.error(f"Error getting CloudWatch Logs: {e}")
            return []
    
    def collect_historical_events(self, start_time: datetime, end_time: datetime = None) -> List[Dict]:
        """
        Collect historical events from CloudTrail within a time range
        
        Args:
            start_time: Start time for event collection
            end_time: End time for event collection (defaults to now)
            
        Returns:
            List of event dictionaries
        """
        if end_time is None:
            end_time = datetime.now()
        
        events = []
        next_token = None
        
        try:
            while True:
                # Prepare lookup parameters
                lookup_kwargs = {
                    'StartTime': start_time,
                    'EndTime': end_time,
                    'MaxResults': 50
                }
                
                if next_token:
                    lookup_kwargs['NextToken'] = next_token
                
                # Query CloudTrail
                response = self.cloudtrail.lookup_events(**lookup_kwargs)
                
                # Process events
                for event in response.get('Events', []):
                    try:
                        event_data = json.loads(event.get('CloudTrailEvent', '{}'))
                        events.append(event_data)
                    except json.JSONDecodeError:
                        continue
                
                # Check if more pages
                next_token = response.get('NextToken')
                if not next_token:
                    break
                
                # Avoid rate limiting
                time.sleep(0.2)
            
            return events
        
        except Exception as e:
            self.logger.error(f"Error collecting historical events: {e}")
            return []
    
    def block_ip(self, ip_address: str, security_group_id: str = None) -> bool:
        """
        Block an IP address in a security group
        
        Args:
            ip_address: IP address to block
            security_group_id: Security group ID (if None, uses default from config)
            
        Returns:
            True if successful, False otherwise
        """
        if security_group_id is None:
            security_group_id = self.config.get('security', {}).get('security_group_id')
            
        if not security_group_id:
            self.logger.error("No security group ID provided for IP blocking")
            return False
        
        try:
            # Add deny rule for the IP
            response = self.ec2.authorize_security_group_ingress(
                GroupId=security_group_id,
                IpPermissions=[
                    {
                        'IpProtocol': '-1',  # All protocols
                        'FromPort': -1,      # All ports
                        'ToPort': -1,
                        'IpRanges': [
                            {
                                'CidrIp': f"{ip_address}/32",
                                'Description': f"Blocked by threat detection system at {datetime.now().isoformat()}"
                            }
                        ]
                    }
                ]
            )
            
            return True
        
        except ClientError as e:
            self.logger.error(f"Failed to block IP {ip_address}: {e}")
            return False
    
    def disable_user(self, username: str) -> bool:
        """
        Disable an IAM user
        
        Args:
            username: IAM username to disable
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # First remove access keys
            response = self.iam.list_access_keys(UserName=username)
            
            for key in response.get('AccessKeyMetadata', []):
                key_id = key.get('AccessKeyId')
                self.iam.update_access_key(
                    UserName=username,
                    AccessKeyId=key_id,
                    Status='Inactive'
                )
            
            # Then remove console access
            try:
                self.iam.delete_login_profile(UserName=username)
            except ClientError as e:
                # User might not have console access
                pass
            
            self.logger.info(f"Successfully disabled user {username}")
            return True
        
        except ClientError as e:
            self.logger.error(f"Failed to disable user {username}: {e}")
            return False
    
    def quarantine_instance(self, instance_id: str) -> bool:
        """
        Quarantine an EC2 instance by moving it to a restricted security group
        
        Args:
            instance_id: EC2 instance ID
            
        Returns:
            True if successful, False otherwise
        """
        quarantine_sg = self.config.get('security', {}).get('quarantine_security_group')
        
        if not quarantine_sg:
            self.logger.error("No quarantine security group defined")
            return False
        
        try:
            # Modify the instance security groups
            response = self.ec2.modify_instance_attribute(
                InstanceId=instance_id,
                Groups=[quarantine_sg]
            )
            
            self.logger.info(f"Successfully quarantined instance {instance_id}")
            return True
        
        except ClientError as e:
            self.logger.error(f"Failed to quarantine instance {instance_id}: {e}")
            return False
