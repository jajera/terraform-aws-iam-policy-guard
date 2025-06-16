#!/usr/bin/env python3
"""IAM Policy Violation Detector.

This module can be run both as an AWS Lambda function and locally for
testing. The main business logic is separated from the Lambda handler
for better testability.
"""

import argparse
import fnmatch
import json
import logging
import os
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.request import Request, urlopen

import boto3
import yaml
from violation_event import (
    MockViolationEventPublisher,
    ViolationEventPublisher,
)


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Set up logging configuration.

    Args:
        level: The logging level to use. Defaults to "INFO".

    Returns:
        logging.Logger: Configured logger instance.
    """
    logger = logging.getLogger(__name__)
    if not logger.handlers:  # Avoid duplicate handlers
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)

    logger.setLevel(getattr(logging, level.upper()))
    return logger


logger = setup_logging()


@dataclass
class DetectorConfig:
    """Configuration for the detector.

    Stores configuration settings for the IAM policy
    violation detector, including storage locations,
    notification settings, and remediation options.
    """

    rules_bucket: str
    # Event-driven configuration
    use_eventbridge: bool = True
    # Legacy configuration (kept for backward compatibility)
    sns_topic_arn: str | None = None
    enable_slack_alerts: bool = False
    slack_webhook_url: str | None = None
    enable_remediation: bool = False
    sqs_queue_url: str | None = None
    # Bedrock configuration
    enable_bedrock_analysis: bool = False
    bedrock_model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0"

    @classmethod
    def from_env(cls) -> "DetectorConfig":
        """Create config from environment variables.

        Returns:
            DetectorConfig: Configured detector instance.
        """
        return cls(
            rules_bucket=os.environ.get("RULES_BUCKET", ""),
            sns_topic_arn=os.environ.get("SNS_TOPIC_ARN"),
            enable_slack_alerts=os.environ.get("ENABLE_SLACK_ALERTS", "false").lower()
            == "true",
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL"),
            enable_remediation=os.environ.get("ENABLE_REMEDIATION", "false").lower()
            == "true",
            sqs_queue_url=os.environ.get("SQS_QUEUE_URL"),
            enable_bedrock_analysis=os.environ.get(
                "ENABLE_BEDROCK_ANALYSIS", "false"
            ).lower()
            == "true",
            bedrock_model_id=os.environ.get(
                "BEDROCK_MODEL_ID", "anthropic.claude-3-sonnet-20240229-v1:0"
            ),
        )

    @classmethod
    def from_dict(cls, config_dict: dict) -> "DetectorConfig":
        """Create config from dictionary.

        Args:
            config_dict: Dictionary containing configuration settings.

        Returns:
            DetectorConfig: Configured detector instance.
        """
        return cls(**config_dict)


class AWSClientInterface(ABC):
    """Abstract interface for AWS clients to enable mocking.

    This interface defines the methods that must be implemented by the AWS
    client wrapper classes. It allows for mocking of AWS client methods during
    testing.
    """

    @abstractmethod
    def get_object(self, **kwargs: Any) -> Any:
        """Get an object from S3.

        Args:
            **kwargs: Keyword arguments to pass to S3 get_object.

        Returns:
            Any: Response from S3 get_object call.
        """
        pass

    @abstractmethod
    def put_object(self, **kwargs: Any) -> Any:
        """Put an object to S3.

        Args:
            **kwargs: Keyword arguments to pass to S3 put_object.

        Returns:
            Any: Response from S3 put_object call.
        """
        pass

    @abstractmethod
    def publish(self, **kwargs: Any) -> Any:
        """Publish a message to SNS.

        Args:
            **kwargs: Keyword arguments to pass to SNS publish.

        Returns:
            Any: Response from SNS publish call.
        """
        pass

    @abstractmethod
    def send_message(self, **kwargs: Any) -> Any:
        """Send a message to SQS.

        Args:
            **kwargs: Keyword arguments to pass to SQS send_message.

        Returns:
            Any: Response from SQS send_message call.
        """
        pass

    @abstractmethod
    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data to CloudWatch.

        Args:
            **kwargs: Keyword arguments to pass to CloudWatch put_metric_data.

        Returns:
            Any: Response from CloudWatch put_metric_data call.
        """
        pass

    @abstractmethod
    def put_events(self, **kwargs: Any) -> Any:
        """Put events to EventBridge.

        Args:
            **kwargs: Keyword arguments to pass to EventBridge put_events.

        Returns:
            Any: Response from EventBridge put_events call.
        """
        pass

    @abstractmethod
    def get_policy(self, **kwargs: Any) -> Any:
        """Get policy from IAM.

        Args:
            **kwargs: Keyword arguments to pass to IAM get_policy.

        Returns:
            Any: Response from IAM get_policy call.
        """
        pass

    @abstractmethod
    def get_policy_version(self, **kwargs: Any) -> Any:
        """Get policy version from IAM.

        Args:
            **kwargs: Keyword arguments to pass to IAM get_policy_version.

        Returns:
            Any: Response from IAM get_policy_version call.
        """
        pass

    @abstractmethod
    def invoke_model(self, **kwargs: Any) -> Any:
        """Invoke a Bedrock model.

        Args:
            **kwargs: Keyword arguments to pass to Bedrock invoke_model.

        Returns:
            Any: Response from Bedrock invoke_model call.
        """
        pass


class AWSClients(AWSClientInterface):
    """Real AWS clients wrapper.

    This class provides a wrapper around the AWS clients for the detector.
    It allows for mocking of AWS client methods during testing.
    """

    def __init__(self, region: str | None = None) -> None:
        """Initialize AWS clients.

        Args:
            region: The AWS region to use. Defaults to None.
        """
        self.s3 = boto3.client("s3", region_name=region)
        self.sns = boto3.client("sns", region_name=region)
        self.sqs = boto3.client("sqs", region_name=region)
        self.cloudwatch = boto3.client("cloudwatch", region_name=region)
        self.events = boto3.client("events", region_name=region)
        self.iam = boto3.client("iam", region_name=region)
        self.bedrock_runtime = boto3.client("bedrock-runtime", region_name=region)

    def get_object(self, **kwargs: Any) -> Any:
        """Get an object from S3.

        Args:
            **kwargs: Keyword arguments to pass to S3 get_object.

        Returns:
            Any: Response from S3 get_object call.
        """
        return self.s3.get_object(**kwargs)

    def put_object(self, **kwargs: Any) -> Any:
        """Put an object to S3.

        Args:
            **kwargs: Keyword arguments to pass to S3 put_object.

        Returns:
            Any: Response from S3 put_object call.
        """
        return self.s3.put_object(**kwargs)

    def publish(self, **kwargs: Any) -> Any:
        """Publish a message to SNS.

        Args:
            **kwargs: Keyword arguments to pass to SNS publish.

        Returns:
            Any: Response from SNS publish call.
        """
        return self.sns.publish(**kwargs)

    def send_message(self, **kwargs: Any) -> Any:
        """Send a message to SQS.

        Args:
            **kwargs: Keyword arguments to pass to SQS send_message.

        Returns:
            Any: Response from SQS send_message call.
        """
        return self.sqs.send_message(**kwargs)

    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data to CloudWatch.

        Args:
            **kwargs: Keyword arguments to pass to CloudWatch put_metric_data.

        Returns:
            Any: Response from CloudWatch put_metric_data call.
        """
        return self.cloudwatch.put_metric_data(**kwargs)

    def put_events(self, **kwargs: Any) -> Any:
        """Put events to EventBridge.

        Args:
            **kwargs: Keyword arguments to pass to EventBridge put_events.

        Returns:
            Any: Response from EventBridge put_events call.
        """
        return self.events.put_events(**kwargs)

    def get_policy(self, **kwargs: Any) -> Any:
        """Get policy from IAM.

        Args:
            **kwargs: Keyword arguments to pass to IAM get_policy.

        Returns:
            Any: Response from IAM get_policy call.
        """
        return self.iam.get_policy(**kwargs)

    def get_policy_version(self, **kwargs: Any) -> Any:
        """Get policy version from IAM.

        Args:
            **kwargs: Keyword arguments to pass to IAM get_policy_version.

        Returns:
            Any: Response from IAM get_policy_version call.
        """
        return self.iam.get_policy_version(**kwargs)

    def invoke_model(self, **kwargs: Any) -> Any:
        """Invoke a Bedrock model.

        Args:
            **kwargs: Keyword arguments to pass to Bedrock invoke_model.

        Returns:
            Any: Response from Bedrock invoke_model call.
        """
        return self.bedrock_runtime.invoke_model(**kwargs)


@dataclass
class BedrockAnalysisResult:
    """Result of Bedrock AI analysis.

    Stores the result of AI-powered risk analysis, including risk score,
    insights, recommendations, and potential impact assessment.
    """

    risk_score: int  # 1-10 scale
    risk_level: str  # LOW, MEDIUM, HIGH, CRITICAL
    summary: str
    detailed_analysis: str
    recommendations: list[str]
    potential_impact: str
    confidence: float  # 0.0-1.0
    analysis_timestamp: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the Bedrock analysis.
        """
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "summary": self.summary,
            "detailed_analysis": self.detailed_analysis,
            "recommendations": self.recommendations,
            "potential_impact": self.potential_impact,
            "confidence": self.confidence,
            "analysis_timestamp": self.analysis_timestamp,
        }


@dataclass
class ViolationResult:
    """Result of violation detection.

    Stores the result of a violation detection, including the rule name,
    description, severity, action, suppression status, timestamp, event name,
    event source, and optional Bedrock analysis results.
    """

    found: bool
    rule_name: str | None = None
    description: str | None = None
    severity: str | None = None
    action: str | None = None
    suppressed: bool = False
    timestamp: str | None = None
    event_name: str | None = None
    event_source: str | None = None
    bedrock_analysis: BedrockAnalysisResult | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dict[str, Any]: Dictionary representation of the violation result.
        """
        result: dict[str, Any] = {
            "rule_name": self.rule_name,
            "description": self.description,
            "severity": self.severity,
            "action": self.action,
            "timestamp": self.timestamp,
            "event_name": self.event_name,
            "event_source": self.event_source,
            "suppressed": self.suppressed,
        }

        if self.bedrock_analysis:
            result["bedrock_analysis"] = self.bedrock_analysis.to_dict()

        return result


class PolicyViolationDetector:
    """Main business logic for IAM policy violation detection.

    This class contains the main business logic for detecting IAM policy
    violations. It processes EventBridge events from CloudTrail, checks for
    violations against configured rules, and handles suppression of violations.
    """

    def __init__(
        self,
        config: DetectorConfig,
        aws_clients: AWSClientInterface,
        log_level: str = "INFO",
    ):
        """Initialize the PolicyViolationDetector.

        Args:
            config: The configuration for the detector.
            aws_clients: The AWS clients to use.
            log_level: The logging level to use.
        """
        self.config = config
        self.aws_clients = aws_clients
        self.logger = setup_logging(log_level)

        # Initialize event publisher for event-driven architecture
        self.event_publisher: (
            ViolationEventPublisher | MockViolationEventPublisher | None
        )
        if config.use_eventbridge:
            if isinstance(aws_clients, MockAWSClients):
                self.event_publisher = MockViolationEventPublisher(aws_clients)
            else:
                self.event_publisher = ViolationEventPublisher(aws_clients)
        else:
            self.event_publisher = None

    def process_eventbridge_event(self, event: dict) -> dict[str, Any]:
        """Process EventBridge event from CloudTrail.

        Args:
            event: The EventBridge event to process.

        Returns:
            Dict[str, Any]: The result of the event processing.
        """
        try:
            self.logger.info(f"Processing event: {json.dumps(event, default=str)}")

            # Extract CloudTrail event from EventBridge
            if "detail" not in event:
                self.logger.warning("No detail found in event")
                return {"statusCode": 200, "body": "No event detail found"}

            cloudtrail_event = event["detail"]

            # Load rules and suppression config from S3
            self.logger.debug("Loading rules config...")
            rules_config = self._load_config_from_s3("rules.yaml")
            self.logger.debug(f"Loaded rules config: {rules_config}")

            self.logger.debug("Loading suppress config...")
            suppress_config = self._load_config_from_s3("suppress.yaml")
            self.logger.debug(f"Loaded suppress config: {suppress_config}")

            # Check for violations
            self.logger.debug("Checking for violations...")
            violation = self._check_violations(cloudtrail_event, rules_config)
            self.logger.debug(f"Violation result: {violation}")

            if violation.found:
                self.logger.info(f"Violation found: {violation.rule_name}")
                # Check if violation should be suppressed
                is_suppressed = self._check_suppression(
                    cloudtrail_event, suppress_config
                )
                violation.suppressed = is_suppressed

                if not is_suppressed:
                    # Handle violation based on action
                    self._handle_violation(violation, cloudtrail_event)
                else:
                    self.logger.info(f"Violation suppressed: {violation.rule_name}")

                # Log violation to S3 for Athena analysis
                self._log_violation_to_s3(violation, cloudtrail_event)

                # Send CloudWatch metrics
                self._send_metrics(violation)
            else:
                self.logger.debug("No violations found")

            return {"statusCode": 200, "body": "Event processed successfully"}

        except Exception as e:
            self.logger.error(f"Error processing event: {e!s}", exc_info=True)
            return {"statusCode": 500, "body": f"Error: {e!s}"}

    def _load_config_from_s3(self, key: str) -> dict[str, Any]:
        """Load configuration from S3 bucket.

        Args:
            key: The key of the configuration file in S3.

        Returns:
            Dict[str, Any]: The loaded configuration.
        """
        try:
            # For MockAWSClients, allow empty bucket (local testing)
            if not self.config.rules_bucket and not isinstance(
                self.aws_clients, MockAWSClients
            ):
                self.logger.warning(
                    f"No rules bucket configured, returning empty config for {key}"
                )
                return {}

            response = self.aws_clients.get_object(
                Bucket=self.config.rules_bucket, Key=key
            )
            if response is None:
                raise ValueError(f"Failed to load config {key}")
            content = response["Body"].read().decode("utf-8")
            config = yaml.safe_load(content)
            return config if isinstance(config, dict) else {}
        except Exception as e:
            self.logger.error(f"Error loading config {key}: {e!s}")
            raise

    def _check_violations(self, event: dict, rules_config: dict) -> ViolationResult:
        """Check if the event violates any rules.

        Args:
            event: The EventBridge event to process.
            rules_config: The configuration for the rules.

        Returns:
            ViolationResult: The result of the violation detection.
        """
        event_name = event.get("eventName", "")
        event_source = event.get("eventSource", "")
        user_identity = event.get("userIdentity", {})
        resources = event.get("resources", [])

        self.logger.debug(f"Checking violations for event: {event_name}")
        self.logger.debug(
            f"Rules config has {len(rules_config.get('rules', []))} rules"
        )

        for rule in rules_config.get("rules", []):
            self.logger.debug(f"Checking rule: {rule['name']}")
            conditions = rule.get("conditions", {})

            # Check event names
            if event_name in conditions.get("event_names", []):
                self.logger.debug(
                    f"Event name {event_name} matches rule {rule['name']}"
                )

                # Check resource types (if specified)
                resource_types = conditions.get("resource_types", [])
                if resource_types:
                    resource_match = any(
                        any(
                            res_type in resource.get("type", "")
                            for res_type in resource_types
                        )
                        for resource in resources
                    )
                    if not resource_match:
                        self.logger.debug(
                            f"Resource types don't match for rule {rule['name']}"
                        )
                        continue

                # Check principals (if specified)
                principals = conditions.get("principals", [])
                if principals:
                    user_arn = user_identity.get("arn", "")
                    principal_match = any(
                        principal in user_arn for principal in principals
                    )
                    if not principal_match:
                        self.logger.debug(
                            f"Principals don't match for rule {rule['name']}"
                        )
                        continue

                # Check rule conditions
                rule_conditions = conditions.get("conditions", {})
                self.logger.debug(
                    f"Rule conditions for {rule['name']}: {rule_conditions}"
                )

                # Check policy ARNs for specific managed policies
                policy_arns = rule_conditions.get("policy_arns", [])
                if policy_arns:
                    request_params = event.get("requestParameters", {})
                    policy_arn = request_params.get("policyArn", "")

                    if not any(arn in policy_arn for arn in policy_arns):
                        self.logger.debug(
                            f"Policy ARNs don't match for rule {rule['name']}"
                        )
                        continue

                # Check policy document content for dangerous permissions
                policy_document_patterns = rule_conditions.get(
                    "policy_document_contains", []
                )

                if policy_document_patterns:
                    self.logger.debug(
                        f"Checking policy document patterns: {policy_document_patterns}"
                    )
                    policy_document = self._extract_policy_document(event)
                    self.logger.debug(f"Extracted policy document: {policy_document}")

                    if not policy_document:
                        # If we can't extract policy document
                        #  but rule requires it, skip
                        self.logger.debug(
                            f"No policy document found for rule {rule['name']}"
                        )
                        continue

                    policy_str = json.dumps(policy_document).lower()
                    self.logger.debug(f"Policy string for matching: {policy_str}")
                    matched = False

                    for pattern in policy_document_patterns:
                        self.logger.debug(f"Checking pattern: {pattern}")
                        if pattern.lower() in policy_str:
                            self.logger.debug(f"Pattern {pattern} matched!")
                            matched = True
                            break

                    if not matched:
                        self.logger.debug(
                            f"No policy document patterns matched for rule {rule['name']}"
                        )
                        continue

                # If we reach here, it's a violation
                self.logger.info(f"VIOLATION FOUND: {rule['name']}")
                violation_result = ViolationResult(
                    found=True,
                    rule_name=rule["name"],
                    description=rule["description"],
                    severity=rule["severity"],
                    action=rule["action"],
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    event_name=event_name,
                    event_source=event_source,
                )

                # Perform Bedrock analysis if enabled
                if self.config.enable_bedrock_analysis:
                    try:
                        bedrock_analysis = self._perform_bedrock_analysis(
                            violation_result, event
                        )
                        violation_result.bedrock_analysis = bedrock_analysis
                        self.logger.info(
                            f"Bedrock analysis completed for {rule['name']}"
                        )
                    except Exception as e:
                        self.logger.error(
                            f"Bedrock analysis failed for {rule['name']}: {e!s}"
                        )

                return violation_result
            else:
                self.logger.debug(
                    f"Event name {event_name} doesn't match rule {rule['name']} events: {conditions.get('event_names', [])}"
                )

        return ViolationResult(found=False)

    def _check_suppression(self, event: dict, suppress_config: dict) -> bool:
        """Check if the event should be suppressed.

        Args:
            event: The EventBridge event to process.
            suppress_config: The configuration for the suppressions.

        Returns:
            bool: True if the event should be suppressed, False otherwise.
        """
        user_agent = event.get("userAgent", "")
        source_ip = event.get("sourceIPAddress", "")
        user_identity = event.get("userIdentity", {})
        user_arn = user_identity.get("arn", "")
        event_name = event.get("eventName", "")

        for suppression in suppress_config.get("suppressions", []):
            conditions = suppression.get("conditions", {})

            # Check user agents
            user_agents = conditions.get("user_agents", [])
            if user_agents and any(
                agent in user_agent.lower() for agent in user_agents
            ):
                # Check if specific event names are required for suppression
                suppression_event_names = conditions.get("event_names", [])
                if (
                    suppression_event_names
                    and event_name not in suppression_event_names
                ):
                    continue

                self.logger.info(f"Suppressed by user agent: {user_agent}")
                return True

            # Check source IPs
            source_ips = conditions.get("source_ips", [])
            if source_ips and source_ip in source_ips:
                self.logger.info(f"Suppressed by source IP: {source_ip}")
                return True

            # Check principals
            principals = conditions.get("principals", [])
            if principals:
                for principal in principals:
                    # Check the user making the change
                    if principal in user_arn:
                        self.logger.info(f"Suppressed by principal (user): {user_arn}")
                        return True

                    # Also check the target resource being modified
                    request_params = event.get("requestParameters", {})
                    target_role = request_params.get("roleName", "")
                    target_user = request_params.get("userName", "")
                    target_group = request_params.get("groupName", "")

                    # Build target ARN patterns to check
                    account_id = event.get("recipientAccountId", "*")
                    target_arns = []
                    if target_role:
                        target_arns.append(
                            f"arn:aws:iam::{account_id}:role/{target_role}"
                        )
                    if target_user:
                        target_arns.append(
                            f"arn:aws:iam::{account_id}:user/{target_user}"
                        )
                    if target_group:
                        target_arns.append(
                            f"arn:aws:iam::{account_id}:group/{target_group}"
                        )

                    # Check if any target ARN matches the suppression pattern
                    for target_arn in target_arns:
                        # Use simple pattern matching (supports wildcards)
                        if fnmatch.fnmatch(target_arn, principal):
                            self.logger.info(
                                f"Suppressed by principal (target): {target_arn} matches {principal}"
                            )
                            return True

            # Check event names
            event_names = conditions.get("event_names", [])
            if event_names and event_name in event_names:
                self.logger.info(f"Suppressed by event name: {event_name}")
                return True

        # Only check if this is a dangerous policy AFTER checking suppression rules
        # This allows legitimate infrastructure roles to be suppressed even if they have wildcards
        if self._is_dangerous_policy_event(event):
            self.logger.info(
                "Dangerous policy detected but no suppression rule matched - not suppressing"
            )
            return False

        return False

    def _is_dangerous_policy_event(self, event: dict) -> bool:
        """Check if event contains a dangerous policy.

        This policy should never be suppressed due to potential security risks.

        Args:
            event: The EventBridge event to process.

        Returns:
            bool: True if the event contains a dangerous policy,
                False otherwise.
        """
        try:
            if event.get("eventName") not in [
                "PutUserPolicy",
                "PutRolePolicy",
            ]:
                return False

            policy_document = self._extract_policy_document(event)
            if not policy_document:
                return False

            policy_str = json.dumps(policy_document).lower()

            # Check for dangerous patterns
            dangerous_patterns = [
                '"action": "*"',
                '"action":"*"',
                '"*"',
                '"resource": "*"',
                '"resource":"*"',
                "*:*",
                "iam:*",
                "s3:*",
                "ec2:*",
            ]

            return any(pattern.lower() in policy_str for pattern in dangerous_patterns)

        except Exception as e:
            self.logger.error(f"Error checking dangerous policy: {e!s}")
            return False

    def _extract_policy_document(self, event: dict) -> dict[str, Any] | None:
        """Extract policy document from CloudTrail event."""
        try:
            request_params = event.get("requestParameters", {})

            # Check for inline policy document
            policy_document = request_params.get("policyDocument")
            if policy_document:
                if isinstance(policy_document, str):
                    parsed = json.loads(policy_document)
                    policy_document = parsed if isinstance(parsed, dict) else None
                elif not isinstance(policy_document, dict):
                    policy_document = None
                return policy_document

            # Check for policy ARN in attach operations
            policy_arn = request_params.get("policyArn")
            if policy_arn:
                try:
                    policy_response = self.aws_clients.get_policy(PolicyArn=policy_arn)
                    default_version = policy_response["Policy"]["DefaultVersionId"]

                    version_response = self.aws_clients.get_policy_version(
                        PolicyArn=policy_arn, VersionId=default_version
                    )

                    policy_doc = version_response["PolicyVersion"]["Document"]
                    return (
                        json.loads(policy_doc)
                        if isinstance(policy_doc, str)
                        else policy_doc
                    )

                except Exception as e:
                    self.logger.warning(
                        f"Could not fetch policy document for {policy_arn}: {e}"
                    )
                    return {"PolicyArn": policy_arn}

            return None
        except Exception as e:
            self.logger.error(f"Error extracting policy document: {e!s}")
            return None

    def _handle_violation(self, violation: ViolationResult, event: dict) -> None:
        """Handle violation based on action type."""
        action = violation.action

        if action == "log":
            self.logger.warning(
                "IAM Policy Violation - %s: %s",
                violation.rule_name,
                violation.description,
            )

        elif action == "alert":
            if self.config.use_eventbridge and self.event_publisher:
                # Use event-driven approach
                success = self.event_publisher.publish_violation(violation, event)
                if success:
                    self.logger.info("Violation event published to EventBridge")
                else:
                    self.logger.error("Failed to publish violation event")
                    # Fallback to direct notifications
                    self._send_alert(violation, event)
            else:
                # Use legacy direct notifications
                self._send_alert(violation, event)

        elif action == "remediate":
            # Queue for remediation
            self._queue_for_remediation(violation, event)

            # ALSO publish an alert event so operators are notified immediately
            if self.config.use_eventbridge and self.event_publisher:
                try:
                    self.event_publisher.publish_violation(violation, event)
                    self.logger.info(
                        "Violation event published to EventBridge (remediate branch)"
                    )
                except Exception as e:
                    self.logger.error(
                        f"Failed to publish alert event in remediate branch: {e!s}"
                    )

        else:
            self.logger.warning(f"Unknown action: {action}")

    def _send_alert(self, violation: ViolationResult, event: dict) -> None:
        """Send alert via SNS and optionally Slack."""
        message = self._format_alert_message(violation, event)

        # Send to SNS if configured
        if self.config.sns_topic_arn:
            try:
                self.aws_clients.publish(  # Send notification to SNS topic.
                    TopicArn=self.config.sns_topic_arn,
                    Subject=f"IAM Policy Violation: {violation.rule_name}",
                    Message=message,
                )
                self.logger.info("Alert sent to SNS")
            except Exception as e:
                self.logger.error(f"Error sending SNS alert: {e!s}")

        # Send to Slack if configured
        if self.config.enable_slack_alerts:
            self._send_slack_alert(violation, event)

    def _send_slack_alert(self, violation: ViolationResult, event: dict) -> None:
        """Send alert to Slack webhook."""
        if not self.config.slack_webhook_url:
            return

        try:
            user_identity = event.get("userIdentity", {})
            user_name = user_identity.get("userName", "Unknown")

            color = "danger" if violation.severity == "HIGH" else "warning"
            timestamp = int(datetime.now(timezone.utc).timestamp())

            fields = [
                {"title": "Rule", "value": violation.rule_name, "short": True},
                {
                    "title": "Severity",
                    "value": violation.severity,
                    "short": True,
                },
                {
                    "title": "Event",
                    "value": violation.event_name,
                    "short": True,
                },
                {"title": "User", "value": user_name, "short": True},
                {
                    "title": "Description",
                    "value": violation.description,
                    "short": False,
                },
            ]

            slack_message = {
                "text": "🚨 IAM Policy Violation Detected",
                "attachments": [
                    {
                        "color": color,
                        "fields": fields,
                        "timestamp": timestamp,
                    }
                ],
            }

            data = json.dumps(slack_message).encode("utf-8")
            req = Request(
                self.config.slack_webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )
            urlopen(req)
            self.logger.info("Alert sent to Slack")

        except Exception as e:
            self.logger.error(f"Error sending Slack alert: {e!s}")

    def _queue_for_remediation(self, violation: ViolationResult, event: dict) -> None:
        """Queue violation for remediation."""
        if not self.config.enable_remediation:
            self.logger.info("Remediation not enabled, logging violation instead")
            return

        if not self.config.sqs_queue_url:
            self.logger.error("SQS queue URL not configured")
            return

        try:
            remediation_message = {
                "violation": violation.to_dict(),
                "event": event,
                "remediation_action": self._determine_remediation_action(
                    violation, event
                ),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self.aws_clients.send_message(
                QueueUrl=self.config.sqs_queue_url,
                MessageBody=json.dumps(remediation_message, default=str),
            )
            self.logger.info("Violation queued for remediation")

        except Exception as e:
            self.logger.error(f"Error queuing for remediation: {e!s}")

    def _determine_remediation_action(
        self, _violation: ViolationResult, event: dict
    ) -> str:
        """Determine appropriate remediation action."""
        event_name = event.get("eventName", "")

        if event_name in ["AttachUserPolicy", "AttachRolePolicy"]:
            return "detach_policy"
        elif event_name == "CreatePolicy":
            return "delete_policy"
        elif event_name in ["PutUserPolicy", "PutRolePolicy"]:
            return "delete_inline_policy"
        else:
            return "log_only"

    def _log_violation_to_s3(self, violation: ViolationResult, event: dict) -> None:
        """Log violation to S3 for Athena analysis."""
        try:
            now = datetime.now(timezone.utc)

            # Create partitioned path for Athena
            year = str(now.year)
            month = str(now.month).zfill(2)
            day = str(now.day).zfill(2)

            date_prefix = f"violations/year={year}/month={month}/day={day}"
            timestamp = now.strftime("%Y%m%d_%H%M%S")
            filename = f"{timestamp}_{violation.rule_name}.json"

            s3_key = f"{date_prefix}/{filename}"

            violation_log = {
                "timestamp": violation.timestamp,
                "event_name": violation.event_name,
                "event_source": violation.event_source,
                "aws_region": event.get("awsRegion", ""),
                "source_ip_address": event.get("sourceIPAddress", ""),
                "user_agent": event.get("userAgent", ""),
                "user_identity": event.get("userIdentity", {}),
                "resources": event.get("resources", []),
                "rule_name": violation.rule_name,
                "severity": violation.severity,
                "action_taken": violation.action,
                "suppressed": violation.suppressed,
                "violation_details": self._extract_violation_details(event),
            }

            self.aws_clients.put_object(
                Bucket=self.config.rules_bucket,
                Key=s3_key,
                Body=json.dumps(violation_log, default=str),
                ContentType="application/json",
            )
            self.logger.info(f"Violation logged to S3: {s3_key}")

        except Exception as e:
            self.logger.error(f"Error logging to S3: {e!s}")

    def _extract_violation_details(self, event: dict) -> dict[str, Any]:
        """Extract specific violation details from the event."""
        details = {}
        resources = event.get("resources", [])

        for resource in resources:
            if resource.get("type") == "AWS::IAM::Policy":
                details["policy_arn"] = resource.get("ARN", "")
                details["policy_name"] = (
                    resource.get("ARN", "").split("/")[-1]
                    if resource.get("ARN")
                    else ""
                )
            elif resource.get("type") in ["AWS::IAM::User", "AWS::IAM::Role"]:
                details["attached_to"] = resource.get("ARN", "")

        return details

    def _send_metrics(self, violation: ViolationResult) -> None:
        """Send custom metrics to CloudWatch."""
        try:
            self.aws_clients.put_metric_data(
                Namespace="IAMPolicyMonitor",
                MetricData=[
                    {
                        "MetricName": "ViolationCount",
                        "Dimensions": [
                            {"Name": "Severity", "Value": violation.severity},
                            {"Name": "RuleName", "Value": violation.rule_name},
                        ],
                        "Value": 1,
                        "Unit": "Count",
                        "Timestamp": datetime.now(timezone.utc),
                    }
                ],
            )
            self.logger.info("Metrics sent to CloudWatch")

        except Exception as e:
            self.logger.error(f"Error sending metrics: {e!s}")

    def _perform_bedrock_analysis(
        self, violation: ViolationResult, event: dict
    ) -> BedrockAnalysisResult:
        """Perform AI-powered risk analysis using Amazon Bedrock.

        Args:
            violation: The violation result to analyze.
            event: The original CloudTrail event.

        Returns:
            BedrockAnalysisResult: The AI analysis result.

        Raises:
            Exception: If Bedrock analysis fails.
        """
        try:
            # Extract relevant information for analysis
            policy_document = self._extract_policy_document(event)
            violation_context = self._prepare_bedrock_context(
                violation, event, policy_document
            )

            # Create the prompt for Bedrock
            prompt = self._create_bedrock_prompt(violation_context)

            # Invoke Bedrock model
            response = self._invoke_bedrock_model(prompt)

            # Parse and validate the response
            analysis = self._parse_bedrock_response(response)

            return analysis

        except Exception as e:
            self.logger.error(f"Bedrock analysis failed: {e!s}")
            raise

    def _prepare_bedrock_context(
        self,
        violation: ViolationResult,
        event: dict,
        policy_document: dict | None,
    ) -> dict[str, Any]:
        """Prepare context information for Bedrock analysis.

        Args:
            violation: The violation result.
            event: The original CloudTrail event.
            policy_document: The IAM policy document if available.

        Returns:
            Dict[str, Any]: Context information for analysis.
        """
        user_identity = event.get("userIdentity", {})

        context = {
            "violation": {
                "rule_name": violation.rule_name,
                "description": violation.description,
                "severity": violation.severity,
                "event_name": violation.event_name,
                "event_source": violation.event_source,
            },
            "event_details": {
                "user_name": user_identity.get("userName", "Unknown"),
                "user_arn": user_identity.get("arn", "Unknown"),
                "user_type": user_identity.get("type", "Unknown"),
                "source_ip": event.get("sourceIPAddress", "Unknown"),
                "user_agent": event.get("userAgent", "Unknown"),
                "aws_region": event.get("awsRegion", "Unknown"),
                "timestamp": event.get("eventTime", violation.timestamp),
            },
            "request_parameters": event.get("requestParameters", {}),
            "policy_document": policy_document,
        }

        return context

    def _create_bedrock_prompt(self, context: dict[str, Any]) -> str:
        """Create a prompt for Bedrock analysis.

        Args:
            context: The context information for analysis.

        Returns:
            str: The formatted prompt for Bedrock.
        """
        policy_info = ""
        if context.get("policy_document"):
            policy_info = f"""
Policy Document:
{json.dumps(context["policy_document"], indent=2)}
"""

        prompt = f"""
You are a cybersecurity expert analyzing an IAM policy violation. Please provide a comprehensive risk analysis.

VIOLATION DETAILS:
- Rule: {context["violation"]["rule_name"]}
- Description: {context["violation"]["description"]}
- Severity: {context["violation"]["severity"]}
- Event: {context["violation"]["event_name"]}
- Source: {context["violation"]["event_source"]}

EVENT CONTEXT:
- User: {context["event_details"]["user_name"]} ({context["event_details"]["user_type"]})
- User ARN: {context["event_details"]["user_arn"]}
- Source IP: {context["event_details"]["source_ip"]}
- User Agent: {context["event_details"]["user_agent"]}
- Region: {context["event_details"]["aws_region"]}
- Timestamp: {context["event_details"]["timestamp"]}

REQUEST PARAMETERS:
{json.dumps(context["request_parameters"], indent=2)}
{policy_info}

Please analyze this IAM policy violation and provide your response in the following JSON format:
{{
    "risk_score": <integer 1-10>,
    "risk_level": "<LOW|MEDIUM|HIGH|CRITICAL>",
    "summary": "<brief 1-2 sentence summary>",
    "detailed_analysis": "<detailed technical analysis>",
    "recommendations": ["<recommendation 1>", "<recommendation 2>", ...],
    "potential_impact": "<description of potential security impact>",
    "confidence": <float 0.0-1.0>
}}

Focus on:
1. Security implications and risk level
2. Potential attack vectors or misuse scenarios
3. Business impact and compliance considerations
4. Specific remediation recommendations
5. Context-aware risk assessment (user, location, timing)
"""

        return prompt.strip()

    def _invoke_bedrock_model(self, prompt: str) -> dict[str, Any]:
        """Invoke the Bedrock model with the given prompt.

        Args:
            prompt: The prompt to send to the model.

        Returns:
            Dict[str, Any]: The raw response from Bedrock.

        Raises:
            Exception: If the Bedrock invocation fails.
        """
        try:
            # Prepare the request body for Claude 3 Sonnet
            request_body = {
                "anthropic_version": "bedrock-2023-05-31",
                "max_tokens": 4000,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.1,  # Low temperature for consistent analysis
                "top_p": 0.9,
            }

            # Invoke the model
            response = self.aws_clients.invoke_model(
                modelId=self.config.bedrock_model_id,
                contentType="application/json",
                accept="application/json",
                body=json.dumps(request_body),
            )

            # Parse the response
            response_body = json.loads(response["body"].read())

            return response_body

        except Exception as e:
            self.logger.error(f"Failed to invoke Bedrock model: {e!s}")
            raise

    def _parse_bedrock_response(
        self, response: dict[str, Any]
    ) -> BedrockAnalysisResult:
        """Parse the Bedrock response into a BedrockAnalysisResult.

        Args:
            response: The raw response from Bedrock.

        Returns:
            BedrockAnalysisResult: The parsed analysis result.

        Raises:
            Exception: If parsing fails or response is invalid.
        """
        try:
            # Extract the content from Claude 3 response
            content = response.get("content", [])
            if not content:
                raise ValueError("No content in Bedrock response")

            # Get the text content
            text_content = content[0].get("text", "")
            if not text_content:
                raise ValueError("No text content in Bedrock response")

            # Find JSON in the response (may have additional text around it)
            json_match = re.search(r"\{.*\}", text_content, re.DOTALL)
            if not json_match:
                raise ValueError("No JSON found in Bedrock response")

            analysis_data = json.loads(json_match.group())

            # Validate required fields
            required_fields = [
                "risk_score",
                "risk_level",
                "summary",
                "detailed_analysis",
                "recommendations",
                "potential_impact",
                "confidence",
            ]

            for field in required_fields:
                if field not in analysis_data:
                    raise ValueError(f"Missing required field: {field}")

            # Validate data types and ranges
            risk_score = int(analysis_data["risk_score"])
            if not 1 <= risk_score <= 10:
                raise ValueError(f"Risk score must be 1-10, got {risk_score}")

            confidence = float(analysis_data["confidence"])
            if not 0.0 <= confidence <= 1.0:
                raise ValueError(f"Confidence must be 0.0-1.0, got {confidence}")

            risk_level = analysis_data["risk_level"].upper()
            if risk_level not in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]:
                raise ValueError(f"Invalid risk level: {risk_level}")

            if not isinstance(analysis_data["recommendations"], list):
                raise ValueError("Recommendations must be a list")

            # Create and return the result
            return BedrockAnalysisResult(
                risk_score=risk_score,
                risk_level=risk_level,
                summary=str(analysis_data["summary"]),
                detailed_analysis=str(analysis_data["detailed_analysis"]),
                recommendations=analysis_data["recommendations"],
                potential_impact=str(analysis_data["potential_impact"]),
                confidence=confidence,
                analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            )

        except Exception as e:
            self.logger.error(f"Failed to parse Bedrock response: {e!s}")
            # Return a fallback analysis result
            return BedrockAnalysisResult(
                risk_score=5,
                risk_level="MEDIUM",
                summary="Bedrock analysis failed - manual review required",
                detailed_analysis=f"AI analysis could not be completed due to: {e!s}",
                recommendations=[
                    "Manually review this violation",
                    "Check Bedrock configuration",
                ],
                potential_impact="Unknown - requires manual assessment",
                confidence=0.0,
                analysis_timestamp=datetime.now(timezone.utc).isoformat(),
            )

    def _format_alert_message(self, violation: ViolationResult, event: dict) -> str:
        """Format alert message for SNS."""
        user_identity = event.get("userIdentity", {})

        message = f"""
IAM Policy Violation Detected

Rule: {violation.rule_name}
Severity: {violation.severity}
Description: {violation.description}

Event Details:
- Event Name: {violation.event_name}
- Event Source: {violation.event_source}
- Timestamp: {violation.timestamp}
- User: {user_identity.get("userName", "Unknown")}
- User ARN: {user_identity.get("arn", "Unknown")}
- Source IP: {event.get("sourceIPAddress", "Unknown")}
- User Agent: {event.get("userAgent", "Unknown")}
- AWS Region: {event.get("awsRegion", "Unknown")}"""

        # Add Bedrock analysis if available
        if violation.bedrock_analysis:
            analysis = violation.bedrock_analysis
            message += f"""

🤖 AI Risk Analysis:
- Risk Score: {analysis.risk_score}/10 ({analysis.risk_level})
- Summary: {analysis.summary}
- Potential Impact: {analysis.potential_impact}
- Confidence: {analysis.confidence:.2f}

Recommendations:
{chr(10).join([f"  • {rec}" for rec in analysis.recommendations])}"""

        message += """

Resources Affected:
"""

        for resource in event.get("resources", []):
            resource_type = resource.get("type", "Unknown")
            resource_arn = resource.get("ARN", "Unknown")
            message += f"- {resource_type}: {resource_arn}\n"

        return message


# Lambda handler function
def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """AWS Lambda handler - thin wrapper around business logic."""
    try:
        # Set log level based on DEBUG environment variable
        log_level = (
            "DEBUG" if os.environ.get("DEBUG", "false").lower() == "true" else "INFO"
        )

        config = DetectorConfig.from_env()
        aws_clients = AWSClients()
        detector = PolicyViolationDetector(config, aws_clients, log_level)

        return detector.process_eventbridge_event(event)

    except Exception as e:
        logger.error(f"Error in lambda_handler: {e!s}", exc_info=True)
        return {"statusCode": 500, "body": f"Error: {e!s}"}


# Local execution support
def create_sample_event() -> dict:
    """Create a sample EventBridge event for testing."""
    policy_doc = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Action":"*","Resource":"*"}]}'
    )

    return {
        "version": "0",
        "id": "12345678-1234-1234-1234-123456789012",
        "detail-type": "AWS API Call via CloudTrail",
        "source": "aws.iam",
        "account": "123456789012",
        "time": "2023-01-01T12:00:00Z",
        "region": "us-east-1",
        "detail": {
            "eventVersion": "1.08",
            "userIdentity": {
                "type": "IAMUser",
                "principalId": "AIDACKCEVSQ6C2EXAMPLE",
                "arn": "arn:aws:iam::123456789012:user/test-user",
                "accountId": "123456789012",
                "userName": "test-user",
            },
            "eventTime": "2023-01-01T12:00:00Z",
            "eventSource": "iam.amazonaws.com",
            "eventName": "PutUserPolicy",
            "awsRegion": "us-east-1",
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "terraform/1.0.0",
            "requestParameters": {
                "userName": "test-user",
                "policyName": "TestDangerousPolicy",
                "policyDocument": policy_doc,
            },
            "responseElements": None,
            "requestID": "12345678-1234-1234-1234-123456789012",
            "eventID": "87654321-4321-4321-4321-210987654321",
            "eventType": "AwsApiCall",
            "recipientAccountId": "123456789012",
            "serviceEventDetails": {"responseElements": None},
            "resources": [
                {
                    "type": "AWS::IAM::User",
                    "ARN": "arn:aws:iam::123456789012:user/test-user",
                }
            ],
        },
    }


class MockAWSClients(AWSClientInterface):
    """Mock AWS clients for local testing."""

    def __init__(
        self, rules_file: str | None = None, suppress_file: str | None = None
    ) -> None:
        """Initialize mock AWS clients."""
        logger.info("Using mock AWS clients for local testing")
        # Load local rules and suppress files if provided
        self.local_rules = None
        self.local_suppress = None

        if rules_file:
            with Path(rules_file).open() as f:
                self.local_rules = yaml.safe_load(f)

        if suppress_file:
            with Path(suppress_file).open() as f:
                self.local_suppress = yaml.safe_load(f)

    def get_object(self, **kwargs: Any) -> Any:
        """Mock S3 get_object."""
        key = kwargs.get("Key", "")
        if key == "rules.yaml" and self.local_rules:
            response = {
                "Body": type(
                    "obj",
                    (object,),
                    {"read": lambda *_: yaml.dump(self.local_rules).encode("utf-8")},
                )
            }
            return response
        elif key == "suppress.yaml" and self.local_suppress:
            response = {
                "Body": type(
                    "obj",
                    (object,),
                    {"read": lambda *_: yaml.dump(self.local_suppress).encode("utf-8")},
                )
            }
            return response
        else:
            # Return default empty configs
            empty_config: dict[str, Any] = {
                "rules": [],
                "suppressions": [],
            }
            response = {
                "Body": type(
                    "obj",
                    (object,),
                    {"read": lambda *_: yaml.dump(empty_config).encode("utf-8")},
                )
            }
            return response

    def put_object(self, **kwargs: Any) -> Any:
        """Mock S3 put_object."""
        bucket = kwargs.get("Bucket")
        key = kwargs.get("Key")
        logger.info(f"MOCK: put_object to s3://{bucket}/{key}")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def publish(self, **kwargs: Any) -> Any:
        """Mock SNS publish."""
        logger.info(f"MOCK: publish to SNS: {kwargs.get('Subject')}")
        logger.info(f"MOCK: SNS message: {kwargs.get('Message')}")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def send_message(self, **kwargs: Any) -> Any:
        """Mock SQS send_message."""
        queue_url = kwargs.get("QueueUrl")
        logger.info(f"MOCK: send_message to SQS: {queue_url}")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_metric_data(self, **kwargs: Any) -> Any:
        """Mock CloudWatch put_metric_data."""
        logger.info(f"MOCK: put_metric_data: {kwargs}")
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_events(self, **kwargs: Any) -> Any:
        """Mock EventBridge put_events."""
        entries = kwargs.get("Entries", [])
        logger.info(f"MOCK: put_events with {len(entries)} entries")
        for e in entries:
            logger.info(f"MOCK: {e.get('Source')} - {e.get('DetailType')}")
        return {
            "ResponseMetadata": {"HTTPStatusCode": 200},
            "FailedEntryCount": 0,
            "Entries": [],
        }

    def get_policy(self, **kwargs: Any) -> Any:
        """Mock IAM get_policy."""
        policy_arn = kwargs.get("PolicyArn", "")
        logger.info(f"MOCK: get_policy for {policy_arn}")
        return {
            "Policy": {
                "PolicyName": "MockPolicy",
                "DefaultVersionId": "v1",
                "Arn": policy_arn,
            }
        }

    def get_policy_version(self, **kwargs: Any) -> Any:
        """Mock IAM get_policy_version."""
        policy_arn = kwargs.get("PolicyArn", "")
        logger.info(f"MOCK: get_policy_version for {policy_arn}")
        return {
            "PolicyVersion": {
                "Document": '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
            }
        }

    def invoke_model(self, **kwargs: Any) -> Any:
        """Mock Bedrock invoke_model."""
        logger.info(f"MOCK: invoke_model with {kwargs}")

        # Return a mock response that matches Claude 3 Sonnet format
        mock_analysis = {
            "risk_score": 7,
            "risk_level": "HIGH",
            "summary": "Mock analysis: High-risk IAM policy violation detected with potential for privilege escalation.",
            "detailed_analysis": "This is a mock analysis response for testing purposes. The violation involves creating or modifying IAM policies with potentially dangerous permissions that could lead to privilege escalation.",
            "recommendations": [
                "Review and restrict the policy permissions",
                "Implement least-privilege access controls",
                "Monitor the affected user/role for unusual activity",
                "Consider automated remediation for this violation type",
            ],
            "potential_impact": "Could allow unauthorized access to AWS resources and potential account compromise",
            "confidence": 0.85,
        }

        mock_response = {
            "content": [
                {
                    "text": f"Based on my analysis, I've determined the following risk assessment:\n\n{json.dumps(mock_analysis, indent=2)}"
                }
            ],
            "ResponseMetadata": {"HTTPStatusCode": 200},
        }

        # Mock the body.read() method
        response_body = json.dumps(mock_response).encode("utf-8")
        mock_body = type("MockBody", (), {"read": lambda *_: response_body})()

        return {"body": mock_body, "ResponseMetadata": {"HTTPStatusCode": 200}}


def main() -> Any:
    r"""Run function for local execution.

    This function is used to test the detector locally. It can be run with
    the following command:

    python -m lambdas.detector --event event.json --rules rules.yaml \
        --suppress suppress.yaml
    """
    parser = argparse.ArgumentParser(description="IAM Policy Violation Detector")
    parser.add_argument("--config", help="Configuration file (JSON)")
    parser.add_argument("--event", help="Event file (JSON)")
    parser.add_argument("--rules", help="Rules YAML file")
    parser.add_argument("--suppress", help="Suppressions YAML file")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Setup logging (create local logger instead of using global)
    local_logger = setup_logging(args.log_level)

    # Load configuration
    if args.config:
        with Path(args.config).open() as f:
            config_dict = json.load(f)
            config = DetectorConfig.from_dict(config_dict)
    else:
        config = DetectorConfig.from_env()

    # Load event
    if args.event:
        with Path(args.event).open() as f:
            event = json.load(f)
    else:
        local_logger.info("No event file provided, using sample event")
        event = create_sample_event()

    # Use mock clients for local testing by default
    aws_clients: AWSClientInterface
    use_real_aws = os.environ.get("USE_REAL_AWS", "false").lower() == "true"

    if use_real_aws and (
        os.environ.get("AWS_PROFILE") or os.environ.get("AWS_ACCESS_KEY_ID")
    ):
        try:
            aws_clients = AWSClients()
            local_logger.info("Using real AWS clients")
        except Exception as e:
            local_logger.warning(
                f"Failed to create real AWS clients: {e}. Using mock clients."
            )
            aws_clients = MockAWSClients(args.rules, args.suppress)
    else:
        aws_clients = MockAWSClients(args.rules, args.suppress)

    # Process event
    detector = PolicyViolationDetector(config, aws_clients, args.log_level)
    result = detector.process_eventbridge_event(event)

    local_logger.info(f"Processing complete: {result}")
    return result


if __name__ == "__main__":
    main()
