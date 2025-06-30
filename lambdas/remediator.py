#!/usr/bin/env python3
"""IAM Policy Violation Remediator.

This module can be run both as an AWS Lambda function and locally for
testing. The main business logic is separated from the Lambda handler
for better testability.
"""

import argparse
import fnmatch
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from io import StringIO
from pathlib import Path
from typing import Any

import boto3


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


# Set up global logger with DEBUG support
log_level = "DEBUG" if os.environ.get("DEBUG", "false").lower() == "true" else "INFO"
logger = setup_logging(log_level)


@dataclass
class RemediationConfig:
    """Configuration for the remediator."""

    rules_bucket: str
    sns_topic_arn: str | None = None
    allowed_actions: list[str] | None = None
    dry_run: bool = False
    eventbridge_bus_name: str | None = None

    def __post_init__(self) -> None:
        """Initialize allowed_actions if None."""
        if self.allowed_actions is None:
            self.allowed_actions = []

    @classmethod
    def from_env(cls) -> "RemediationConfig":
        """Create config from environment variables."""
        allowed_actions_str = os.environ.get("ALLOWED_ACTIONS", "[]")
        try:
            allowed_actions = json.loads(allowed_actions_str)
        except json.JSONDecodeError:
            allowed_actions = []

        dry_run_str = os.environ.get("DRY_RUN", "false").lower()
        dry_run = dry_run_str in ("true", "1", "yes", "on")

        return cls(
            rules_bucket=os.environ.get("RULES_BUCKET", ""),
            sns_topic_arn=os.environ.get("SNS_TOPIC_ARN"),
            allowed_actions=allowed_actions,
            dry_run=dry_run,
            eventbridge_bus_name=os.environ.get("EVENTBRIDGE_BUS_NAME"),
        )

    @classmethod
    def from_dict(cls, config_dict: dict) -> "RemediationConfig":
        """Create config from dictionary."""
        return cls(**config_dict)


class AWSClientInterface(ABC):
    """Abstract interface for AWS clients to enable mocking.

    This interface defines the methods that must be implemented by the AWS
    client wrapper classes. It allows for mocking of AWS client methods during
    testing.
    """

    @abstractmethod
    def detach_user_policy(self, **kwargs: Any) -> Any:
        """Detach a policy from a user."""
        pass

    @abstractmethod
    def detach_role_policy(self, **kwargs: Any) -> Any:
        """Detach a policy from a role."""
        pass

    @abstractmethod
    def delete_policy(self, **kwargs: Any) -> Any:
        """Delete a policy."""
        pass

    @abstractmethod
    def delete_user_policy(self, **kwargs: Any) -> Any:
        """Delete a user policy."""
        pass

    @abstractmethod
    def delete_role_policy(self, **kwargs: Any) -> Any:
        """Delete a role policy."""
        pass

    @abstractmethod
    def get_policy(self, **kwargs: Any) -> Any:
        """Get a policy."""
        pass

    @abstractmethod
    def list_policy_versions(self, **kwargs: Any) -> Any:
        """List policy versions."""
        pass

    @abstractmethod
    def delete_policy_version(self, **kwargs: Any) -> Any:
        """Delete a policy version."""
        pass

    @abstractmethod
    def get_object(self, **kwargs: Any) -> Any:
        """Get an object from S3."""
        pass

    @abstractmethod
    def put_object(self, **kwargs: Any) -> Any:
        """Put an object to S3."""
        pass

    @abstractmethod
    def publish(self, **kwargs: Any) -> Any:
        """Publish a message to SNS."""
        pass

    @abstractmethod
    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data to CloudWatch."""
        pass

    @abstractmethod
    def detach_group_policy(self, **kwargs: Any) -> Any:
        """Detach group policy."""
        pass

    @abstractmethod
    def list_entities_for_policy(self, **kwargs: Any) -> Any:
        """List entities attached to a policy."""
        pass


class AWSClients(AWSClientInterface):
    """Real AWS clients wrapper.

    This class provides a wrapper around the AWS clients for the remediator.
    It allows for mocking of AWS client methods during testing.
    """

    def __init__(self, region: str | None = None) -> None:
        """Initialize AWS clients."""
        self.iam = boto3.client("iam", region_name=region)
        self.s3 = boto3.client("s3", region_name=region)
        self.sns = boto3.client("sns", region_name=region)
        self.cloudwatch = boto3.client("cloudwatch", region_name=region)

    def detach_user_policy(self, **kwargs: Any) -> Any:
        """Detach a policy from a user."""
        try:
            return self.iam.detach_user_policy(**kwargs)
        except Exception as e:
            # If policy already detached/missing, still consider success
            if "NoSuchEntity" not in str(e):
                raise

    def detach_role_policy(self, **kwargs: Any) -> Any:
        """Detach a policy from a role."""
        try:
            return self.iam.detach_role_policy(**kwargs)
        except Exception as e:
            if "NoSuchEntity" not in str(e):
                raise

    def delete_policy(self, **kwargs: Any) -> Any:
        """Delete a policy."""
        return self.iam.delete_policy(**kwargs)

    def delete_user_policy(self, **kwargs: Any) -> Any:
        """Delete a user policy."""
        return self.iam.delete_user_policy(**kwargs)

    def delete_role_policy(self, **kwargs: Any) -> Any:
        """Delete a role policy."""
        return self.iam.delete_role_policy(**kwargs)

    def get_policy(self, **kwargs: Any) -> Any:
        """Get a policy."""
        return self.iam.get_policy(**kwargs)

    def list_policy_versions(self, **kwargs: Any) -> Any:
        """List policy versions."""
        return self.iam.list_policy_versions(**kwargs)

    def delete_policy_version(self, **kwargs: Any) -> Any:
        """Delete a policy version."""
        return self.iam.delete_policy_version(**kwargs)

    def get_object(self, **kwargs: Any) -> Any:
        """Get an object from S3."""
        return self.s3.get_object(**kwargs)

    def put_object(self, **kwargs: Any) -> Any:
        """Put an object to S3."""
        return self.s3.put_object(**kwargs)

    def publish(self, **kwargs: Any) -> Any:
        """Publish a message to SNS."""
        return self.sns.publish(**kwargs)

    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data to CloudWatch."""
        return self.cloudwatch.put_metric_data(**kwargs)

    def detach_group_policy(self, **kwargs: Any) -> Any:
        """Detach group policy."""
        return self.iam.detach_group_policy(**kwargs)

    def list_entities_for_policy(self, **kwargs: Any) -> Any:
        """List entities attached to a policy."""
        return self.iam.list_entities_for_policy(**kwargs)


class RemediationResult:
    """Result of a remediation action.

    This class stores the result of a remediation action, including the
    success status, details, and error message.
    """

    def __init__(
        self,
        success: bool,
        details: dict[str, Any],
        error: str | None = None,
    ):
        """Initialize the RemediationResult."""
        self.success = success
        self.details = details
        self.error = error
        self.timestamp = datetime.now(timezone.utc).isoformat()


class PolicyRemediator:
    """Main business logic for IAM policy remediation.

    This class contains the main business logic for remediating IAM policy
    violations. It processes SQS events containing remediation messages,
    validates the safety of the remediation actions, and performs the actual
    remediation actions.
    """

    def __init__(self, config: RemediationConfig, aws_clients: AWSClientInterface):
        """Initialize the PolicyRemediator."""
        self.config = config
        self.aws_clients = aws_clients
        # Set up logger with DEBUG support
        log_level = (
            "DEBUG" if os.environ.get("DEBUG", "false").lower() == "true" else "INFO"
        )
        self.logger = setup_logging(log_level)

        # Load remediator configuration from S3
        self.remediator_config = self._load_config_from_s3("remediator-config.json")

        # Initialize EventBridge publisher if configured
        self.event_publisher = None
        if self.config.eventbridge_bus_name:
            try:
                self.event_publisher = EventBridgePublisher(
                    self.config.eventbridge_bus_name
                )
                self.logger.info("EventBridge publisher initialized")
            except Exception as e:
                self.logger.error(f"Failed to initialize EventBridge publisher: {e!s}")
                self.event_publisher = None

    def process_sqs_event(self, event: dict) -> dict[str, Any]:
        """Process SQS event containing remediation messages.

        Args:
            event: The SQS event to process.

        Returns:
            Dict[str, Any]: The result of the event processing.
        """
        results = []

        for record in event.get("Records", []):
            if record.get("eventSource") == "aws:sqs":
                try:
                    message_body = json.loads(record["body"])
                    result = self.process_remediation_message(message_body)
                    results.append(result)
                except Exception as e:
                    self.logger.error(
                        f"Error processing SQS record: {e!s}", exc_info=True
                    )
                    results.append(RemediationResult(False, {}, str(e)))

        return {
            "statusCode": 200 if all(r.success for r in results) else 500,
            "body": f"Processed {len(results)} messages",
            "results": [
                {"success": r.success, "details": r.details, "error": r.error}
                for r in results
            ],
        }

    def process_remediation_message(self, message: dict) -> RemediationResult:
        """Process individual remediation message.

        Args:
            message: The remediation message to process.

        Returns:
            RemediationResult: The result of the remediation action.
        """
        try:
            violation = message.get("violation", {})
            event = message.get("event", {})
            remediation_action = message.get("remediation_action", "")

            self.logger.info(
                f"Processing remediation for rule: {violation.get('rule_name')}"
            )

            # Validate allowed actions
            allowed_actions = self.remediator_config.get("allowed_actions", [])
            if allowed_actions and remediation_action not in allowed_actions:
                self.logger.warning(
                    f"Remediation action '{remediation_action}' not allowed"
                )
                self._send_metric("RemediationSkipped", 1)
                return RemediationResult(False, {"reason": "action_not_allowed"})

            # Validate safety
            if not self._validate_remediation_safety(event, remediation_action):
                self.logger.warning("Remediation skipped for safety reasons")
                self._send_metric("RemediationSkipped", 1)
                return RemediationResult(False, {"reason": "safety_check_failed"})

            # Perform remediation
            dry_run = self.remediator_config.get("dry_run", True)
            if dry_run:
                self.logger.info(f"DRY RUN: Would perform {remediation_action}")
                result = RemediationResult(
                    True, {"action": remediation_action, "dry_run": True}
                )
            else:
                result = self._perform_remediation(remediation_action, event)

            # Send metrics
            metric_name = (
                "RemediationSuccess" if result.success else "RemediationFailure"
            )
            self._send_metric(metric_name, 1)

            # Also publish a RemediationAction metric grouped by action for dashboarding
            if result.success and remediation_action:
                self._send_metric(
                    "RemediationAction", 1, {"Action": remediation_action}
                )

            # Log result
            self._log_remediation_result(violation, event, remediation_action, result)

            # Send notification
            self._send_notification(violation, remediation_action, result)

            # Send remediation status event to EventBridge (similar to detector alerts)
            if self.event_publisher:
                try:
                    self.event_publisher.publish_remediation_event(
                        violation, event, remediation_action, result
                    )
                except Exception as e:
                    self.logger.error(f"Failed to publish remediation event: {e!s}")

            return result

        except Exception as e:
            self.logger.error(
                f"Error processing remediation message: {e!s}",
                exc_info=True,
            )
            self._send_metric("RemediationFailure", 1)
            return RemediationResult(False, {}, str(e))

    def _determine_remediation_action(self, event_name: str) -> str:
        """Determines the remediation action based on the event name."""
        if event_name in ["AttachUserPolicy", "AttachRolePolicy"]:
            return "detach_policy"
        if event_name in ["PutUserPolicy", "PutRolePolicy"]:
            return "delete_inline_policy"
        if event_name == "CreatePolicy":
            return "delete_policy"
        self.logger.warning(f"No remediation action defined for event '{event_name}'")
        return ""

    def _load_config_from_s3(self, key: str) -> dict[str, Any]:
        """Load configuration from S3 bucket.

        Args:
            key: The key of the configuration file in S3.

        Returns:
            Dict[str, Any]: The loaded configuration.
        """
        try:
            if not self.config.rules_bucket:
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
            config = json.loads(content)
            return config if isinstance(config, dict) else {}
        except Exception as e:
            self.logger.error(f"Error loading config {key}: {e!s}")
            # Return safe defaults if config loading fails
            return {
                "dry_run": True,
                "allowed_actions": [],
                "safety_checks": {},
                "notifications": {},
            }

    def _perform_remediation(
        self, action: str, event: dict[str, Any]
    ) -> RemediationResult:
        """Perform the actual remediation action.

        Args:
            action: The remediation action to perform.
            event: The event that triggered the remediation.

        Returns:
            RemediationResult: The result of the remediation action.
        """
        action_map = {
            "detach_policy": self._detach_policy,
            "delete_policy": self._delete_policy,
            "delete_inline_policy": self._delete_inline_policy,
            "log_only": lambda _e: RemediationResult(True, {"action": "logged"}),
        }

        if action not in action_map:
            return RemediationResult(False, {}, f"Unknown action: {action}")

        return action_map[action](event)

    def _detach_policy(self, event: dict[str, Any]) -> RemediationResult:
        """Detach policy from user or role.

        Args:
            event: The event that triggered the remediation.

        Returns:
            RemediationResult: The result of the remediation action.
        """
        try:
            event_name = event.get("eventName", "")
            request_parameters = event.get("requestParameters", {})

            if event_name == "AttachUserPolicy":
                user_name = request_parameters.get("userName")
                policy_arn = request_parameters.get("policyArn")

                if user_name and policy_arn:
                    try:
                        self.aws_clients.detach_user_policy(
                            UserName=user_name, PolicyArn=policy_arn
                        )
                    except Exception as e:
                        # If policy already detached/missing, still consider success
                        if "NoSuchEntity" not in str(e):
                            raise
                    return RemediationResult(
                        True,
                        {
                            "action": "detach_user_policy",
                            "user_name": user_name,
                            "policy_arn": policy_arn,
                        },
                    )

            elif event_name == "AttachRolePolicy":
                role_name = request_parameters.get("roleName")
                policy_arn = request_parameters.get("policyArn")

                if role_name and policy_arn:
                    try:
                        self.aws_clients.detach_role_policy(
                            RoleName=role_name, PolicyArn=policy_arn
                        )
                    except Exception as e:
                        if "NoSuchEntity" not in str(e):
                            raise
                    return RemediationResult(
                        True,
                        {
                            "action": "detach_role_policy",
                            "role_name": role_name,
                            "policy_arn": policy_arn,
                        },
                    )

            return RemediationResult(
                False, {}, "Unable to determine detachment parameters"
            )

        except Exception as e:
            self.logger.error(f"Error detaching policy: {e!s}")
            return RemediationResult(False, {}, str(e))

    def _delete_policy(self, event: dict[str, Any]) -> RemediationResult:
        """Delete IAM policy.

        Args:
            event: The event that triggered the remediation.

        Returns:
            RemediationResult: The result of the remediation action.
        """
        try:
            request_parameters = event.get("requestParameters", {})
            policy_name = request_parameters.get("policyName")

            if not policy_name:
                return RemediationResult(False, {}, "Policy name not found in event")

            account_id = event.get("recipientAccountId", "")
            policy_arn = f"arn:aws:iam::{account_id}:policy/{policy_name}"

            try:
                # Get policy details
                policy_response = self.aws_clients.get_policy(PolicyArn=policy_arn)
                if policy_response is None:
                    raise ValueError(f"Failed to get policy {policy_arn}")
                policy = policy_response["Policy"]

                # Delete all non-default policy versions first
                versions_response = self.aws_clients.list_policy_versions(
                    PolicyArn=policy_arn
                )
                if versions_response and "Versions" in versions_response:
                    for version in versions_response["Versions"]:
                        if not version["IsDefaultVersion"]:
                            self.aws_clients.delete_policy_version(
                                PolicyArn=policy_arn,
                                VersionId=version["VersionId"],
                            )

                # Detach the policy from all entities before deletion
                try:
                    entities_response = self.aws_clients.list_entities_for_policy(
                        PolicyArn=policy_arn
                    )
                    if entities_response:
                        # Detach from users
                        for user in entities_response.get("PolicyUsers", []):
                            user_name = user.get("UserName")
                            if user_name:
                                self.aws_clients.detach_user_policy(
                                    UserName=user_name,
                                    PolicyArn=policy_arn,
                                )

                        # Detach from roles
                        for role in entities_response.get("PolicyRoles", []):
                            role_name = role.get("RoleName")
                            if role_name:
                                self.aws_clients.detach_role_policy(
                                    RoleName=role_name,
                                    PolicyArn=policy_arn,
                                )

                        # Detach from groups
                        for group in entities_response.get("PolicyGroups", []):
                            group_name = group.get("GroupName")
                            if group_name:
                                self.aws_clients.detach_group_policy(
                                    GroupName=group_name,
                                    PolicyArn=policy_arn,
                                )
                except Exception as det_e:
                    # Log but proceed,  deletion will fail if still attached
                    self.logger.warning(
                        f"Error detaching entities from policy {policy_arn}: {det_e!s}"
                    )

                # Delete the policy
                self.aws_clients.delete_policy(PolicyArn=policy_arn)

                return RemediationResult(
                    True,
                    {
                        "action": "delete_policy",
                        "policy_name": policy_name,
                        "policy_arn": policy_arn,
                        "attachment_count": policy.get("AttachmentCount", 0),
                    },
                )

            except Exception as e:
                if "NoSuchEntity" in str(e):
                    return RemediationResult(
                        False, {}, f"Policy {policy_name} not found"
                    )
                raise

        except Exception as e:
            self.logger.error(f"Error deleting policy: {e!s}")
            return RemediationResult(False, {}, str(e))

    def _delete_inline_policy(self, event: dict[str, Any]) -> RemediationResult:
        """Delete inline policy from user or role.

        Args:
            event: The event that triggered the remediation.

        Returns:
            RemediationResult: The result of the remediation action.
        """
        try:
            event_name = event.get("eventName", "")
            request_parameters = event.get("requestParameters", {})

            if event_name == "PutUserPolicy":
                user_name = request_parameters.get("userName")
                policy_name = request_parameters.get("policyName")

                if user_name and policy_name:
                    try:
                        self.aws_clients.delete_user_policy(
                            UserName=user_name, PolicyName=policy_name
                        )
                    except Exception as e:
                        if "NoSuchEntity" not in str(e):
                            raise
                    return RemediationResult(
                        True,
                        {
                            "action": "delete_user_policy",
                            "user_name": user_name,
                            "policy_name": policy_name,
                            "note": "Already deleted or user missing",
                        },
                    )

            elif event_name == "PutRolePolicy":
                role_name = request_parameters.get("roleName")
                policy_name = request_parameters.get("policyName")

                if role_name and policy_name:
                    try:
                        self.aws_clients.delete_role_policy(
                            RoleName=role_name, PolicyName=policy_name
                        )
                    except Exception as e:
                        if "NoSuchEntity" not in str(e):
                            raise
                    return RemediationResult(
                        True,
                        {
                            "action": "delete_role_policy",
                            "role_name": role_name,
                            "policy_name": policy_name,
                            "note": "Already deleted or role missing",
                        },
                    )

            return RemediationResult(
                False, {}, "Unable to determine inline policy parameters"
            )

        except Exception as e:
            self.logger.error(f"Error deleting inline policy: {e!s}")
            return RemediationResult(False, {}, str(e))

    def _log_remediation_result(
        self,
        violation: dict[str, Any],
        event: dict[str, Any],
        action: str,
        result: RemediationResult,
    ) -> None:
        """Log remediation result to S3 for audit trail.

        Args:
            violation: The violation that triggered the remediation.
            event: The event that triggered the remediation.
            action: The remediation action performed.
            result: The result of the remediation action.
        """
        if not self.config.rules_bucket:
            self.logger.warning("No rules bucket configured, skipping S3 logging")
            return

        try:
            now = datetime.now(timezone.utc)
            rule_name = violation.get("rule_name", "unknown")
            timestamp_str = now.strftime("%Y%m%d_%H%M%S")

            s3_key = (
                f"remediation/year={now.year}/"
                f"month={now.month:02d}/day={now.day:02d}/"
                f"{timestamp_str}_{rule_name}_remediation.json"
            )

            remediation_log = {
                "timestamp": result.timestamp,
                "violation": violation,
                "original_event": {
                    "event_name": event.get("eventName"),
                    "event_time": event.get("eventTime"),
                    "user_identity": event.get("userIdentity", {}),
                    "source_ip_address": event.get("sourceIPAddress"),
                    "user_agent": event.get("userAgent"),
                    "aws_region": event.get("awsRegion"),
                    "request_parameters": event.get("requestParameters", {}),
                },
                "remediation_action": action,
                "success": result.success,
                "remediation_details": result.details,
                "error": result.error,
                "originalEventId": violation.get("event_id")
                or violation.get("eventId"),
            }

            self.aws_clients.put_object(
                Bucket=self.config.rules_bucket,
                Key=s3_key,
                Body=json.dumps(remediation_log, default=str),
                ContentType="application/json",
            )
            self.logger.info(f"Remediation result logged to S3: {s3_key}")

        except Exception as e:
            self.logger.error(f"Error logging remediation result to S3: {e!s}")

    def _send_notification(
        self, violation: dict[str, Any], action: str, result: RemediationResult
    ) -> None:
        """Send notification about remediation result.

        Args:
            violation: The violation that triggered the remediation.
            action: The remediation action performed.
            result: The result of the remediation action.
        """
        if not self.config.sns_topic_arn:
            return

        try:
            status = "SUCCESS" if result.success else "FAILED"
            rule_name = violation.get("rule_name", "Unknown")
            subject = f"IAM Policy Remediation {status}: {rule_name}"

            message = f"""
IAM Policy Remediation Report

Rule: {violation.get("rule_name", "Unknown")}
Violation Severity: {violation.get("severity", "Unknown")}
Remediation Action: {action}
Status: {status}
Timestamp: {result.timestamp}

Remediation Details:
{json.dumps(result.details, indent=2)}

{"Error: " + result.error if result.error else ""}

Original Violation:
- Description: {violation.get("description", "N/A")}
- Event: {violation.get("event_name", "N/A")}
- Timestamp: {violation.get("timestamp", "N/A")}
"""

            self.aws_clients.publish(
                TopicArn=self.config.sns_topic_arn,
                Subject=subject,
                Message=message,
            )
            self.logger.info("Remediation notification sent")

        except Exception as e:
            self.logger.error(f"Error sending remediation notification: {e!s}")

    def _send_metric(
        self,
        metric_name: str,
        value: float,
        dimensions: dict[str, str] | None = None,
    ) -> None:
        """Send custom metrics to CloudWatch.

        Args:
            metric_name: The name of the metric to send.
            value: The value of the metric to send.
            dimensions: Optional dimensions for the metric.
        """
        try:
            metric = {
                "MetricName": metric_name,
                "Value": value,
                "Unit": "Count",
                "Timestamp": datetime.now(timezone.utc),
            }
            if dimensions:
                metric["Dimensions"] = [
                    {"Name": k, "Value": v} for k, v in dimensions.items()
                ]

            self.aws_clients.put_metric_data(
                Namespace="IAMPolicyMonitor",
                MetricData=[metric],
            )
            dims_str = f" dimensions={dimensions}" if dimensions else ""
            self.logger.info(f"Metric sent: {metric_name} = {value}{dims_str}")

        except Exception as e:
            self.logger.error(f"Error sending metric {metric_name}: {e!s}")

    def _validate_remediation_safety(
        self, event: dict[str, Any], remediation_action: str
    ) -> bool:
        """
        Validates if the remediation action is safe to perform based on configuration.
        """
        # The `event` parameter here is the CloudTrail-like event dict (not the full message)
        # User identity can live under event.userIdentity
        user_identity = event.get("userIdentity", {})
        principal_name = user_identity.get("userName") or user_identity.get(
            "principalId", ""
        )

        # Fail fast for AWS root user
        user_type = user_identity.get("type")
        if user_type == "Root":
            self.logger.warning(
                "SAFETY CHECK FAILED: Root user action - skipping remediation"
            )
            return False

        # Extract request parameters for further checks
        request_parameters = event.get("requestParameters", {})

        # Get safety check config from the loaded remediator_config dictionary
        safety_config = self.remediator_config.get("safety_checks", {})
        exclude_patterns = safety_config.get("exclude_patterns", [])
        protected_policies = self.remediator_config.get("protected_policies", [])

        # 1. Check if the principal is excluded
        if principal_name:
            for pattern in exclude_patterns:
                if fnmatch.fnmatch(principal_name, pattern):
                    self.logger.warning(
                        f"SAFETY CHECK FAILED: Principal '{principal_name}' matches "
                        f"exclude pattern '{pattern}'. Skipping remediation."
                    )
                    return False

        # 2. Check if the policy is protected (for detach/delete actions)
        if remediation_action in ["detach_policy", "delete_policy"]:
            policy_arn = request_parameters.get("policyArn")
            if policy_arn:
                for pattern in protected_policies:
                    if fnmatch.fnmatch(policy_arn, pattern):
                        self.logger.warning(
                            f"SAFETY CHECK FAILED: Policy ARN '{policy_arn}' matches "
                            f"protected pattern '{pattern}'. Skipping remediation."
                        )
                        return False

        # 3. Block critical AWS managed role names explicitly
        role_name = (
            request_parameters.get("roleName")
            if isinstance(request_parameters, dict)
            else None
        )
        if role_name and role_name in ["OrganizationAccountAccessRole"]:
            self.logger.warning(
                "SAFETY CHECK FAILED: Critical role name detected - skipping remediation"
            )
            return False

        self.logger.info("Remediation safety checks passed.")
        return True


class EventBridgePublisher:
    """Publishes remediation events to EventBridge."""

    def __init__(self, bus_name: str) -> None:
        """Initialize EventBridge publisher.

        Args:
            bus_name: EventBridge bus name for publishing events
        """
        self.bus_name = bus_name
        self.eventbridge = boto3.client("events")
        self.logger = setup_logging()

    def publish_remediation_event(
        self,
        violation: dict[str, Any],
        original_event: dict[str, Any],
        remediation_action: str,
        result: "RemediationResult",
    ) -> bool:
        """Publish remediation status event to EventBridge.

        Args:
            violation: Original violation that triggered remediation
            original_event: Original CloudTrail event
            remediation_action: Action that was attempted
            result: Result of the remediation action

        Returns:
            bool: True if published successfully
        """
        try:
            status = "SUCCESS" if result.success else "FAILED"

            # Create remediation event in similar format to violation alerts
            event_detail = {
                "eventId": original_event.get("eventId") or str(uuid.uuid4()),
                "timestamp": result.timestamp,
                "correlationId": original_event.get("correlationId")
                or violation.get("correlation_id")
                or str(uuid.uuid4()),
                "remediation": {
                    "rule_name": violation.get("rule_name", "Unknown"),
                    "severity": violation.get("severity", "Unknown"),
                    "action": remediation_action,
                    "status": status,
                    "description": f"Remediation {status.lower()} for {violation.get('rule_name', 'Unknown')}",
                    "details": result.details,
                    "error": result.error if result.error else None,
                },
                "originalEvent": original_event,
                "originalViolation": violation,
                "originalEventId": violation.get("event_id")
                or violation.get("eventId"),
            }

            # Publish to EventBridge
            entry = {
                "Source": "iam.policy.remediator",
                "DetailType": "IAM Policy Remediation Status",
                "Detail": json.dumps(event_detail),
                "EventBusName": self.bus_name,
            }

            response = self.eventbridge.put_events(Entries=[entry])

            if response.get("FailedEntryCount", 0) == 0:
                self.logger.info(f"Remediation {status} event published to EventBridge")
                return True
            else:
                self.logger.error(f"Failed to publish remediation event: {response}")
                return False

        except Exception as e:
            self.logger.error(f"Error publishing remediation event: {e!s}")
            return False


# Lambda handler function
def lambda_handler(event: dict[str, Any], _context: Any) -> dict[str, Any]:
    """AWS Lambda handler - thin wrapper around business logic.

    Args:
        event: The event to process.
        _context: The context of the event (unused).

    Returns:
        Dict[str, Any]: The result of the event processing.
    """
    try:
        config = RemediationConfig.from_env()
        aws_clients = AWSClients()
        remediator = PolicyRemediator(config, aws_clients)

        return remediator.process_sqs_event(event)

    except Exception as e:
        logger.error(f"Error in lambda_handler: {e!s}", exc_info=True)
        return {"statusCode": 500, "body": f"Error: {e!s}"}


# Local execution support
def create_sample_event() -> dict:
    """Create a sample SQS event for testing.

    Returns:
        Dict: A sample SQS event.
    """
    policy_arn = "arn:aws:iam::123456789012:policy/test-policy"
    user_arn = "arn:aws:iam::123456789012:user/test-user"

    return {
        "Records": [
            {
                "eventSource": "aws:sqs",
                "body": json.dumps(
                    {
                        "violation": {
                            "rule_name": "test_rule",
                            "severity": "HIGH",
                            "description": "Test violation",
                            "event_name": "AttachUserPolicy",
                        },
                        "event": {
                            "eventName": "AttachUserPolicy",
                            "userIdentity": {
                                "type": "IAMUser",
                                "userName": "test-user",
                                "arn": user_arn,
                            },
                            "requestParameters": {
                                "userName": "test-user",
                                "policyArn": policy_arn,
                            },
                            "recipientAccountId": "123456789012",
                        },
                        "remediation_action": "detach_policy",
                    }
                ),
            }
        ]
    }


def main() -> Any:
    """Run function for local execution.

    This function is used to test the remediator locally. It can be run with
    the following command:

    python -m lambdas.remediator --event event.json --config config.json
    """
    parser = argparse.ArgumentParser(description="IAM Policy Remediator")
    parser.add_argument("--config", help="Configuration file (JSON)")
    parser.add_argument("--event", help="Event file (JSON)")
    parser.add_argument("--dry-run", action="store_true", help="Dry run mode")
    parser.add_argument("--log-level", default="INFO", help="Log level")

    args = parser.parse_args()

    # Setup logging (create local logger instead of using global)
    local_logger = setup_logging(args.log_level)

    # Load configuration
    if args.config:
        with Path(args.config).open() as f:
            config_dict = json.load(f)
            config_dict["dry_run"] = args.dry_run
            config = RemediationConfig.from_dict(config_dict)
    else:
        config = RemediationConfig.from_env()

    # Load event
    if args.event:
        with Path(args.event).open() as f:
            event = json.load(f)
    else:
        local_logger.info("No event file provided, using sample event")
        event = create_sample_event()

    # Create mock clients for local testing
    class MockAWSClients(AWSClientInterface):
        def __init__(self) -> None:
            local_logger.info("Using mock AWS clients for local testing")

        def detach_user_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: detach_user_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def detach_role_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: detach_role_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def delete_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: delete_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def delete_user_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: delete_user_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def delete_role_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: delete_role_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def get_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: get_policy({kwargs})")
            return {"Policy": {"PolicyName": "test-policy", "AttachmentCount": 1}}

        def list_policy_versions(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: list_policy_versions({kwargs})")
            return {"Versions": [{"VersionId": "v1", "IsDefaultVersion": True}]}

        def delete_policy_version(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: delete_policy_version({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def get_object(self, **kwargs: Any) -> Any:
            bucket = kwargs.get("Bucket")
            key = kwargs.get("Key")
            local_logger.info(f"MOCK: get_object from s3://{bucket}/{key}")
            # Return mock config data
            if key == "remediator-config.json":
                mock_config = '{"dry_run": true, "allowed_actions": []}'
                return {"Body": StringIO(mock_config)}
            return {"Body": StringIO("{}")}

        def put_object(self, **kwargs: Any) -> Any:
            bucket = kwargs.get("Bucket")
            key = kwargs.get("Key")
            local_logger.info(f"MOCK: put_object to s3://{bucket}/{key}")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def publish(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: publish to SNS: {kwargs.get('Subject')}")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def put_metric_data(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: put_metric_data: {kwargs}")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def detach_group_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: detach_group_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

        def list_entities_for_policy(self, **kwargs: Any) -> Any:
            local_logger.info(f"MOCK: list_entities_for_policy({kwargs})")
            return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    # Use real clients if AWS credentials are available, otherwise use mock
    aws_clients: AWSClientInterface
    try:
        aws_env_vars = os.environ.get("AWS_PROFILE") or os.environ.get(
            "AWS_ACCESS_KEY_ID"
        )
        if not config.dry_run and aws_env_vars:
            aws_clients = AWSClients()
            local_logger.info("Using real AWS clients")
        else:
            aws_clients = MockAWSClients()
    except Exception as e:
        local_logger.warning(
            f"Failed to create real AWS clients: {e}. Using mock clients."
        )
        aws_clients = MockAWSClients()

    # Process event
    remediator = PolicyRemediator(config, aws_clients)
    result = remediator.process_sqs_event(event)

    local_logger.info(f"Processing complete: {result}")
    return result


if __name__ == "__main__":
    main()
