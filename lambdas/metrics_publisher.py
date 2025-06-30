#!/usr/bin/env python3
"""Metrics Publisher Lambda Handler.

This Lambda function receives IAM policy violation events from EventBridge
and publishes custom metrics to CloudWatch for monitoring and alerting.
"""

import json
import logging
import os
from datetime import datetime
from typing import Any

import boto3
from violation_event import ViolationEvent


def setup_logging(level: str = "INFO") -> logging.Logger:
    """Set up logging configuration."""
    logger = logging.getLogger(__name__)
    if not logger.handlers:
        handler = logging.StreamHandler()
        formatter = logging.Formatter(
            "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
    logger.setLevel(getattr(logging, level.upper()))
    return logger


class MetricsPublisher:
    """Publishes IAM violation metrics to CloudWatch."""

    def __init__(
        self, namespace: str = "IAM/PolicyGuard", aws_clients: Any = None
    ) -> None:
        """Initialize metrics publisher.

        Args:
            namespace: CloudWatch namespace for metrics
            aws_clients: Optional AWS clients (for dependency injection)
        """
        self.namespace = namespace
        self.logger = setup_logging()

        if aws_clients:
            self.cloudwatch = aws_clients
        else:
            self.cloudwatch = boto3.client("cloudwatch")

    def publish_violation_metrics(self, violation_event: ViolationEvent) -> bool:
        """Publish violation metrics to CloudWatch.

        Args:
            violation_event: Violation event from EventBridge

        Returns:
            bool: True if metrics published successfully
        """
        try:
            # Prepare metric data
            metric_data = self._build_metric_data(violation_event)

            # Publish to CloudWatch
            self.cloudwatch.put_metric_data(
                Namespace=self.namespace, MetricData=metric_data
            )

            self.logger.info(
                f"Published {len(metric_data)} metrics for violation: "
                f"{violation_event.get_rule_name()}"
            )
            return True

        except Exception as e:
            self.logger.error(f"Failed to publish metrics: {e!s}", exc_info=True)
            return False

    def _build_metric_data(
        self, violation_event: ViolationEvent
    ) -> list[dict[str, Any]]:
        """Build CloudWatch metric data from violation event.

        Args:
            violation_event: Violation event to extract metrics from

        Returns:
            List of CloudWatch metric data points
        """
        violation = violation_event.violation
        original_event = violation_event.original_event
        user_identity = violation_event.get_user_identity()

        # Parse timestamp
        timestamp = datetime.fromisoformat(
            violation_event.timestamp.replace("Z", "+00:00")
        )

        metric_data = []

        # 1. Overall violation count
        metric_data.append(
            {
                "MetricName": "ViolationCount",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {
                        "Name": "Rule",
                        "Value": violation.get("rule_name", "Unknown"),
                    },
                    {
                        "Name": "Severity",
                        "Value": violation.get("severity", "UNKNOWN"),
                    },
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # Simplified metric for dashboarding: only Severity dimension
        metric_data.append(
            {
                "MetricName": "ViolationSeverityCount",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {
                        "Name": "Severity",
                        "Value": violation.get("severity", "UNKNOWN"),
                    },
                ],
            }
        )

        # 2. Severity distribution
        severity = violation.get("severity", "UNKNOWN")
        metric_data.append(
            {
                "MetricName": f"Violations{severity}",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "Severity", "Value": severity},
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # 3. Event type metrics
        event_name = original_event.get("eventName", "Unknown")
        metric_data.append(
            {
                "MetricName": "ViolationsByEventType",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "EventName", "Value": event_name},
                    {
                        "Name": "EventSource",
                        "Value": original_event.get("eventSource", "unknown"),
                    },
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # 4. User type metrics
        user_type = user_identity.get("type", "Unknown")
        metric_data.append(
            {
                "MetricName": "ViolationsByUserType",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "UserType", "Value": user_type},
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # 5. Risk score metrics (if available)
        risk_score = violation.get("risk_score")
        if risk_score is not None:
            metric_data.append(
                {
                    "MetricName": "RiskScore",
                    "Value": float(risk_score),
                    "Unit": "None",
                    "Timestamp": timestamp,
                    "Dimensions": [
                        {
                            "Name": "Rule",
                            "Value": violation.get("rule_name", "Unknown"),
                        },
                        {"Name": "Severity", "Value": severity},
                        {
                            "Name": "Region",
                            "Value": original_event.get("awsRegion", "unknown"),
                        },
                    ],
                }
            )

        # 6. Account-level metrics
        account_id = user_identity.get("accountId", "unknown")
        metric_data.append(
            {
                "MetricName": "ViolationsByAccount",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "AccountId", "Value": account_id},
                    {"Name": "Severity", "Value": severity},
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # 7. Source IP patterns (for security analysis)
        source_ip = original_event.get("sourceIPAddress", "unknown")
        # Anonymize IP for privacy (keep first 3 octets for IPv4)
        if "." in source_ip and len(source_ip.split(".")) == 4:
            ip_parts = source_ip.split(".")
            anonymized_ip = f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.xxx"
        else:
            anonymized_ip = "unknown"

        metric_data.append(
            {
                "MetricName": "ViolationsBySourcePattern",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "SourcePattern", "Value": anonymized_ip},
                    {"Name": "Severity", "Value": severity},
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        # 8. Category metrics
        category = violation.get("category", "Unknown")
        metric_data.append(
            {
                "MetricName": "ViolationsByCategory",
                "Value": 1,
                "Unit": "Count",
                "Timestamp": timestamp,
                "Dimensions": [
                    {"Name": "Category", "Value": category},
                    {"Name": "Severity", "Value": severity},
                    {
                        "Name": "Region",
                        "Value": original_event.get("awsRegion", "unknown"),
                    },
                ],
            }
        )

        return metric_data


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for metrics publishing.

    Args:
        event: EventBridge event containing violation details
        context: Lambda context

    Returns:
        Dict containing processing results
    """
    # Set log level based on DEBUG environment variable
    log_level = (
        "DEBUG" if os.environ.get("DEBUG", "false").lower() == "true" else "INFO"
    )
    logger = setup_logging(log_level)

    try:
        # Skip non-violation events (e.g., health checks or unrelated events)
        if not event.get("detail") or "violation" not in event["detail"]:
            logger.debug(
                "Skipping event without violation payload: %s",
                json.dumps(event),
            )
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "Event skipped - no violation field"}),
            }

        # Get CloudWatch namespace from environment
        namespace = os.environ.get("CLOUDWATCH_NAMESPACE", "IAM/PolicyGuard")

        # Parse violation event
        violation_event = ViolationEvent.from_eventbridge_event(event)

        logger.info(
            "Publishing metrics for violation: %s (Severity: %s)",
            violation_event.get_rule_name(),
            violation_event.get_severity(),
        )

        # Create publisher and send metrics
        publisher = MetricsPublisher(namespace)
        success = publisher.publish_violation_metrics(violation_event)

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "Metrics published successfully",
                        "eventId": violation_event.event_id,
                        "correlationId": violation_event.correlation_id,
                        "namespace": namespace,
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to publish metrics",
                        "eventId": violation_event.event_id,
                        "correlationId": violation_event.correlation_id,
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in metrics publisher handler: {e!s}", exc_info=True)
        return {"statusCode": 500, "body": json.dumps({"error": str(e)})}


# Mock for testing
class MockMetricsPublisher(MetricsPublisher):
    """Mock metrics publisher for testing."""

    def __init__(
        self, namespace: str = "IAM/PolicyGuard", aws_clients: Any = None
    ) -> None:
        """Initialize mock publisher."""
        self.namespace = namespace
        self.logger = setup_logging()
        self.published_metrics: list[dict[str, Any]] = []

    def publish_violation_metrics(self, violation_event: ViolationEvent) -> bool:
        """Mock publish - store metrics for testing."""
        metric_data = self._build_metric_data(violation_event)

        self.published_metrics.append(
            {"namespace": self.namespace, "metric_data": metric_data}
        )

        self.logger.info(
            f"MOCK: Published {len(metric_data)} metrics for "
            f"{violation_event.get_rule_name()}"
        )
        return True


if __name__ == "__main__":
    # Local testing
    sample_event = {
        "source": "iam.policy.monitor",
        "detail-type": "IAM Policy Violation",
        "detail": {
            "eventId": "test-event-id",
            "timestamp": "2024-01-01T12:00:00Z",
            "correlationId": "test-correlation-id",
            "violation": {
                "rule_name": "AdminPolicyDetected",
                "severity": "CRITICAL",
                "description": "Policy with Administrator access detected",
                "category": "Policy",
                "risk_score": 9.8,
            },
            "originalEvent": {
                "eventName": "CreateRole",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2024-01-01T12:00:00Z",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.45",
                "userAgent": "aws-cli/2.0.0",
                "requestID": "12345678-1234-1234-1234-123456789012",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAIOSFODNN7EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/admin-user",
                    "accountId": "123456789012",
                    "userName": "admin-user",
                },
                "requestParameters": {
                    "roleName": "AdminRole",
                    "assumeRolePolicyDocument": (
                        "%7B%22Version%22%3A%222012-10-17%22%7D"
                    ),
                },
                "resources": [
                    {
                        "type": "AWS::IAM::Role",
                        "ARN": "arn:aws:iam::123456789012:role/AdminRole",
                    }
                ],
            },
        },
    }

    # Test with mock
    os.environ["CLOUDWATCH_NAMESPACE"] = "IAM/PolicyGuard"
    result = lambda_handler(sample_event, None)
    print(f"Result: {result}")
