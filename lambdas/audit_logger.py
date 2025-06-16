#!/usr/bin/env python3
"""Audit Logger Lambda Handler.

This Lambda function receives IAM policy violation events from EventBridge
and logs them to S3 for audit and compliance purposes.
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


class AuditLogger:
    """Logs IAM violations to S3 for audit purposes."""

    def __init__(
        self,
        bucket_name: str,
        key_prefix: str = "audit-logs",
        aws_clients: Any = None,
    ) -> None:
        """Initialize audit logger.

        Args:
            bucket_name: S3 bucket for audit logs
            key_prefix: S3 key prefix for organizing logs
            aws_clients: Optional AWS clients (for dependency injection)
        """
        self.bucket_name = bucket_name
        self.key_prefix = key_prefix
        self.logger = setup_logging()

        if aws_clients:
            self.s3 = aws_clients
        else:
            self.s3 = boto3.client("s3")

    def log_violation(self, violation_event: ViolationEvent) -> bool:
        """Log violation event to S3.

        Args:
            violation_event: Violation event from EventBridge

        Returns:
            bool: True if logged successfully
        """
        try:
            # Generate S3 key with hierarchical structure
            s3_key = self._generate_s3_key(violation_event)

            # Create audit record
            audit_record = self._create_audit_record(violation_event)

            # Upload to S3
            self.s3.put_object(
                Bucket=self.bucket_name,
                Key=s3_key,
                Body=json.dumps(audit_record, indent=2),
                ContentType="application/json",
                Metadata={
                    "event-id": violation_event.event_id,
                    "correlation-id": violation_event.correlation_id or "",
                    "severity": violation_event.get_severity(),
                    "rule-name": violation_event.get_rule_name(),
                },
            )

            self.logger.info(f"Audit log written to s3://{self.bucket_name}/{s3_key}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to write audit log: {e!s}", exc_info=True)
            return False

    def _generate_s3_key(self, violation_event: ViolationEvent) -> str:
        """Generate hierarchical S3 key for audit log.

        Format: {prefix}/year=YYYY/month=MM/day=DD/hour=HH/{event_id}.json
        """
        # Parse timestamp
        timestamp = datetime.fromisoformat(
            violation_event.timestamp.replace("Z", "+00:00")
        )

        # Create hierarchical path for partitioning
        year = timestamp.year
        month = f"{timestamp.month:02d}"
        day = f"{timestamp.day:02d}"
        hour = f"{timestamp.hour:02d}"

        return (
            f"{self.key_prefix}/"
            f"year={year}/month={month}/day={day}/hour={hour}/"
            f"{violation_event.event_id}.json"
        )

    def _create_audit_record(self, violation_event: ViolationEvent) -> dict[str, Any]:
        """Create comprehensive audit record."""
        original_event = violation_event.original_event
        violation = violation_event.violation
        user_identity = violation_event.get_user_identity()

        return {
            # Event metadata
            "eventId": violation_event.event_id,
            "timestamp": violation_event.timestamp,
            "correlationId": violation_event.correlation_id,
            "auditVersion": "1.0",
            # Violation details
            "violation": {
                "ruleName": violation.get("rule_name"),
                "severity": violation.get("severity"),
                "description": violation.get("description"),
                "category": violation.get("category", "Policy"),
                "riskScore": violation.get("risk_score"),
            },
            # Event context
            "event": {
                "name": original_event.get("eventName"),
                "source": original_event.get("eventSource"),
                "time": original_event.get("eventTime"),
                "region": original_event.get("awsRegion"),
                "sourceIPAddress": original_event.get("sourceIPAddress"),
                "userAgent": original_event.get("userAgent"),
                "requestID": original_event.get("requestID"),
                "apiVersion": original_event.get("apiVersion"),
            },
            # User/Identity information
            "identity": {
                "type": user_identity.get("type"),
                "principalId": user_identity.get("principalId"),
                "arn": user_identity.get("arn"),
                "accountId": user_identity.get("accountId"),
                "userName": user_identity.get("userName"),
                "sessionContext": user_identity.get("sessionContext"),
            },
            # Request parameters (if available)
            "requestParameters": original_event.get("requestParameters", {}),
            # Response elements (if available)
            "responseElements": original_event.get("responseElements", {}),
            # Resources affected
            "resources": original_event.get("resources", []),
            # Service event details (if available)
            "serviceEventDetails": original_event.get("serviceEventDetails"),
            # Additional context
            "additionalEventData": original_event.get("additionalEventData"),
            "requestId": original_event.get("requestId"),
            "eventType": original_event.get("eventType"),
            "recipientAccountId": original_event.get("recipientAccountId"),
            "vpcEndpointId": original_event.get("vpcEndpointId"),
        }


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for audit logging.

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
        # Get S3 configuration from environment
        bucket_name = os.environ.get("AUDIT_BUCKET_NAME") or os.environ.get(
            "AUDIT_BUCKET"
        )
        if not bucket_name:
            logger.error(
                "AUDIT_BUCKET or AUDIT_BUCKET_NAME environment variable not set"
            )
            return {"statusCode": 400, "body": "Audit bucket not configured"}

        key_prefix = os.environ.get("AUDIT_KEY_PREFIX", "iam-violations")

        # Ignore non-violation events (e.g., remediation status) that lack a 'violation' key
        try:
            violation_event = ViolationEvent.from_eventbridge_event(event)
        except KeyError:
            logger.info(
                "Event does not contain a violation payload; skipping audit log."
            )
            return {"statusCode": 204, "body": "Non-violation event skipped"}

        logger.info(
            f"Logging violation event: {violation_event.get_rule_name()} "
            f"(ID: {violation_event.event_id})"
        )

        # Create logger and write audit record
        audit_logger = AuditLogger(bucket_name, key_prefix)
        success = audit_logger.log_violation(violation_event)

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "Audit log written successfully",
                        "eventId": violation_event.event_id,
                        "correlationId": violation_event.correlation_id,
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to write audit log",
                        "eventId": violation_event.event_id,
                        "correlationId": violation_event.correlation_id,
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in audit logger handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


# Mock for testing
class MockAuditLogger(AuditLogger):
    """Mock audit logger for testing."""

    def __init__(
        self,
        bucket_name: str = "mock-bucket",
        key_prefix: str = "audit-logs",
        aws_clients: Any = None,
    ) -> None:
        """Initialize mock logger."""
        self.bucket_name = bucket_name
        self.key_prefix = key_prefix
        self.logger = setup_logging()
        self.logged_records: list[dict[str, Any]] = []

    def log_violation(self, violation_event: ViolationEvent) -> bool:
        """Mock log - store record for testing."""
        s3_key = self._generate_s3_key(violation_event)
        audit_record = self._create_audit_record(violation_event)

        self.logged_records.append(
            {
                "s3_key": s3_key,
                "audit_record": audit_record,
                "bucket": self.bucket_name,
            }
        )

        self.logger.info(f"MOCK: Logged audit record to {s3_key}")
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
                "rule_name": "OverlyBroadRole",
                "severity": "CRITICAL",
                "description": "Role with Admin access created",
                "category": "Role",
                "risk_score": 9.5,
            },
            "originalEvent": {
                "eventName": "CreateRole",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2024-01-01T12:00:00Z",
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.12",
                "userAgent": "aws-cli/2.0.0",
                "requestID": "12345678-1234-1234-1234-123456789012",
                "userIdentity": {
                    "type": "IAMUser",
                    "principalId": "AIDAIOSFODNN7EXAMPLE",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                    "accountId": "123456789012",
                    "userName": "test-user",
                },
                "requestParameters": {
                    "roleName": "TestRole",
                    "assumeRolePolicyDocument": (
                        "%7B%22Version%22%3A%222012-10-17%22%7D"
                    ),
                },
                "responseElements": {
                    "role": {
                        "roleId": "AROAIOSFODNN7EXAMPLE",
                        "roleName": "TestRole",
                        "arn": "arn:aws:iam::123456789012:role/TestRole",
                    }
                },
                "resources": [
                    {
                        "type": "AWS::IAM::Role",
                        "ARN": "arn:aws:iam::123456789012:role/TestRole",
                    }
                ],
            },
        },
    }

    # Test with mock
    os.environ["AUDIT_BUCKET_NAME"] = "test-audit-bucket"
    os.environ["AUDIT_KEY_PREFIX"] = "iam-violations"
    result = lambda_handler(sample_event, None)
    print(f"Result: {result}")
