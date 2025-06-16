#!/usr/bin/env python3
"""Unit tests for audit_logger module."""

import os
from unittest.mock import MagicMock, patch

from audit_logger import AuditLogger, MockAuditLogger, lambda_handler

import pytest

from violation_event import ViolationEvent


class TestAuditLogger:
    """Test AuditLogger class."""

    def test_init(self):
        """Test logger initialization."""
        bucket_name = "test-audit-bucket"
        key_prefix = "audit-logs"
        mock_clients = MagicMock()

        logger = AuditLogger(bucket_name, key_prefix, mock_clients)

        assert logger.bucket_name == bucket_name
        assert logger.key_prefix == key_prefix
        assert logger.s3 == mock_clients

    def test_init_without_clients(self):
        """Test logger initialization without AWS clients."""
        bucket_name = "test-audit-bucket"

        with patch("audit_logger.boto3") as mock_boto3:
            mock_s3 = MagicMock()
            mock_boto3.client.return_value = mock_s3

            logger = AuditLogger(bucket_name)

            assert logger.bucket_name == bucket_name
            assert logger.key_prefix == "audit-logs"
            assert logger.s3 == mock_s3
            mock_boto3.client.assert_called_once_with("s3")

    def test_log_violation_success(self):
        """Test successful violation logging."""
        bucket_name = "test-audit-bucket"
        mock_clients = MagicMock()
        mock_clients.put_object.return_value = {"ETag": "test-etag"}

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={
                "rule_name": "TestRule",
                "severity": "HIGH",
                "description": "Test violation",
            },
            original_event={
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {"userName": "test-user"},
                "awsRegion": "us-east-1",
            },
            correlation_id="test-correlation",
        )

        logger = AuditLogger(bucket_name, aws_clients=mock_clients)
        result = logger.log_violation(violation_event)

        assert result is True
        mock_clients.put_object.assert_called_once()
        call_args = mock_clients.put_object.call_args
        assert call_args[1]["Bucket"] == bucket_name
        expected_key_part = "audit-logs/year=2024/month=01/day=01/hour=12/"
        assert expected_key_part in call_args[1]["Key"]
        assert call_args[1]["ContentType"] == "application/json"

    def test_log_violation_failure(self):
        """Test violation logging failure."""
        bucket_name = "test-audit-bucket"
        mock_clients = MagicMock()
        mock_clients.put_object.side_effect = Exception("S3 error")

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        logger = AuditLogger(bucket_name, aws_clients=mock_clients)
        result = logger.log_violation(violation_event)

        assert result is False

    def test_generate_s3_key(self):
        """Test S3 key generation."""
        bucket_name = "test-audit-bucket"
        mock_clients = MagicMock()

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-03-15T14:30:45Z",
            violation={},
            original_event={},
            correlation_id="test-correlation",
        )

        logger = AuditLogger(bucket_name, "custom-prefix", mock_clients)
        s3_key = logger._generate_s3_key(violation_event)

        # Verify hierarchical partitioning
        expected_prefix = "custom-prefix/year=2024/month=03/day=15/hour=14/"
        assert s3_key.startswith(expected_prefix)
        assert s3_key.endswith(".json")
        assert "test-event-id" in s3_key

    def test_create_audit_record(self):
        """Test audit record creation."""
        bucket_name = "test-audit-bucket"
        mock_clients = MagicMock()

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={
                "rule_name": "DangerousPolicy",
                "severity": "CRITICAL",
                "description": "Policy allows admin access",
                "resources_affected": ["iam:policy/dangerous-policy"],
            },
            original_event={
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "eventTime": "2024-01-01T12:00:00Z",
                "userIdentity": {
                    "type": "IAMUser",
                    "userName": "test-user",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "sourceIPAddress": "203.0.113.1",
                "userAgent": "aws-cli/2.0.0",
                "awsRegion": "us-east-1",
                "requestID": "test-request-id",
                "resources": [{"accountId": "123456789012"}],
            },
            correlation_id="test-correlation",
        )

        logger = AuditLogger(bucket_name, aws_clients=mock_clients)
        audit_record = logger._create_audit_record(violation_event)

        # Verify audit record structure
        assert audit_record["auditVersion"] == "1.0"
        assert audit_record["eventId"] == "test-event-id"
        assert audit_record["correlationId"] == "test-correlation"
        assert audit_record["timestamp"] is not None

        # Verify violation summary
        violation = audit_record["violation"]
        assert violation["ruleName"] == "DangerousPolicy"
        assert violation["severity"] == "CRITICAL"
        assert violation["description"] == "Policy allows admin access"

        # Verify event context
        event = audit_record["event"]
        assert event["name"] == "PutUserPolicy"
        assert event["source"] == "iam.amazonaws.com"
        assert event["region"] == "us-east-1"

        # Verify user context
        identity = audit_record["identity"]
        assert identity["type"] == "IAMUser"
        assert identity["userName"] == "test-user"
        assert identity["arn"] == "arn:aws:iam::123456789012:user/test-user"

        # Verify security context
        assert event["sourceIPAddress"] == "203.0.113.1"
        assert event["userAgent"] == "aws-cli/2.0.0"

    def test_create_audit_record_minimal(self):
        """Test audit record creation with minimal data."""
        bucket_name = "test-audit-bucket"
        mock_clients = MagicMock()

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
            correlation_id="test-correlation",
        )

        logger = AuditLogger(bucket_name, aws_clients=mock_clients)
        audit_record = logger._create_audit_record(violation_event)

        # Verify record handles missing data gracefully
        assert audit_record["eventId"] == "test-event-id"
        assert audit_record["violation"]["ruleName"] is None
        assert audit_record["event"]["name"] is None
        assert audit_record["identity"]["userName"] is None


class TestMockAuditLogger:
    """Test MockAuditLogger class."""

    def test_init(self):
        """Test mock logger initialization."""
        bucket_name = "test-audit-bucket"

        logger = MockAuditLogger(bucket_name)

        assert logger.bucket_name == bucket_name
        assert logger.key_prefix == "audit-logs"
        assert logger.logged_records == []

    def test_log_violation_mock(self):
        """Test mock violation logging."""
        bucket_name = "test-audit-bucket"

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        logger = MockAuditLogger(bucket_name)
        result = logger.log_violation(violation_event)

        assert result is True
        assert len(logger.logged_records) == 1

        logged_record = logger.logged_records[0]
        assert logged_record["bucket"] == bucket_name
        expected_key_part = "year=2024/month=01/day=01/hour=12/"
        assert expected_key_part in logged_record["s3_key"]
        assert logged_record["audit_record"]["eventId"] == "test-event-id"

    def test_multiple_logs(self):
        """Test logging multiple violations."""
        bucket_name = "test-audit-bucket"
        logger = MockAuditLogger(bucket_name)

        # Log multiple violations
        for i in range(3):
            violation_event = ViolationEvent(
                event_id=f"test-event-{i}",
                timestamp="2024-01-01T12:00:00Z",
                violation={"rule_name": f"Rule{i}", "severity": "MEDIUM"},
                original_event={},
                correlation_id=f"test-correlation-{i}",
            )
            result = logger.log_violation(violation_event)
            assert result is True

        assert len(logger.logged_records) == 3


class TestLambdaHandler:
    """Test Lambda handler function."""

    @patch.dict(os.environ, {"AUDIT_BUCKET_NAME": "test-audit-bucket"})
    @patch("audit_logger.AuditLogger")
    def test_lambda_handler_success(self, mock_logger_class):
        """Test successful Lambda handler execution."""
        # Setup mock logger
        mock_logger = MagicMock()
        mock_logger.log_violation.return_value = True
        mock_logger_class.return_value = mock_logger

        # Sample EventBridge event
        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {
                "eventId": "test-event-id",
                "timestamp": "2024-01-01T12:00:00Z",
                "correlationId": "test-correlation",
                "violation": {"rule_name": "TestRule", "severity": "HIGH"},
                "originalEvent": {"eventName": "PutUserPolicy"},
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 200
        mock_logger.log_violation.assert_called_once()

    @patch.dict(os.environ, {"AUDIT_BUCKET_NAME": "test-audit-bucket"})
    @patch("audit_logger.AuditLogger")
    def test_lambda_handler_failure(self, mock_logger_class):
        """Test Lambda handler with logging failure."""
        # Setup mock logger
        mock_logger = MagicMock()
        mock_logger.log_violation.return_value = False
        mock_logger_class.return_value = mock_logger

        # Sample EventBridge event
        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {
                "eventId": "test-event-id",
                "timestamp": "2024-01-01T12:00:00Z",
                "correlationId": "test-correlation",
                "violation": {"rule_name": "TestRule", "severity": "HIGH"},
                "originalEvent": {"eventName": "PutUserPolicy"},
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 500

    def test_lambda_handler_missing_env_var(self):
        """Test Lambda handler with missing environment variable."""
        # Clear environment variable
        if "AUDIT_BUCKET_NAME" in os.environ:
            del os.environ["AUDIT_BUCKET_NAME"]
        if "AUDIT_BUCKET" in os.environ:
            del os.environ["AUDIT_BUCKET"]

        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {
                "eventId": "test-event-id",
                "timestamp": "2024-01-01T12:00:00Z",
                "correlationId": "test-correlation",
                "violation": {"rule_name": "TestRule", "severity": "HIGH"},
                "originalEvent": {"eventName": "PutUserPolicy"},
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 400
        assert "Audit bucket not configured" in result["body"]

    @patch.dict(os.environ, {"AUDIT_BUCKET": "test-audit-bucket"})
    @patch("audit_logger.AuditLogger")
    def test_lambda_handler_with_audit_bucket_env(self, mock_logger_class):
        """Test Lambda handler with AUDIT_BUCKET environment variable."""
        # Setup mock logger
        mock_logger = MagicMock()
        mock_logger.log_violation.return_value = True
        mock_logger_class.return_value = mock_logger

        # Sample EventBridge event
        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {
                "eventId": "test-event-id",
                "timestamp": "2024-01-01T12:00:00Z",
                "correlationId": "test-correlation",
                "violation": {"rule_name": "TestRule", "severity": "HIGH"},
                "originalEvent": {"eventName": "PutUserPolicy"},
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 200
        mock_logger.log_violation.assert_called_once()
        # Verify the logger was initialized with the correct bucket name
        mock_logger_class.assert_called_once_with("test-audit-bucket", "iam-violations")

    @patch.dict(os.environ, {"AUDIT_BUCKET_NAME": "test-audit-bucket"})
    @patch("audit_logger.AuditLogger")
    def test_lambda_handler_exception(self, mock_logger_class):
        """Test Lambda handler with exception."""
        # Setup mock logger to raise exception
        mock_logger_class.side_effect = Exception("Test exception")

        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {
                "eventId": "test-event-id",
                "timestamp": "2024-01-01T12:00:00Z",
                "correlationId": "test-correlation",
                "violation": {"rule_name": "TestRule", "severity": "HIGH"},
                "originalEvent": {"eventName": "PutUserPolicy"},
            },
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 500


if __name__ == "__main__":
    pytest.main([__file__])
