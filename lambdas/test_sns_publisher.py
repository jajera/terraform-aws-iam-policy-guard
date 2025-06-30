#!/usr/bin/env python3
"""Unit tests for sns_publisher module."""

import os
from unittest.mock import MagicMock, patch

import pytest

from sns_publisher import (
    MockSNSPublisher,
    SNSPublisher,
    lambda_handler,
)

from violation_event import ViolationEvent


class TestSNSPublisher:
    """Test SNSPublisher class."""

    def test_init(self):
        """Test publisher initialization."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        mock_clients = MagicMock()

        publisher = SNSPublisher(topic_arn, mock_clients)

        assert publisher.topic_arn == topic_arn
        assert publisher.sns == mock_clients

    def test_init_without_clients(self):
        """Test publisher initialization without AWS clients."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"

        with patch("sns_publisher.boto3") as mock_boto3:
            mock_sns = MagicMock()
            mock_boto3.client.return_value = mock_sns

            publisher = SNSPublisher(topic_arn)

            assert publisher.topic_arn == topic_arn
            assert publisher.sns == mock_sns
            mock_boto3.client.assert_called_once_with("sns")

    def test_publish_alert_success(self):
        """Test successful alert publishing."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        mock_clients = MagicMock()
        mock_clients.publish.return_value = {"MessageId": "test-message-id"}

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

        publisher = SNSPublisher(topic_arn, mock_clients)
        result = publisher.publish_violation_alert(violation_event)

        assert result is True
        mock_clients.publish.assert_called_once()
        call_args = mock_clients.publish.call_args
        assert call_args[1]["TopicArn"] == topic_arn
        expected_subject = "IAM Policy Violation - HIGH: TestRule"
        assert expected_subject in call_args[1]["Subject"]
        assert "TestRule" in call_args[1]["Message"]

    def test_publish_alert_failure(self):
        """Test alert publishing failure."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        mock_clients = MagicMock()
        mock_clients.publish.side_effect = Exception("SNS error")

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        publisher = SNSPublisher(topic_arn, mock_clients)
        result = publisher.publish_violation_alert(violation_event)

        assert result is False

    def test_format_message(self):
        """Test message formatting."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
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
                    "userName": "test-user",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "sourceIPAddress": "203.0.113.1",
                "userAgent": "aws-cli/2.0.0",
                "awsRegion": "us-east-1",
            },
            correlation_id="test-correlation",
        )

        publisher = SNSPublisher(topic_arn, mock_clients)
        message = publisher._format_message(violation_event)

        # Verify message contains key information
        assert "DangerousPolicy" in message
        assert "CRITICAL" in message
        assert "Policy allows admin access" in message
        assert "test-user" in message
        assert "203.0.113.1" in message
        assert "us-east-1" in message
        assert "test-correlation" in message

    def test_format_message_minimal(self):
        """Test message formatting with minimal data."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        mock_clients = MagicMock()

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
            correlation_id="test-correlation",
        )

        publisher = SNSPublisher(topic_arn, mock_clients)
        message = publisher._format_message(violation_event)

        # Verify message handles missing data gracefully
        assert "Unknown" in message
        assert "test-correlation" in message


class TestMockSNSPublisher:
    """Test MockSNSPublisher class."""

    def test_init(self):
        """Test mock publisher initialization."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"

        publisher = MockSNSPublisher(topic_arn)

        assert publisher.topic_arn == topic_arn
        assert publisher.published_messages == []

    def test_publish_alert_mock(self):
        """Test mock alert publishing."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        publisher = MockSNSPublisher(topic_arn)
        result = publisher.publish_violation_alert(violation_event)

        assert result is True
        assert len(publisher.published_messages) == 1

        message = publisher.published_messages[0]
        assert message["topic_arn"] == topic_arn
        assert "HIGH: TestRule" in message["subject"]
        assert "TestRule" in message["message"]

    def test_multiple_alerts(self):
        """Test publishing multiple alerts."""
        topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic"
        publisher = MockSNSPublisher(topic_arn)

        # Publish multiple alerts
        for i in range(3):
            violation_event = ViolationEvent(
                event_id=f"test-event-{i}",
                timestamp="2024-01-01T12:00:00Z",
                violation={"rule_name": f"Rule{i}", "severity": "MEDIUM"},
                original_event={},
                correlation_id=f"test-correlation-{i}",
            )
            result = publisher.publish_violation_alert(violation_event)
            assert result is True

        assert len(publisher.published_messages) == 3


class TestLambdaHandler:
    """Test Lambda handler function."""

    @patch.dict(
        os.environ,
        {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"},
    )
    @patch("sns_publisher.SNSPublisher")
    def test_lambda_handler_success(self, mock_publisher_class):
        """Test successful Lambda handler execution."""
        # Setup mock publisher
        mock_publisher = MagicMock()
        mock_publisher.publish_alert.return_value = True
        mock_publisher_class.return_value = mock_publisher

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
        mock_publisher.publish_violation_alert.assert_called_once()

    @patch.dict(
        os.environ,
        {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"},
    )
    @patch("sns_publisher.SNSPublisher")
    def test_lambda_handler_failure(self, mock_publisher_class):
        """Test Lambda handler with publishing failure."""
        # Setup mock publisher
        mock_publisher = MagicMock()
        mock_publisher.publish_violation_alert.return_value = False
        mock_publisher_class.return_value = mock_publisher

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
        if "SNS_TOPIC_ARN" in os.environ:
            del os.environ["SNS_TOPIC_ARN"]

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
        assert "SNS topic not configured" in result["body"]

    @patch.dict(
        os.environ,
        {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"},
    )
    @patch("sns_publisher.SNSPublisher")
    def test_lambda_handler_exception(self, mock_publisher_class):
        """Test Lambda handler with exception."""
        # Setup mock publisher to raise exception
        mock_publisher_class.side_effect = Exception("Test exception")

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

    @patch.dict(
        os.environ,
        {"SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test-topic"},
    )
    @patch("sns_publisher.SNSPublisher")
    def test_lambda_handler_invalid_event(self, mock_publisher_class):
        """Test Lambda handler with invalid event structure."""
        # Setup mock publisher
        mock_publisher = MagicMock()
        mock_publisher_class.return_value = mock_publisher

        # Invalid event (missing required fields)
        event = {
            "source": "iam.policy.monitor",
            "detail-type": "IAM Policy Violation",
            "detail": {},  # Missing required fields
        }

        result = lambda_handler(event, None)

        assert result["statusCode"] == 500


if __name__ == "__main__":
    pytest.main([__file__])
