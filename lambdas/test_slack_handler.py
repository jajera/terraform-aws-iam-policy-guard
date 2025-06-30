#!/usr/bin/env python3
"""Unit tests for slack_handler module."""

import os
from unittest.mock import MagicMock, patch

import pytest
from slack_handler import (
    _convert_to_slack_format,
    lambda_handler,
    remediation_handler,
)
from violation_event import ViolationEvent

# Test constants
TEST_WEBHOOK_URL = "https://hooks.slack.com/services/TEST/TEST/TEST"


class TestSlackFormatConversion:
    """Test Slack format conversion functions."""

    def test_convert_to_slack_format(self):
        """Test converting ViolationEvent to Slack format."""
        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={
                "rule_name": "DangerousPolicy",
                "severity": "CRITICAL",
                "description": "Policy allows admin access",
                "category": "Permission",
                "risk_score": 9.5,
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
            },
            correlation_id="test-correlation",
        )

        slack_data = _convert_to_slack_format(violation_event)

        # Verify basic structure
        assert slack_data["rule_name"] == "DangerousPolicy"
        assert slack_data["severity"] == "CRITICAL"
        assert slack_data["description"] == "Policy allows admin access"
        assert slack_data["category"] == "Permission"
        assert slack_data["risk_score"] == 9.5

        # Verify event context
        assert slack_data["event_name"] == "PutUserPolicy"
        assert slack_data["event_source"] == "iam.amazonaws.com"
        assert slack_data["event_time"] == "2024-01-01T12:00:00Z"
        assert slack_data["aws_region"] == "us-east-1"
        assert slack_data["source_ip"] == "203.0.113.1"
        assert slack_data["user_agent"] == "aws-cli/2.0.0"

        # Verify user context
        assert slack_data["user_type"] == "IAMUser"
        assert slack_data["user_name"] == "test-user"
        assert slack_data["user_arn"] == "arn:aws:iam::123456789012:user/test-user"

        # Verify metadata
        assert slack_data["correlation_id"] == "test-correlation"
        assert slack_data["event_id"] == "test-event-id"

    def test_convert_to_slack_format_minimal(self):
        """Test converting minimal ViolationEvent to Slack format."""
        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
            correlation_id="test-correlation",
        )

        slack_data = _convert_to_slack_format(violation_event)

        # Verify defaults are used
        assert slack_data["rule_name"] == "Unknown"
        assert slack_data["severity"] == "MEDIUM"
        assert slack_data["description"] == "No description available"
        assert slack_data["category"] == "Policy"
        assert slack_data["event_name"] == "Unknown"
        assert slack_data["event_source"] == "Unknown"
        assert slack_data["user_type"] == "Unknown"
        assert slack_data["user_name"] == "Unknown"


class TestViolationLambdaHandler:
    """Test violation Lambda handler function."""

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
            "SLACK_CONFIG_KEY": "notification-config.yaml",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_lambda_handler_success(self, mock_slack_notifier_class):
        """Test successful violation Lambda handler execution."""
        # Setup mock Slack notifier
        mock_notifier = MagicMock()
        mock_notifier.send_slack_notification.return_value = True
        mock_slack_notifier_class.return_value = mock_notifier

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
        mock_notifier.send_slack_notification.assert_called_once()

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_lambda_handler_failure(self, mock_slack_notifier_class):
        """Test Lambda handler with Slack notification failure."""
        # Setup mock Slack notifier
        mock_notifier = MagicMock()
        mock_notifier.send_slack_notification.return_value = False
        mock_slack_notifier_class.return_value = mock_notifier

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

    def test_lambda_handler_missing_webhook_url(self):
        """Test Lambda handler with missing webhook URL."""
        # Clear webhook URL environment variable
        if "SLACK_WEBHOOK_URL" in os.environ:
            del os.environ["SLACK_WEBHOOK_URL"]

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
        assert "Slack webhook not configured" in result["body"]

    def test_lambda_handler_missing_config_bucket(self):
        """Test Lambda handler with missing config bucket."""
        # Set webhook URL but clear config bucket
        os.environ["SLACK_WEBHOOK_URL"] = (
            "https://hooks.slack.com/services/TEST/TEST/TEST"
        )
        if "CONFIG_BUCKET_NAME" in os.environ:
            del os.environ["CONFIG_BUCKET_NAME"]

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
        assert "Config bucket not configured" in result["body"]

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_lambda_handler_exception(self, mock_slack_notifier_class):
        """Test Lambda handler with exception."""
        # Setup mock Slack notifier to raise exception
        mock_slack_notifier_class.side_effect = Exception("Test exception")

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


class TestRemediationLambdaHandler:
    """Test remediation Lambda handler function."""

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
            "SLACK_CONFIG_KEY": "notification-config.yaml",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_remediation_handler_success(self, mock_slack_notifier_class):
        """Test successful remediation Lambda handler execution."""
        # Setup mock Slack notifier
        mock_notifier = MagicMock()
        mock_notifier.send_remediation_notification.return_value = True
        mock_slack_notifier_class.return_value = mock_notifier

        # Sample EventBridge event for remediation
        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {
                "correlationId": "test-correlation",
                "remediationAction": "quarantine_policy",
                "remediationResult": {
                    "success": True,
                    "message": "Policy quarantined successfully",
                },
                "originalViolation": {
                    "rule_name": "TestRule",
                    "severity": "HIGH",
                },
            },
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 200
        mock_notifier.send_remediation_notification.assert_called_once()

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_remediation_handler_failure(self, mock_slack_notifier_class):
        """Test remediation handler with notification failure."""
        # Setup mock Slack notifier
        mock_notifier = MagicMock()
        mock_notifier.send_remediation_notification.return_value = False
        mock_slack_notifier_class.return_value = mock_notifier

        # Sample EventBridge event for remediation
        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {
                "correlationId": "test-correlation",
                "remediationAction": "quarantine_policy",
                "remediationResult": {
                    "success": False,
                    "message": "Failed to quarantine policy",
                },
                "originalViolation": {
                    "rule_name": "TestRule",
                    "severity": "HIGH",
                },
            },
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 500

    def test_remediation_handler_missing_webhook_url(self):
        """Test remediation handler with missing webhook URL."""
        # Clear webhook URL environment variable
        if "SLACK_WEBHOOK_URL" in os.environ:
            del os.environ["SLACK_WEBHOOK_URL"]

        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {
                "correlationId": "test-correlation",
                "remediationAction": "quarantine_policy",
                "remediationResult": {"success": True},
                "originalViolation": {
                    "rule_name": "TestRule",
                    "severity": "HIGH",
                },
            },
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 400
        assert "Slack webhook not configured" in result["body"]

    def test_remediation_handler_missing_config_bucket(self):
        """Test remediation handler with missing config bucket."""
        # Set webhook URL but clear config bucket
        os.environ["SLACK_WEBHOOK_URL"] = (
            "https://hooks.slack.com/services/TEST/TEST/TEST"
        )
        if "CONFIG_BUCKET_NAME" in os.environ:
            del os.environ["CONFIG_BUCKET_NAME"]

        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {
                "correlationId": "test-correlation",
                "remediationAction": "quarantine_policy",
                "remediationResult": {"success": True},
                "originalViolation": {
                    "rule_name": "TestRule",
                    "severity": "HIGH",
                },
            },
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 400
        assert "Config bucket not configured" in result["body"]

    @patch.dict(
        os.environ,
        {
            "SLACK_WEBHOOK_URL": TEST_WEBHOOK_URL,
            "CONFIG_BUCKET_NAME": "test-config-bucket",
        },
    )
    @patch("slack_handler.SlackNotifier")
    def test_remediation_handler_exception(self, mock_slack_notifier_class):
        """Test remediation handler with exception."""
        # Setup mock Slack notifier to raise exception
        mock_slack_notifier_class.side_effect = Exception("Test exception")

        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {
                "correlationId": "test-correlation",
                "remediationAction": "quarantine_policy",
                "remediationResult": {"success": True},
                "originalViolation": {
                    "rule_name": "TestRule",
                    "severity": "HIGH",
                },
            },
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 500

    def test_remediation_handler_invalid_event(self):
        """Test remediation handler with invalid event structure."""
        os.environ["SLACK_WEBHOOK_URL"] = (
            "https://hooks.slack.com/services/TEST/TEST/TEST"
        )
        os.environ["CONFIG_BUCKET_NAME"] = "test-config-bucket"

        # Invalid event (missing required fields)
        event = {
            "source": "iam.policy.monitor.remediation",
            "detail-type": "IAM Policy Remediation Complete",
            "detail": {},  # Missing required fields
        }

        result = remediation_handler(event, None)

        assert result["statusCode"] == 500


class TestEdgeCases:
    """Test edge cases and error handling."""

    def test_convert_to_slack_format_with_missing_user_identity(self):
        """Test Slack format conversion with missing user identity."""
        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={"eventName": "PutUserPolicy"},  # No userIdentity
            correlation_id="test-correlation",
        )

        slack_data = _convert_to_slack_format(violation_event)

        # Should handle missing user identity gracefully
        assert slack_data["user_type"] == "Unknown"
        assert slack_data["user_name"] == "Unknown"
        assert slack_data["user_arn"] == "Unknown"

    def test_convert_to_slack_format_with_partial_user_identity(self):
        """Test Slack format conversion with partial user identity."""
        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={
                "eventName": "PutUserPolicy",
                "userIdentity": {"type": "IAMUser"},  # Missing userName and arn
            },
            correlation_id="test-correlation",
        )

        slack_data = _convert_to_slack_format(violation_event)

        # Should handle partial user identity gracefully
        assert slack_data["user_type"] == "IAMUser"
        assert slack_data["user_name"] == "Unknown"
        assert slack_data["user_arn"] == "Unknown"


if __name__ == "__main__":
    pytest.main([__file__])
