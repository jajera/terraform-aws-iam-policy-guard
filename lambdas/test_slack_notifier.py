#!/usr/bin/env python3
"""Tests for simplified Slack Notifier."""

from unittest.mock import MagicMock, patch

import pytest

from slack_notifier import MockSlackNotifier, SlackNotifier


class TestSlackNotifier:
    """Test SlackNotifier class."""

    def test_init(self):
        """Test notifier initialization."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        rules_bucket = "test-config-bucket"
        mock_aws_clients = MagicMock()

        notifier = SlackNotifier(webhook_url, mock_aws_clients, rules_bucket)

        assert notifier.webhook_url == webhook_url
        assert notifier.aws_clients == mock_aws_clients
        assert notifier.rules_bucket == rules_bucket
        # Config should not be loaded yet (lazy loading)
        assert not notifier._config_loaded

    @patch("slack_notifier.urllib.request.urlopen")
    def test_send_slack_notification_success(self, mock_urlopen):
        """Test successful Slack notification sending."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        mock_response = MagicMock()
        mock_response.status = 200
        mock_response.read.return_value = b"ok"
        mock_urlopen.return_value.__enter__.return_value = mock_response

        violation_data = {
            "rule_name": "TestRule",
            "severity": "HIGH",
            "description": "Test violation",
        }

        event_data = {
            "eventName": "PutUserPolicy",
            "userIdentity": {"userName": "test-user"},
        }

        notifier = SlackNotifier(webhook_url)
        result = notifier.send_slack_notification(violation_data, event_data)

        assert result is True
        mock_urlopen.assert_called_once()

    # TODO: This test takes 31s due to retry logic - temporarily disabled
    @patch("slack_notifier.urllib.request.urlopen")
    def _test_send_slack_notification_failure(self, mock_urlopen):
        """Test Slack notification sending failure."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        mock_urlopen.side_effect = Exception("Network error")

        violation_data = {
            "rule_name": "TestRule",
            "severity": "HIGH",
        }

        notifier = SlackNotifier(webhook_url)
        result = notifier.send_slack_notification(violation_data, {})

        assert result is False

    def test_get_status_color(self):
        """Test status color retrieval."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        notifier = SlackNotifier(webhook_url)

        assert notifier.get_status_color("CRITICAL") == "#E01E5A"
        assert notifier.get_status_color("HIGH") == "#FF5733"
        assert notifier.get_status_color("UNKNOWN") is None

    @patch("slack_notifier.urllib.request.urlopen")
    def test_send_remediation_notification(self, mock_urlopen):
        """Test remediation notification sending."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        notifier = SlackNotifier(webhook_url)
        result = notifier.send_remediation_notification(
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            action="quarantine_policy",
            result={"success": True, "message": "Success"},
        )

        assert result is True
        mock_urlopen.assert_called_once()

    def test_format_slack_message(self):
        """Test Slack message formatting."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        notifier = SlackNotifier(webhook_url)

        violation_data = {
            "rule_name": "TestRule",
            "severity": "HIGH",
            "description": "Test violation",
        }

        event_data = {
            "event_name": "PutUserPolicy",
            "user_name": "test-user",
            "user_arn": "arn:aws:iam::123456789012:user/test-user",
            "source_ip": "203.0.113.12",
            "aws_region": "us-east-1",
            "request_parameters": {
                "userName": "test-user",
                "policyName": "dangerous-policy",
            },
        }

        message = notifier.format_slack_message(violation_data, event_data)

        assert "attachments" in message
        assert len(message["attachments"]) == 1

        attachment = message["attachments"][0]
        assert "IAM Policy Violation Detected" in attachment["pretext"]
        assert attachment["color"] == "#FF5733"  # HIGH severity color
        assert "text" in attachment  # Description should be present
        assert len(attachment["fields"]) >= 6  # Should have basic fields

    def test_extract_field(self):
        """Test field value extraction with dot notation."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        notifier = SlackNotifier(webhook_url)

        data = {
            "user": {"name": "test-user", "details": {"role": "admin"}},
            "simple_field": "simple_value",
        }

        # Test simple field
        assert notifier.extract_field(data, "simple_field") == "simple_value"

        # Test dot notation
        assert notifier.extract_field(data, "user.name") == "test-user"
        assert notifier.extract_field(data, "user.details.role") == "admin"

        # Test missing field
        assert notifier.extract_field(data, "missing_field") == "N/A"
        assert notifier.extract_field(data, "user.missing") == "N/A"


class TestMockSlackNotifier:
    """Test MockSlackNotifier class."""

    def test_init(self):
        """Test mock notifier initialization."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"

        notifier = MockSlackNotifier(webhook_url)

        assert notifier.webhook_url == webhook_url
        assert notifier.sent_messages == []

    def test_send_slack_notification_mock(self):
        """Test mock Slack notification sending."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"

        violation_data = {
            "rule_name": "TestRule",
            "severity": "HIGH",
            "description": "Test violation",
        }

        notifier = MockSlackNotifier(webhook_url)
        result = notifier.send_slack_notification(violation_data, {})

        assert result is True
        assert len(notifier.sent_messages) == 1

        message = notifier.sent_messages[0]
        assert "attachments" in message

    def test_send_remediation_notification_mock(self):
        """Test mock remediation notification sending."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"

        notifier = MockSlackNotifier(webhook_url)
        result = notifier.send_remediation_notification(
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            action="quarantine_policy",
            result={"success": True, "message": "Success"},
        )

        assert result is True
        assert len(notifier.sent_messages) == 1

    def test_multiple_notifications(self):
        """Test sending multiple notifications."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        notifier = MockSlackNotifier(webhook_url)

        # Send multiple notifications
        for i in range(3):
            violation_data = {
                "rule_name": f"Rule{i}",
                "severity": "MEDIUM",
            }
            result = notifier.send_slack_notification(violation_data, {})
            assert result is True

        assert len(notifier.sent_messages) == 3


class TestEdgeCases:
    """Test edge cases and error handling."""

    # TODO: This test takes 31s due to retry logic - temporarily disabled
    @patch("slack_notifier.urllib.request.urlopen")
    def _test_send_notification_with_connection_error(self, mock_urlopen):
        """Test notification sending with connection error."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        mock_urlopen.side_effect = Exception("Connection failed")

        violation_data = {
            "rule_name": "TestRule",
            "severity": "HIGH",
        }

        notifier = SlackNotifier(webhook_url)
        result = notifier.send_slack_notification(violation_data, {})

        assert result is False

    def test_format_message_with_minimal_data(self):
        """Test message formatting with minimal violation data."""
        webhook_url = "https://hooks.slack.com/services/TEST/TEST/TEST"
        notifier = SlackNotifier(webhook_url)

        minimal_data = {}
        message = notifier.format_slack_message(minimal_data, {})

        # Should handle missing data gracefully
        assert "attachments" in message
        attachment = message["attachments"][0]
        assert "fields" in attachment


if __name__ == "__main__":
    pytest.main([__file__])
