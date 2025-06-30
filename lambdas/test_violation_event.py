#!/usr/bin/env python3
"""Unit tests for violation_event module."""

import json
from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from violation_event import (
    MockViolationEventPublisher,
    ViolationEvent,
    ViolationEventPublisher,
)


class TestViolationEvent:
    """Test ViolationEvent class."""

    def test_create_violation_event(self):
        """Test creating a ViolationEvent from detection results."""
        # Mock violation result
        violation_result = MagicMock()
        violation_result.to_dict.return_value = {
            "rule_name": "TestRule",
            "severity": "HIGH",
            "description": "Test violation",
            "action": "alert",
        }

        # Mock CloudTrail event
        cloudtrail_event = {
            "eventName": "PutUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"userName": "test-user"},
        }

        # Create violation event
        event = ViolationEvent.create(violation_result, cloudtrail_event)

        # Verify event properties
        assert event.source == "iam.policy.monitor"
        assert event.detail_type == "IAM Policy Violation"
        assert event.violation == violation_result.to_dict()
        assert event.original_event == cloudtrail_event
        assert event.correlation_id is not None
        assert event.event_id is not None

        # Verify timestamp format
        timestamp = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        assert isinstance(timestamp, datetime)

    def test_create_with_correlation_id(self):
        """Test creating event with specific correlation ID."""
        violation_result = MagicMock()
        violation_result.to_dict.return_value = {"rule_name": "TestRule"}
        cloudtrail_event = {"eventName": "PutUserPolicy"}
        correlation_id = "test-correlation-id"

        event = ViolationEvent.create(
            violation_result, cloudtrail_event, correlation_id
        )

        assert event.correlation_id == correlation_id

    def test_to_eventbridge_entry(self):
        """Test converting to EventBridge entry format."""
        event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={"eventName": "PutUserPolicy"},
            correlation_id="test-correlation",
        )

        entry = event.to_eventbridge_entry()

        # Verify entry structure
        assert entry["Source"] == "iam.policy.monitor"
        assert entry["DetailType"] == "IAM Policy Violation"

        # Verify detail is valid JSON
        detail = json.loads(entry["Detail"])
        assert detail["eventId"] == "test-event-id"
        assert detail["correlationId"] == "test-correlation"
        assert detail["violation"]["rule_name"] == "TestRule"

        # Verify timestamp format
        assert isinstance(entry["Time"], datetime)

    def test_from_eventbridge_event(self):
        """Test parsing from EventBridge Lambda event."""
        eventbridge_event = {
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

        event = ViolationEvent.from_eventbridge_event(eventbridge_event)

        assert event.event_id == "test-event-id"
        assert event.timestamp == "2024-01-01T12:00:00Z"
        assert event.correlation_id == "test-correlation"
        assert event.violation["rule_name"] == "TestRule"
        assert event.original_event["eventName"] == "PutUserPolicy"

    def test_get_severity(self):
        """Test getting violation severity."""
        event = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={"severity": "CRITICAL"},
            original_event={},
        )

        assert event.get_severity() == "CRITICAL"

        # Test default value
        event_no_severity = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
        )
        assert event_no_severity.get_severity() == "MEDIUM"

    def test_get_rule_name(self):
        """Test getting rule name."""
        event = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "DangerousPolicy"},
            original_event={},
        )

        assert event.get_rule_name() == "DangerousPolicy"

        # Test default value
        event_no_rule = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
        )
        assert event_no_rule.get_rule_name() == "Unknown"

    def test_get_event_name(self):
        """Test getting CloudTrail event name."""
        event = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={"eventName": "PutUserPolicy"},
        )

        assert event.get_event_name() == "PutUserPolicy"

    def test_get_user_identity(self):
        """Test getting user identity."""
        user_identity = {
            "type": "IAMUser",
            "userName": "test-user",
            "arn": "arn:aws:iam::123456789012:user/test-user",
        }
        event = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={"userIdentity": user_identity},
        )

        assert event.get_user_identity() == user_identity

        # Test empty user identity
        event_no_user = ViolationEvent(
            event_id="test",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
        )
        assert event_no_user.get_user_identity() == {}


class TestViolationEventPublisher:
    """Test ViolationEventPublisher class."""

    def test_init(self):
        """Test publisher initialization."""
        mock_clients = MagicMock()
        publisher = ViolationEventPublisher(mock_clients)

        assert publisher.aws_clients == mock_clients

    @patch("violation_event.ViolationEvent.create")
    def test_publish_violation_success(self, mock_create):
        """Test successful violation publishing."""
        # Setup mocks
        mock_clients = MagicMock()
        mock_clients.put_events.return_value = {"FailedEntryCount": 0}

        mock_event = MagicMock()
        mock_event.to_eventbridge_entry.return_value = {
            "Source": "iam.policy.monitor",
            "DetailType": "IAM Policy Violation",
            "Detail": '{"test": "data"}',
        }
        mock_create.return_value = mock_event

        violation_result = MagicMock()
        cloudtrail_event = {"eventName": "PutUserPolicy"}

        # Test publishing
        publisher = ViolationEventPublisher(mock_clients)
        result = publisher.publish_violation(violation_result, cloudtrail_event)

        # Verify success
        assert result is True
        mock_create.assert_called_once_with(violation_result, cloudtrail_event)
        mock_clients.put_events.assert_called_once()

    @patch("violation_event.ViolationEvent.create")
    def test_publish_violation_failure(self, mock_create):
        """Test failed violation publishing."""
        # Setup mocks
        mock_clients = MagicMock()
        mock_clients.put_events.return_value = {
            "FailedEntryCount": 1,
            "Entries": [{"ErrorCode": "ValidationError", "ErrorMessage": "Test error"}],
        }

        mock_event = MagicMock()
        mock_event.to_eventbridge_entry.return_value = {"test": "data"}
        mock_create.return_value = mock_event

        violation_result = MagicMock()
        cloudtrail_event = {"eventName": "PutUserPolicy"}

        # Test publishing
        publisher = ViolationEventPublisher(mock_clients)
        result = publisher.publish_violation(violation_result, cloudtrail_event)

        # Verify failure
        assert result is False

    @patch("violation_event.ViolationEvent.create")
    def test_publish_violation_exception(self, mock_create):
        """Test publishing with exception."""
        # Setup mocks
        mock_clients = MagicMock()
        mock_clients.put_events.side_effect = Exception("Connection error")

        mock_event = MagicMock()
        mock_create.return_value = mock_event

        violation_result = MagicMock()
        cloudtrail_event = {"eventName": "PutUserPolicy"}

        # Test publishing
        publisher = ViolationEventPublisher(mock_clients)
        result = publisher.publish_violation(violation_result, cloudtrail_event)

        # Verify failure
        assert result is False


class TestMockViolationEventPublisher:
    """Test MockViolationEventPublisher class."""

    def test_init(self):
        """Test mock publisher initialization."""
        publisher = MockViolationEventPublisher()

        assert publisher.aws_clients is None
        assert publisher.published_events == []

    def test_init_with_clients(self):
        """Test mock publisher with AWS clients."""
        mock_clients = MagicMock()
        publisher = MockViolationEventPublisher(mock_clients)

        assert publisher.aws_clients == mock_clients
        assert publisher.published_events == []

    @patch("violation_event.ViolationEvent.create")
    def test_publish_violation_mock(self, mock_create):
        """Test mock publishing."""
        # Setup mocks
        mock_event = MagicMock()
        mock_event.get_rule_name.return_value = "TestRule"
        mock_create.return_value = mock_event

        violation_result = MagicMock()
        cloudtrail_event = {"eventName": "PutUserPolicy"}

        # Test mock publishing
        publisher = MockViolationEventPublisher()
        result = publisher.publish_violation(violation_result, cloudtrail_event)

        # Verify success and storage
        assert result is True
        assert len(publisher.published_events) == 1
        assert publisher.published_events[0] == mock_event
        mock_create.assert_called_once_with(violation_result, cloudtrail_event)

    def test_multiple_publications(self):
        """Test publishing multiple events."""
        publisher = MockViolationEventPublisher()

        # Publish multiple events
        for i in range(3):
            violation_result = MagicMock()
            cloudtrail_event = {"eventName": f"Event{i}"}
            result = publisher.publish_violation(violation_result, cloudtrail_event)
            assert result is True

        # Verify all events stored
        assert len(publisher.published_events) == 3


if __name__ == "__main__":
    pytest.main([__file__])
