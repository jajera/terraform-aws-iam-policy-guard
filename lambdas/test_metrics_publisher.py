#!/usr/bin/env python3
"""Unit tests for metrics_publisher module."""

import os
from unittest.mock import MagicMock, patch

from metrics_publisher import (
    MetricsPublisher,
    MockMetricsPublisher,
    lambda_handler,
)

import pytest

from violation_event import ViolationEvent


class TestMetricsPublisher:
    """Test MetricsPublisher class."""

    def test_init(self):
        """Test publisher initialization."""
        namespace = "IAM/PolicyMonitor"
        mock_clients = MagicMock()

        publisher = MetricsPublisher(namespace, mock_clients)

        assert publisher.namespace == namespace
        assert publisher.cloudwatch == mock_clients

    def test_init_without_clients(self):
        """Test publisher initialization without AWS clients."""
        namespace = "IAM/PolicyMonitor"

        with patch("metrics_publisher.boto3") as mock_boto3:
            mock_cloudwatch = MagicMock()
            mock_boto3.client.return_value = mock_cloudwatch

            publisher = MetricsPublisher(namespace)

            assert publisher.namespace == namespace
            assert publisher.cloudwatch == mock_cloudwatch
            mock_boto3.client.assert_called_once_with("cloudwatch")

    def test_publish_violation_metrics_success(self):
        """Test successful metrics publishing."""
        namespace = "IAM/PolicyMonitor"
        mock_clients = MagicMock()
        mock_clients.put_metric_data.return_value = {
            "ResponseMetadata": {"HTTPStatusCode": 200}
        }

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={
                "rule_name": "TestRule",
                "severity": "HIGH",
                "description": "Test violation",
                "risk_score": 8.5,
                "category": "Policy",
            },
            original_event={
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {"type": "IAMUser", "userName": "test-user"},
                "awsRegion": "us-east-1",
                "sourceIPAddress": "203.0.113.1",
                "resources": [{"accountId": "123456789012"}],
            },
            correlation_id="test-correlation",
        )

        publisher = MetricsPublisher(namespace, mock_clients)
        result = publisher.publish_violation_metrics(violation_event)

        assert result is True
        mock_clients.put_metric_data.assert_called_once()
        call_args = mock_clients.put_metric_data.call_args
        assert call_args[1]["Namespace"] == namespace
        assert len(call_args[1]["MetricData"]) > 0

    def test_publish_violation_metrics_failure(self):
        """Test metrics publishing failure."""
        namespace = "IAM/PolicyMonitor"
        mock_clients = MagicMock()
        mock_clients.put_metric_data.side_effect = Exception("CloudWatch error")

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        publisher = MetricsPublisher(namespace, mock_clients)
        result = publisher.publish_violation_metrics(violation_event)

        assert result is False

    def test_build_metric_data(self):
        """Test metric data building."""
        namespace = "IAM/PolicyMonitor"
        mock_clients = MagicMock()

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={
                "rule_name": "DangerousPolicy",
                "severity": "CRITICAL",
                "risk_score": 9.5,
                "category": "Permission",
            },
            original_event={
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {"type": "IAMUser", "userName": "test-user"},
                "awsRegion": "us-west-2",
                "sourceIPAddress": "198.51.100.1",
                "resources": [{"accountId": "123456789012"}],
            },
            correlation_id="test-correlation",
        )

        publisher = MetricsPublisher(namespace, mock_clients)
        metric_data = publisher._build_metric_data(violation_event)

        # Verify we have expected metrics
        metric_names = [metric["MetricName"] for metric in metric_data]
        expected_metrics = [
            "ViolationCount",
            "ViolationsBySeverity",
            "ViolationsByEvent",
            "ViolationsByUser",
            "RiskScore",
            "ViolationsByAccount",
            "ViolationsByIP",
            "ViolationsByCategory",
        ]

        # Check that at least some expected metrics are present
        assert any(metric in metric_names for metric in expected_metrics)

        # Verify specific metric data
        violation_count_metric = next(
            (m for m in metric_data if m["MetricName"] == "ViolationCount"),
            None,
        )
        assert violation_count_metric is not None
        assert violation_count_metric["Value"] == 1
        assert violation_count_metric["Unit"] == "Count"

        # Verify dimensions exist
        assert len(violation_count_metric["Dimensions"]) > 0

        # Check for expected dimension names
        dimension_names = [d["Name"] for d in violation_count_metric["Dimensions"]]
        assert "Rule" in dimension_names
        assert "Severity" in dimension_names


class TestMockMetricsPublisher:
    """Test MockMetricsPublisher class."""

    def test_init(self):
        """Test mock publisher initialization."""
        namespace = "IAM/PolicyMonitor"

        publisher = MockMetricsPublisher(namespace)

        assert publisher.namespace == namespace
        assert publisher.published_metrics == []

    def test_publish_violation_metrics_mock(self):
        """Test mock metrics publishing."""
        namespace = "IAM/PolicyMonitor"

        violation_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={"rule_name": "TestRule", "severity": "HIGH"},
            original_event={},
            correlation_id="test-correlation",
        )

        publisher = MockMetricsPublisher(namespace)
        result = publisher.publish_violation_metrics(violation_event)

        assert result is True
        assert len(publisher.published_metrics) == 1

        metrics_batch = publisher.published_metrics[0]
        assert metrics_batch["namespace"] == namespace
        assert len(metrics_batch["metric_data"]) > 0

    def test_multiple_metrics(self):
        """Test publishing multiple metric batches."""
        namespace = "IAM/PolicyMonitor"
        publisher = MockMetricsPublisher(namespace)

        # Publish multiple metric batches
        for i in range(3):
            violation_event = ViolationEvent(
                event_id=f"test-event-{i}",
                timestamp="2024-01-01T12:00:00Z",
                violation={"rule_name": f"Rule{i}", "severity": "MEDIUM"},
                original_event={},
                correlation_id=f"test-correlation-{i}",
            )
            result = publisher.publish_violation_metrics(violation_event)
            assert result is True

        assert len(publisher.published_metrics) == 3


class TestLambdaHandler:
    """Test Lambda handler function."""

    @patch.dict(os.environ, {"METRICS_NAMESPACE": "IAM/PolicyMonitor"})
    @patch("metrics_publisher.MetricsPublisher")
    def test_lambda_handler_success(self, mock_publisher_class):
        """Test successful Lambda handler execution."""
        # Setup mock publisher
        mock_publisher = MagicMock()
        mock_publisher.publish_violation_metrics.return_value = True
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
        mock_publisher.publish_violation_metrics.assert_called_once()

    @patch.dict(os.environ, {"METRICS_NAMESPACE": "IAM/PolicyMonitor"})
    @patch("metrics_publisher.MetricsPublisher")
    def test_lambda_handler_failure(self, mock_publisher_class):
        """Test Lambda handler with publishing failure."""
        # Setup mock publisher
        mock_publisher = MagicMock()
        mock_publisher.publish_violation_metrics.return_value = False
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

    @patch.dict(os.environ, {}, clear=True)  # Clear all env vars
    def test_lambda_handler_missing_env_var(self):
        """Test Lambda handler with missing environment variable."""
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
        assert "You must specify a region" in result["body"]

    @patch.dict(os.environ, {"METRICS_NAMESPACE": "IAM/PolicyMonitor"})
    @patch("metrics_publisher.MetricsPublisher")
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

    def test_edge_cases(self):
        """Test edge cases and error handling."""
        namespace = "IAM/PolicyMonitor"
        mock_clients = MagicMock()
        publisher = MetricsPublisher(namespace, mock_clients)

        # Test with minimal violation event
        minimal_event = ViolationEvent(
            event_id="test-event-id",
            timestamp="2024-01-01T12:00:00Z",
            violation={},
            original_event={},
            correlation_id="test-correlation",
        )

        metric_data = publisher._build_metric_data(minimal_event)

        # Should still generate basic metrics
        assert len(metric_data) > 0

        # Verify default values are used
        violation_count_metric = next(
            (m for m in metric_data if m["MetricName"] == "ViolationCount"),
            None,
        )
        assert violation_count_metric is not None


if __name__ == "__main__":
    pytest.main([__file__])
