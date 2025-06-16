#!/usr/bin/env python3
"""Unit tests for IAM Policy Violation Remediator."""

import json
from io import BytesIO
from typing import Any
from unittest.mock import Mock, patch

import pytest
from remediator import (
    AWSClientInterface,
    PolicyRemediator,
    RemediationConfig,
    RemediationResult,
    create_sample_event,
    lambda_handler,
)


class MockAWSClients(AWSClientInterface):
    """Mock AWS clients for testing."""

    def __init__(self) -> None:
        """Initialize mock AWS clients."""
        self.detached_policies: list[tuple[str, dict[str, Any]]] = []
        self.deleted_policies: list[dict[str, Any]] = []
        self.deleted_user_policies: list[dict[str, Any]] = []
        self.deleted_role_policies: list[dict[str, Any]] = []
        self.detached_group_policies: list[dict[str, Any]] = []
        self.s3_objects: dict[str, str] = {}
        self.sns_messages: list[dict[str, Any]] = []
        self.metrics: list[dict[str, Any]] = []
        self.policy_responses: dict[str, dict[str, Any]] = {}
        # Allow tests to override config
        self.mock_config = {
            "dry_run": False,  # Default to not dry_run for most tests
            "allowed_actions": [
                "detach_policy",
                "delete_policy",
                "delete_inline_policy",
            ],
        }

    def detach_user_policy(self, **kwargs: Any) -> Any:
        """Detach user policy."""
        self.detached_policies.append(("user", kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def detach_role_policy(self, **kwargs: Any) -> Any:
        """Detach role policy."""
        self.detached_policies.append(("role", kwargs))
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_policy(self, **kwargs: Any) -> Any:
        """Delete policy."""
        self.deleted_policies.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_user_policy(self, **kwargs: Any) -> Any:
        """Delete user policy."""
        self.deleted_user_policies.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def delete_role_policy(self, **kwargs: Any) -> Any:
        """Delete role policy."""
        self.deleted_role_policies.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_policy(self, **kwargs: Any) -> Any:
        """Get policy."""
        policy_arn = kwargs.get("PolicyArn")
        if policy_arn in self.policy_responses:
            return self.policy_responses[policy_arn]
        return {"Policy": {"PolicyName": "test-policy", "AttachmentCount": 1}}

    def list_policy_versions(self, **_kwargs: Any) -> Any:
        """List policy versions."""
        return {
            "Versions": [
                {"VersionId": "v1", "IsDefaultVersion": True},
                {"VersionId": "v2", "IsDefaultVersion": False},
            ]
        }

    def delete_policy_version(self, **_kwargs: Any) -> Any:
        """Delete policy version."""
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def get_object(self, **kwargs: Any) -> Any:
        """Get object from S3."""
        key = kwargs.get("Key", "")
        if key == "remediator-config.json":
            mock_config = json.dumps(self.mock_config)
            return {"Body": BytesIO(mock_config.encode("utf-8"))}
        return {"Body": BytesIO(b"{}")}

    def put_object(self, **kwargs: Any) -> Any:
        """Put object."""
        key = kwargs.get("Key", "")
        body = kwargs.get("Body", "")
        self.s3_objects[key] = body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def publish(self, **kwargs: Any) -> Any:
        """Publish to SNS."""
        self.sns_messages.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data."""
        self.metrics.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def detach_group_policy(self, **kwargs: Any) -> Any:
        """Mock detach group policy."""
        self.detached_group_policies.append(kwargs)
        return {}

    def list_entities_for_policy(self, **kwargs: Any) -> Any:
        """Mock list entities for policy - return empty list."""
        return {"PolicyGroups": [], "PolicyUsers": [], "PolicyRoles": []}


@pytest.fixture
def mock_config():
    """Test configuration."""
    return RemediationConfig(
        rules_bucket="test-bucket",
        sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        allowed_actions=[
            "detach_policy",
            "delete_policy",
            "delete_inline_policy",
        ],
        dry_run=False,
    )


@pytest.fixture
def mock_aws_clients():
    """Mock AWS clients."""
    return MockAWSClients()


@pytest.fixture
def remediator(mock_config, mock_aws_clients):
    """Remediator instance with mocked dependencies."""
    return PolicyRemediator(mock_config, mock_aws_clients)


class TestRemediationConfig:
    """Test RemediationConfig class."""

    def test_from_env_default_values(self):
        """Test config creation with default environment values."""
        with patch.dict("os.environ", {}, clear=True):
            config = RemediationConfig.from_env()
            assert config.rules_bucket == ""
            assert config.sns_topic_arn is None
            assert config.allowed_actions == []
            assert config.dry_run is False

    def test_from_env_with_values(self):
        """Test config creation with environment values."""
        env_vars = {
            "RULES_BUCKET": "test-bucket",
            "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test",
            "ALLOWED_ACTIONS": '["detach_policy", "delete_policy"]',
            "DRY_RUN": "true",
        }
        with patch.dict("os.environ", env_vars):
            config = RemediationConfig.from_env()
            assert config.rules_bucket == "test-bucket"
            assert config.allowed_actions == ["detach_policy", "delete_policy"]
            assert config.dry_run is True

    def test_from_dict(self):
        """Test config creation from dictionary."""
        config_dict = {
            "rules_bucket": "test-bucket",
            "allowed_actions": ["detach_policy"],
            "dry_run": True,
        }
        config = RemediationConfig.from_dict(config_dict)
        assert config.rules_bucket == "test-bucket"
        assert config.allowed_actions == ["detach_policy"]
        assert config.dry_run is True


class TestRemediationResult:
    """Test RemediationResult class."""

    def test_initialization(self):
        """Test RemediationResult initialization."""
        details = {"action": "detach_policy", "user": "test-user"}
        result = RemediationResult(True, details, None)

        assert result.success is True
        assert result.details == details
        assert result.error is None
        assert result.timestamp is not None

    def test_with_error(self):
        """Test RemediationResult with error."""
        result = RemediationResult(False, {}, "Test error")

        assert result.success is False
        assert result.error == "Test error"


class TestPolicyRemediator:
    """Test PolicyRemediator class."""

    def test_detach_user_policy(self, remediator):
        """Test detaching policy from user."""
        event = {
            "eventName": "AttachUserPolicy",
            "requestParameters": {
                "userName": "test-user",
                "policyArn": "arn:aws:iam::123456789012:policy/test-policy",
            },
        }

        result = remediator._detach_policy(event)

        assert result.success is True
        assert result.details["action"] == "detach_user_policy"
        assert result.details["user_name"] == "test-user"

        # Verify AWS call was made
        assert len(remediator.aws_clients.detached_policies) == 1
        detach_type, kwargs = remediator.aws_clients.detached_policies[0]
        assert detach_type == "user"
        assert kwargs["UserName"] == "test-user"

    def test_detach_role_policy(self, remediator):
        """Test detaching policy from role."""
        event = {
            "eventName": "AttachRolePolicy",
            "requestParameters": {
                "roleName": "test-role",
                "policyArn": "arn:aws:iam::123456789012:policy/test-policy",
            },
        }

        result = remediator._detach_policy(event)

        assert result.success is True
        assert result.details["action"] == "detach_role_policy"
        assert result.details["role_name"] == "test-role"

        # Verify AWS call was made
        assert len(remediator.aws_clients.detached_policies) == 1
        detach_type, kwargs = remediator.aws_clients.detached_policies[0]
        assert detach_type == "role"
        assert kwargs["RoleName"] == "test-role"

    def test_delete_policy(self, remediator):
        """Test deleting IAM policy."""
        event = {
            "requestParameters": {"policyName": "test-policy"},
            "recipientAccountId": "123456789012",
        }

        result = remediator._delete_policy(event)

        assert result.success is True
        assert result.details["action"] == "delete_policy"
        assert result.details["policy_name"] == "test-policy"

        # Verify AWS calls were made
        assert len(remediator.aws_clients.deleted_policies) == 1

    def test_delete_user_inline_policy(self, remediator):
        """Test deleting user inline policy."""
        event = {
            "eventName": "PutUserPolicy",
            "requestParameters": {
                "userName": "test-user",
                "policyName": "inline-policy",
            },
        }

        result = remediator._delete_inline_policy(event)

        assert result.success is True
        assert result.details["action"] == "delete_user_policy"
        assert result.details["user_name"] == "test-user"

        # Verify AWS call was made
        assert len(remediator.aws_clients.deleted_user_policies) == 1
        kwargs = remediator.aws_clients.deleted_user_policies[0]
        assert kwargs["UserName"] == "test-user"
        assert kwargs["PolicyName"] == "inline-policy"

    def test_delete_role_inline_policy(self, remediator):
        """Test deleting role inline policy."""
        event = {
            "eventName": "PutRolePolicy",
            "requestParameters": {
                "roleName": "test-role",
                "policyName": "inline-policy",
            },
        }

        result = remediator._delete_inline_policy(event)

        assert result.success is True
        assert result.details["action"] == "delete_role_policy"
        assert result.details["role_name"] == "test-role"

        # Verify AWS call was made
        assert len(remediator.aws_clients.deleted_role_policies) == 1
        kwargs = remediator.aws_clients.deleted_role_policies[0]
        assert kwargs["RoleName"] == "test-role"
        assert kwargs["PolicyName"] == "inline-policy"

    def test_dry_run_mode(self, remediator):
        """Test dry run mode."""
        # Configure mock for dry_run mode
        remediator.aws_clients.mock_config = {
            "dry_run": True,
            "allowed_actions": [
                "detach_policy",
                "delete_policy",
                "delete_inline_policy",
            ],
        }
        # Force reload of config
        remediator.remediator_config = remediator._load_config_from_s3(
            "remediator-config.json"
        )

        message = {
            "violation": {"rule_name": "test-rule"},
            "event": {"eventName": "AttachUserPolicy"},
            "remediation_action": "detach_policy",
        }

        result = remediator.process_remediation_message(message)

        assert result.success is True
        assert result.details["dry_run"] is True

        # No actual AWS calls should be made
        assert len(remediator.aws_clients.detached_policies) == 0

    def test_action_not_allowed(self, remediator):
        """Test handling of non-allowed actions."""
        # Configure mock to only allow detach_policy
        remediator.aws_clients.mock_config = {
            "dry_run": False,
            "allowed_actions": ["detach_policy"],
        }
        # Force reload of config
        remediator.remediator_config = remediator._load_config_from_s3(
            "remediator-config.json"
        )

        message = {
            "violation": {"rule_name": "test-rule"},
            "event": {"eventName": "CreatePolicy"},
            "remediation_action": "delete_policy",  # Not allowed
        }

        result = remediator.process_remediation_message(message)

        assert result.success is False
        assert result.details["reason"] == "action_not_allowed"

    def test_safety_check_root_user(self, remediator):
        """Test safety check prevents remediation for root user."""
        message = {
            "violation": {"rule_name": "test-rule"},
            "event": {
                "eventName": "AttachUserPolicy",
                "userIdentity": {"type": "Root"},
            },
            "remediation_action": "detach_policy",
        }

        result = remediator.process_remediation_message(message)

        assert result.success is False
        assert result.details["reason"] == "safety_check_failed"

    def test_safety_check_critical_role(self, remediator):
        """Test safety check prevents remediation for critical roles."""
        message = {
            "violation": {"rule_name": "test-rule"},
            "event": {
                "eventName": "AttachRolePolicy",
                "userIdentity": {"type": "IAMUser"},
                "requestParameters": {"roleName": "OrganizationAccountAccessRole"},
            },
            "remediation_action": "detach_policy",
        }

        result = remediator.process_remediation_message(message)

        assert result.success is False
        assert result.details["reason"] == "safety_check_failed"

    def test_sqs_event_processing(self, remediator):
        """Test processing SQS event with multiple records."""
        event = {
            "Records": [
                {
                    "eventSource": "aws:sqs",
                    "body": json.dumps(
                        {
                            "violation": {"rule_name": "test-rule-1"},
                            "event": {
                                "eventName": "AttachUserPolicy",
                                "userIdentity": {"type": "IAMUser"},
                                "requestParameters": {
                                    "userName": "test-user",
                                    "policyArn": (
                                        "arn:aws:iam::123456789012:policy/test"
                                    ),
                                },
                            },
                            "remediation_action": "detach_policy",
                        }
                    ),
                },
                {
                    "eventSource": "aws:sqs",
                    "body": json.dumps(
                        {
                            "violation": {"rule_name": "test-rule-2"},
                            "event": {
                                "eventName": "PutUserPolicy",
                                "userIdentity": {"type": "IAMUser"},
                                "requestParameters": {
                                    "userName": "test-user",
                                    "policyName": "inline-policy",
                                },
                            },
                            "remediation_action": "delete_inline_policy",
                        }
                    ),
                },
            ]
        }

        result = remediator.process_sqs_event(event)

        assert result["statusCode"] == 200
        assert "Processed 2 messages" in result["body"]
        assert len(result["results"]) == 2

        # Verify both remediation's were performed
        assert len(remediator.aws_clients.detached_policies) == 1
        assert len(remediator.aws_clients.deleted_user_policies) == 1

    def test_notification_sending(self, remediator):
        """Test sending remediation notifications."""
        violation = {"rule_name": "test-rule", "severity": "HIGH"}
        action = "detach_policy"
        result = RemediationResult(True, {"action": "detach_policy"})

        remediator._send_notification(violation, action, result)

        assert len(remediator.aws_clients.sns_messages) == 1
        message = remediator.aws_clients.sns_messages[0]
        assert "IAM Policy Remediation SUCCESS" in message["Subject"]
        assert "test-rule" in message["Subject"]

    def test_s3_logging(self, remediator):
        """Test logging remediation results to S3."""
        violation = {"rule_name": "test-rule"}
        event = {"eventName": "AttachUserPolicy"}
        action = "detach_policy"
        result = RemediationResult(True, {"action": "detach_policy"})

        remediator._log_remediation_result(violation, event, action, result)

        # Check that log was written to S3
        assert len(remediator.aws_clients.s3_objects) == 1
        s3_key = next(iter(remediator.aws_clients.s3_objects.keys()))
        assert "remediation" in s3_key
        assert "test-rule" in s3_key

        # Verify log content
        log_content = remediator.aws_clients.s3_objects[s3_key]
        log_data = json.loads(log_content)
        assert log_data["violation"]["rule_name"] == "test-rule"
        assert log_data["remediation_action"] == "detach_policy"

    def test_metrics_sending(self, remediator):
        """Test sending CloudWatch metrics."""
        remediator._send_metric("TestMetric", 1.0)

        assert len(remediator.aws_clients.metrics) == 1
        metric = remediator.aws_clients.metrics[0]
        assert metric["Namespace"] == "IAMPolicyMonitor"
        assert metric["MetricData"][0]["MetricName"] == "TestMetric"
        assert metric["MetricData"][0]["Value"] == 1.0

    def test_invalid_sqs_record(self, remediator):
        """Test handling of invalid SQS records."""
        event = {"Records": [{"eventSource": "aws:sqs", "body": "invalid json"}]}

        result = remediator.process_sqs_event(event)

        assert result["statusCode"] == 500
        assert len(result["results"]) == 1
        assert result["results"][0]["success"] is False


class TestLambdaHandler:
    """Test Lambda handler function."""

    @patch("remediator.AWSClients")
    @patch("remediator.RemediationConfig.from_env")
    def test_lambda_handler_success(self, mock_config, _mock_clients):
        """Test successful Lambda handler execution."""
        mock_config.return_value = RemediationConfig(
            rules_bucket="test-bucket", allowed_actions=["detach_policy"]
        )
        mock_remediator = Mock()
        mock_remediator.process_sqs_event.return_value = {
            "statusCode": 200,
            "body": "Success",
        }

        with patch("remediator.PolicyRemediator") as mock_remediator_class:
            mock_remediator_class.return_value = mock_remediator

            event = create_sample_event()
            result = lambda_handler(event, None)

            assert result["statusCode"] == 200
            assert result["body"] == "Success"

    @patch("remediator.AWSClients")
    @patch("remediator.RemediationConfig.from_env")
    def test_lambda_handler_error(self, mock_config, _mock_clients):
        """Test Lambda handler error handling."""
        mock_config.side_effect = Exception("Test error")

        event = create_sample_event()
        result = lambda_handler(event, None)

        assert result["statusCode"] == 500
        assert "Test error" in result["body"]


class TestUtilityFunctions:
    """Test utility functions."""

    def test_create_sample_event(self):
        """Test sample event creation."""
        event = create_sample_event()

        assert len(event["Records"]) == 1
        record = event["Records"][0]
        assert record["eventSource"] == "aws:sqs"

        body = json.loads(record["body"])
        assert body["violation"]["rule_name"] == "test_rule"
        assert body["remediation_action"] == "detach_policy"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
