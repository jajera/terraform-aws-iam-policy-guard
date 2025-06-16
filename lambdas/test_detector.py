#!/usr/bin/env python3
"""Unit tests for IAM Policy Violation Detector."""

import json
from typing import Any
from unittest.mock import Mock, patch

import pytest
import yaml

from detector import (
    AWSClientInterface,
    BedrockAnalysisResult,
    DetectorConfig,
    PolicyViolationDetector,
    ViolationResult,
    create_sample_event,
    lambda_handler,
)


class MockAWSClients(AWSClientInterface):
    """Mock AWS clients for testing."""

    def __init__(self) -> None:
        """Initialize mock AWS clients."""
        self.s3_objects: dict[str, str] = {}
        self.sns_messages: list[dict[str, Any]] = []
        self.sqs_messages: list[dict[str, Any]] = []
        self.metrics: list[dict[str, Any]] = []

    def get_object(self, **kwargs: Any) -> Any:
        """Get object from S3."""
        key = kwargs.get("Key", "")
        if key in self.s3_objects:
            content = self.s3_objects[key]
            return {
                "Body": type(
                    "obj", (object,), {"read": lambda: content.encode("utf-8")}
                )
            }
        raise Exception(f"Object not found: {key}")

    def put_object(self, **kwargs: Any) -> Any:
        """Put object in S3."""
        key = kwargs.get("Key", "")
        body = kwargs.get("Body", "")
        self.s3_objects[key] = body
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def publish(self, **kwargs: Any) -> Any:
        """Publish to SNS."""
        self.sns_messages.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def send_message(self, **kwargs: Any) -> Any:
        """Send message to SQS."""
        self.sqs_messages.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_metric_data(self, **kwargs: Any) -> Any:
        """Put metric data."""
        self.metrics.append(kwargs)
        return {"ResponseMetadata": {"HTTPStatusCode": 200}}

    def put_events(self, **kwargs: Any) -> Any:
        """Put events to EventBridge."""
        return {"FailedEntryCount": 0, "Entries": []}

    def get_policy(self, **kwargs: Any) -> Any:
        """Get IAM policy."""
        return {"Policy": {"PolicyName": "TestPolicy"}}

    def get_policy_version(self, **kwargs: Any) -> Any:
        """Get IAM policy version."""
        return {"PolicyVersion": {"Document": "{}"}}

    def invoke_model(self, **kwargs: Any) -> Any:
        """Mock Bedrock invoke_model."""
        # Return a mock response that matches Claude 3 Sonnet format
        mock_analysis = {
            "risk_score": 8,
            "risk_level": "HIGH",
            "summary": "Test analysis: High-risk IAM policy violation for testing.",
            "detailed_analysis": (
                "This is a test analysis response. The violation involves "
                "creating IAM policies with overly permissive permissions."
            ),
            "recommendations": [
                "Restrict policy permissions to minimum required",
                "Implement policy validation before deployment",
                "Regular policy auditing and review",
            ],
            "potential_impact": (
                "Potential for privilege escalation and unauthorized resource access"
            ),
            "confidence": 0.9,
        }

        mock_response = {
            "content": [
                {
                    "text": (
                        f"Analysis complete:\n\n{json.dumps(mock_analysis, indent=2)}"
                    )
                }
            ]
        }

        # Mock the body.read() method
        response_body = json.dumps(mock_response).encode("utf-8")

        def mock_read(*args):
            return response_body

        mock_body = type("MockBody", (), {"read": mock_read})()

        return {"body": mock_body, "ResponseMetadata": {"HTTPStatusCode": 200}}


@pytest.fixture
def mock_config():
    """Test configuration."""
    return DetectorConfig(
        rules_bucket="test-bucket",
        sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        enable_slack_alerts=False,
        slack_webhook_url=None,
        enable_remediation=True,
        sqs_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/test",
        use_eventbridge=False,  # Use direct SNS for testing
        enable_bedrock_analysis=False,
        bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
    )


@pytest.fixture
def bedrock_config():
    """Test configuration with Bedrock enabled."""
    return DetectorConfig(
        rules_bucket="test-bucket",
        sns_topic_arn="arn:aws:sns:us-east-1:123456789012:test-topic",
        enable_slack_alerts=False,
        slack_webhook_url=None,
        enable_remediation=True,
        sqs_queue_url="https://sqs.us-east-1.amazonaws.com/123456789012/test",
        use_eventbridge=False,  # Use direct SNS for testing
        enable_bedrock_analysis=True,
        bedrock_model_id="anthropic.claude-3-sonnet-20240229-v1:0",
    )


@pytest.fixture
def mock_aws_clients():
    """Mock AWS clients."""
    return MockAWSClients()


@pytest.fixture
def sample_rules():
    """Sample rules configuration."""
    return {
        "rules": [
            {
                "name": "DangerousInlinePolicy",
                "description": "Detects dangerous inline policies",
                "severity": "HIGH",
                "action": "alert",
                "conditions": {
                    "event_names": ["PutUserPolicy", "PutRolePolicy"],
                    "conditions": {"policy_document_contains": ['"Action": "*"']},
                },
            },
            {
                "name": "PolicyAttachment",
                "description": "Monitors policy attachments",
                "severity": "MEDIUM",
                "action": "log",
                "conditions": {"event_names": ["AttachUserPolicy", "AttachRolePolicy"]},
            },
        ]
    }


@pytest.fixture
def sample_suppressions():
    """Sample suppression configuration."""
    return {
        "suppressions": [
            {
                "name": "TerraformDeployments",
                "conditions": {
                    "user_agents": ["terraform"],
                    "event_names": ["AttachUserPolicy", "AttachRolePolicy"],
                },
            }
        ]
    }


@pytest.fixture
def detector(mock_config, mock_aws_clients, sample_rules, sample_suppressions):
    """Detector instance with mocked dependencies."""
    mock_aws_clients.s3_objects["rules.yaml"] = yaml.dump(sample_rules)
    mock_aws_clients.s3_objects["suppress.yaml"] = yaml.dump(sample_suppressions)
    return PolicyViolationDetector(mock_config, mock_aws_clients)


class TestDetectorConfig:
    """Test DetectorConfig class."""

    def test_from_env_default_values(self):
        """Test config creation with default environment values."""
        with patch.dict("os.environ", {}, clear=True):
            config = DetectorConfig.from_env()
            assert config.rules_bucket == ""
            assert config.sns_topic_arn is None
            assert config.enable_slack_alerts is False
            assert config.enable_remediation is False
            assert config.enable_bedrock_analysis is False
            expected_model = "anthropic.claude-3-sonnet-20240229-v1:0"
            assert config.bedrock_model_id == expected_model

    def test_from_env_with_values(self):
        """Test config creation with environment values."""
        env_vars = {
            "RULES_BUCKET": "test-bucket",
            "SNS_TOPIC_ARN": "arn:aws:sns:us-east-1:123456789012:test",
            "ENABLE_SLACK_ALERTS": "true",
            "ENABLE_REMEDIATION": "true",
            "SQS_QUEUE_URL": "https://sqs.us-east-1.amazonaws.com/test",
            "ENABLE_BEDROCK_ANALYSIS": "true",
            "BEDROCK_MODEL_ID": "anthropic.claude-v2",
        }
        with patch.dict("os.environ", env_vars):
            config = DetectorConfig.from_env()
            assert config.rules_bucket == "test-bucket"
            assert config.enable_slack_alerts is True
            assert config.enable_remediation is True
            assert config.enable_bedrock_analysis is True
            assert config.bedrock_model_id == "anthropic.claude-v2"

    def test_from_dict(self):
        """Test config creation from dictionary."""
        config_dict = {
            "rules_bucket": "test-bucket",
            "sns_topic_arn": "arn:aws:sns:us-east-1:123456789012:test",
            "enable_bedrock_analysis": True,
            "bedrock_model_id": "anthropic.claude-3-haiku-20240307-v1:0",
        }
        config = DetectorConfig.from_dict(config_dict)
        assert config.rules_bucket == "test-bucket"
        expected_arn = "arn:aws:sns:us-east-1:123456789012:test"
        assert config.sns_topic_arn == expected_arn
        assert config.enable_bedrock_analysis is True
        expected_model = "anthropic.claude-3-haiku-20240307-v1:0"
        assert config.bedrock_model_id == expected_model


class TestViolationResult:
    """Test ViolationResult class."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        result = ViolationResult(
            found=True,
            rule_name="TestRule",
            description="Test description",
            severity="HIGH",
            action="alert",
            timestamp="2023-01-01T12:00:00Z",
            event_name="PutUserPolicy",
            event_source="iam.amazonaws.com",
        )

        result_dict = result.to_dict()
        assert result_dict["rule_name"] == "TestRule"
        assert result_dict["severity"] == "HIGH"
        assert result_dict["suppressed"] is False


class TestPolicyViolationDetector:
    """Test PolicyViolationDetector class."""

    def test_dangerous_policy_detection(self, detector):
        """Test detection of dangerous policies."""
        event = {
            "detail": {
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "requestParameters": {
                    "userName": "test-user",
                    "policyName": "DangerousPolicy",
                    "policyDocument": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ],
                        }
                    ),
                },
                "resources": [],
            }
        }

        result = detector.process_eventbridge_event(event)
        assert result["statusCode"] == 200

        # Check that alert was sent
        assert len(detector.aws_clients.sns_messages) == 1
        sns_message = detector.aws_clients.sns_messages[0]
        assert "DangerousInlinePolicy" in sns_message["Subject"]

        # Check that metrics were sent
        assert len(detector.aws_clients.metrics) == 1

    def test_policy_attachment_logging(self, detector):
        """Test logging of policy attachments."""
        event = {
            "detail": {
                "eventName": "AttachUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "requestParameters": {
                    "userName": "test-user",
                    "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                },
                "resources": [],
            }
        }

        result = detector.process_eventbridge_event(event)
        assert result["statusCode"] == 200

        # Should be logged but not alerted (action is 'log')
        assert len(detector.aws_clients.sns_messages) == 0
        assert len(detector.aws_clients.metrics) == 1

    def test_terraform_suppression(self, detector):
        """Test suppression of Terraform events."""
        event = {
            "detail": {
                "eventName": "AttachUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userAgent": "terraform/1.0.0",
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "requestParameters": {
                    "userName": "test-user",
                    "policyArn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                },
                "resources": [],
            }
        }

        result = detector.process_eventbridge_event(event)
        assert result["statusCode"] == 200

        # Should be suppressed
        assert len(detector.aws_clients.sns_messages) == 0

    def test_dangerous_policy_bypasses_suppression(self, detector):
        """Test that dangerous policies bypass suppression."""
        event = {
            "detail": {
                "eventName": "PutUserPolicy",
                "eventSource": "iam.amazonaws.com",
                "userAgent": "terraform/1.0.0",  # Would normally be suppressed
                "userIdentity": {
                    "type": "IAMUser",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "requestParameters": {
                    "userName": "test-user",
                    "policyName": "DangerousPolicy",
                    "policyDocument": json.dumps(
                        {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Action": "*",
                                    "Resource": "*",
                                }
                            ],
                        }
                    ),
                },
                "resources": [],
            }
        }

        result = detector.process_eventbridge_event(event)
        assert result["statusCode"] == 200

        # Should NOT be suppressed despite Terraform user agent
        assert len(detector.aws_clients.sns_messages) == 1

    def test_extract_policy_document_inline(self, detector):
        """Test extraction of inline policy document."""
        event = {
            "requestParameters": {
                "policyDocument": json.dumps(
                    {
                        "Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "s3:*"}],
                    }
                )
            }
        }

        policy_doc = detector._extract_policy_document(event)
        assert policy_doc is not None
        assert policy_doc["Version"] == "2012-10-17"

    def test_extract_policy_document_arn(self, detector):
        """Test extraction of policy ARN."""
        event = {
            "requestParameters": {
                "policyArn": "arn:aws:iam::aws:policy/PowerUserAccess"
            }
        }

        policy_doc = detector._extract_policy_document(event)
        assert policy_doc is not None
        expected_arn = "arn:aws:iam::aws:policy/PowerUserAccess"
        assert policy_doc["PolicyArn"] == expected_arn

    def test_no_event_detail(self, detector):
        """Test handling of events without detail."""
        event = {"version": "0", "id": "test"}

        result = detector.process_eventbridge_event(event)
        assert result["statusCode"] == 200
        assert "No event detail found" in result["body"]

    def test_slack_alert_disabled(self, detector):
        """Test that Slack alerts are not sent when disabled."""
        detector.config.enable_slack_alerts = False

        violation = ViolationResult(found=True, rule_name="TestRule", severity="HIGH")
        event = {"userIdentity": {"userName": "test-user"}}

        with patch("detector.urlopen") as mock_urlopen:
            detector._send_slack_alert(violation, event)
            mock_urlopen.assert_not_called()

    def test_remediation_queuing(self, detector):
        """Test queuing for remediation."""
        violation = ViolationResult(
            found=True, rule_name="TestRule", action="remediate"
        )
        event = {
            "eventName": "AttachUserPolicy",
            "requestParameters": {"userName": "test-user"},
        }

        detector._queue_for_remediation(violation, event)

        assert len(detector.aws_clients.sqs_messages) == 1
        message = detector.aws_clients.sqs_messages[0]
        message_body = json.loads(message["MessageBody"])
        assert message_body["remediation_action"] == "detach_policy"


class TestLambdaHandler:
    """Test Lambda handler function."""

    @patch("detector.AWSClients")
    @patch("detector.DetectorConfig.from_env")
    def test_lambda_handler_success(self, mock_config, _mock_clients):
        """Test successful Lambda handler execution."""
        mock_config.return_value = DetectorConfig(rules_bucket="test-bucket")
        mock_detector = Mock()
        mock_detector.process_eventbridge_event.return_value = {
            "statusCode": 200,
            "body": "Success",
        }

        with patch("detector.PolicyViolationDetector") as mock_detector_class:
            mock_detector_class.return_value = mock_detector

            event = create_sample_event()
            result = lambda_handler(event, None)

            assert result["statusCode"] == 200
            assert result["body"] == "Success"

    @patch("detector.AWSClients")
    @patch("detector.DetectorConfig.from_env")
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

        assert event["source"] == "aws.iam"
        assert event["detail"]["eventName"] == "PutUserPolicy"
        request_params = event["detail"]["requestParameters"]
        assert "policyDocument" in request_params

        # Verify the policy document contains dangerous permissions
        policy_doc = request_params["policyDocument"]
        assert '"Action":"*"' in policy_doc


class TestBedrockAnalysisResult:
    """Test BedrockAnalysisResult class."""

    def test_to_dict(self):
        """Test conversion to dictionary."""
        analysis = BedrockAnalysisResult(
            risk_score=8,
            risk_level="HIGH",
            summary="High-risk violation detected",
            detailed_analysis="Detailed analysis of the violation",
            recommendations=["Fix this", "Monitor that"],
            potential_impact="Account compromise possible",
            confidence=0.9,
            analysis_timestamp="2023-01-01T12:00:00Z",
        )

        result = analysis.to_dict()
        assert result["risk_score"] == 8
        assert result["risk_level"] == "HIGH"
        assert result["summary"] == "High-risk violation detected"
        assert result["recommendations"] == ["Fix this", "Monitor that"]
        assert result["confidence"] == 0.9


class TestBedrockIntegration:
    """Test Bedrock AI analysis integration."""

    def test_bedrock_analysis_enabled(
        self, bedrock_config, mock_aws_clients, sample_rules, sample_suppressions
    ):
        """Test that Bedrock analysis is performed when enabled."""
        mock_aws_clients.s3_objects["rules.yaml"] = yaml.dump(sample_rules)
        mock_aws_clients.s3_objects["suppress.yaml"] = yaml.dump(sample_suppressions)

        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        # Create an event that will trigger a violation
        event = {
            "eventName": "PutUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"userName": "test-user", "type": "IAMUser"},
            "requestParameters": {
                "userName": "test-user",
                "policyName": "TestPolicy",
                "policyDocument": (
                    '{"Version":"2012-10-17","Statement":'
                    '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
                ),
            },
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "aws-cli/2.0.0",
        }

        violation = detector._check_violations(event, sample_rules)

        assert violation.found is True
        assert violation.bedrock_analysis is not None
        assert violation.bedrock_analysis.risk_score == 8
        assert violation.bedrock_analysis.risk_level == "HIGH"
        assert "test analysis" in violation.bedrock_analysis.summary.lower()

    def test_bedrock_analysis_disabled(
        self, mock_config, mock_aws_clients, sample_rules, sample_suppressions
    ):
        """Test that Bedrock analysis is skipped when disabled."""
        mock_aws_clients.s3_objects["rules.yaml"] = yaml.dump(sample_rules)
        mock_aws_clients.s3_objects["suppress.yaml"] = yaml.dump(sample_suppressions)

        detector = PolicyViolationDetector(mock_config, mock_aws_clients)

        # Create an event that will trigger a violation
        event = {
            "eventName": "PutUserPolicy",
            "eventSource": "iam.amazonaws.com",
            "userIdentity": {"userName": "test-user", "type": "IAMUser"},
            "requestParameters": {
                "userName": "test-user",
                "policyName": "TestPolicy",
                "policyDocument": (
                    '{"Version":"2012-10-17","Statement":'
                    '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
                ),
            },
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "aws-cli/2.0.0",
        }

        violation = detector._check_violations(event, sample_rules)

        assert violation.found is True
        assert violation.bedrock_analysis is None

    def test_bedrock_context_preparation(self, bedrock_config, mock_aws_clients):
        """Test Bedrock context preparation."""
        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        violation = ViolationResult(
            found=True,
            rule_name="TestRule",
            description="Test violation",
            severity="HIGH",
            event_name="PutUserPolicy",
            event_source="iam.amazonaws.com",
        )

        event = {
            "eventName": "PutUserPolicy",
            "userIdentity": {
                "userName": "test-user",
                "arn": "arn:aws:iam::123456789012:user/test-user",
            },
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "aws-cli/2.0.0",
            "requestParameters": {"userName": "test-user"},
        }

        policy_document = {"Version": "2012-10-17", "Statement": []}

        context = detector._prepare_bedrock_context(violation, event, policy_document)

        assert context["violation"]["rule_name"] == "TestRule"
        assert context["event_details"]["user_name"] == "test-user"
        assert context["event_details"]["source_ip"] == "203.0.113.12"
        assert context["policy_document"] == policy_document

    def test_bedrock_prompt_creation(self, bedrock_config, mock_aws_clients):
        """Test Bedrock prompt creation."""
        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        context = {
            "violation": {
                "rule_name": "TestRule",
                "description": "Test violation",
                "severity": "HIGH",
                "event_name": "PutUserPolicy",
                "event_source": "iam.amazonaws.com",
            },
            "event_details": {
                "user_name": "test-user",
                "user_arn": "arn:aws:iam::123456789012:user/test-user",
                "user_type": "IAMUser",
                "source_ip": "203.0.113.12",
                "user_agent": "aws-cli/2.0.0",
                "aws_region": "us-east-1",
                "timestamp": "2023-01-01T12:00:00Z",
            },
            "request_parameters": {},
            "policy_document": None,
        }

        prompt = detector._create_bedrock_prompt(context)

        assert "TestRule" in prompt
        assert "cybersecurity expert" in prompt
        assert "risk_score" in prompt
        assert "recommendations" in prompt

    def test_bedrock_response_parsing(self, bedrock_config, mock_aws_clients):
        """Test Bedrock response parsing."""
        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        # Test valid response
        valid_response = {
            "content": [
                {
                    "text": """Here's my analysis:

{
    "risk_score": 9,
    "risk_level": "CRITICAL",
    "summary": "Critical security violation",
    "detailed_analysis": "This is a critical issue",
    "recommendations": ["Fix immediately", "Review policies"],
    "potential_impact": "Complete account compromise",
    "confidence": 0.95
}"""
                }
            ]
        }

        analysis = detector._parse_bedrock_response(valid_response)

        assert analysis.risk_score == 9
        assert analysis.risk_level == "CRITICAL"
        assert analysis.summary == "Critical security violation"
        assert len(analysis.recommendations) == 2
        assert analysis.confidence == 0.95

    def test_bedrock_response_parsing_invalid(self, bedrock_config, mock_aws_clients):
        """Test Bedrock response parsing with invalid data."""
        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        # Test invalid response (no JSON)
        invalid_response = {"content": [{"text": "No JSON here, just text"}]}

        analysis = detector._parse_bedrock_response(invalid_response)

        # Should return fallback analysis
        assert analysis.risk_score == 5
        assert analysis.risk_level == "MEDIUM"
        assert "failed" in analysis.summary.lower()
        assert analysis.confidence == 0.0

    def test_alert_message_includes_bedrock_analysis(
        self, bedrock_config, mock_aws_clients
    ):
        """Test that alert messages include Bedrock analysis when available."""
        detector = PolicyViolationDetector(bedrock_config, mock_aws_clients)

        # Create violation with Bedrock analysis
        bedrock_analysis = BedrockAnalysisResult(
            risk_score=7,
            risk_level="HIGH",
            summary="High-risk violation",
            detailed_analysis="Detailed analysis",
            recommendations=["Fix this", "Monitor that"],
            potential_impact="Potential compromise",
            confidence=0.8,
            analysis_timestamp="2023-01-01T12:00:00Z",
        )

        violation = ViolationResult(
            found=True,
            rule_name="TestRule",
            description="Test violation",
            severity="HIGH",
            bedrock_analysis=bedrock_analysis,
        )

        event = {
            "userIdentity": {"userName": "test-user"},
            "sourceIPAddress": "203.0.113.12",
            "userAgent": "aws-cli/2.0.0",
            "awsRegion": "us-east-1",
            "resources": [],
        }

        message = detector._format_alert_message(violation, event)

        assert "🤖 AI Risk Analysis:" in message
        assert "Risk Score: 7/10 (HIGH)" in message
        assert "High-risk violation" in message
        assert "Fix this" in message
        assert "Monitor that" in message

    def test_violation_result_with_bedrock_analysis_to_dict(self):
        """Test ViolationResult.to_dict() includes Bedrock analysis."""
        bedrock_analysis = BedrockAnalysisResult(
            risk_score=6,
            risk_level="MEDIUM",
            summary="Medium risk",
            detailed_analysis="Analysis details",
            recommendations=["Recommendation 1"],
            potential_impact="Limited impact",
            confidence=0.7,
            analysis_timestamp="2023-01-01T12:00:00Z",
        )

        violation = ViolationResult(
            found=True,
            rule_name="TestRule",
            bedrock_analysis=bedrock_analysis,
        )

        result_dict = violation.to_dict()

        assert "bedrock_analysis" in result_dict
        assert result_dict["bedrock_analysis"]["risk_score"] == 6
        assert result_dict["bedrock_analysis"]["risk_level"] == "MEDIUM"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
