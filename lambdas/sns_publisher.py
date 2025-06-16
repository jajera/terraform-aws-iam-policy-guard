#!/usr/bin/env python3
"""SNS Publisher Lambda Handler.

This Lambda function receives IAM policy violation events from EventBridge
and publishes formatted alerts to SNS topics.
"""

import json
import logging
import os
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


class SNSPublisher:
    """Publishes IAM violation alerts to SNS."""

    def __init__(self, topic_arn: str, aws_clients: Any = None) -> None:
        """Initialize SNS publisher.

        Args:
            topic_arn: SNS topic ARN for publishing alerts
            aws_clients: Optional AWS clients (for dependency injection)
        """
        self.topic_arn = topic_arn
        self.logger = setup_logging()

        if aws_clients:
            self.sns = aws_clients
        else:
            self.sns = boto3.client("sns")

    def publish_violation_alert(self, violation_event: ViolationEvent) -> bool:
        """Publish violation alert to SNS.

        Args:
            violation_event: Violation event from EventBridge

        Returns:
            bool: True if published successfully
        """
        try:
            # Format alert message
            subject = self._format_subject(violation_event)
            message = self._format_message(violation_event)

            # Publish to SNS
            response = self.sns.publish(
                TopicArn=self.topic_arn, Subject=subject, Message=message
            )

            message_id = response.get("MessageId")
            self.logger.info(f"SNS alert published successfully: {message_id}")
            return True

        except Exception as e:
            self.logger.error(f"Failed to publish SNS alert: {e!s}", exc_info=True)
            return False

    def _format_subject(self, violation_event: ViolationEvent) -> str:
        """Format SNS subject line."""
        severity = violation_event.get_severity()
        rule_name = violation_event.get_rule_name()
        return f"IAM Policy Violation - {severity}: {rule_name}"

    def _format_message(self, violation_event: ViolationEvent) -> str:
        """Format detailed SNS message body with IAM specifics."""
        violation = violation_event.violation
        original_event = violation_event.original_event
        user_identity = violation_event.get_user_identity()

        # Extract detailed IAM information
        event_name = violation.get("event_name", "Unknown")
        request_params = original_event.get("requestParameters", {})
        response_elements = original_event.get("responseElements", {})

        message = f"""
🚨 IAM POLICY VIOLATION DETECTED 🚨

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
VIOLATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule: {violation.get("rule_name", "Unknown")}
Severity: {violation.get("severity", "Unknown")} ⚠️
Description: {violation.get("description", "N/A")}
Action Triggered: {violation.get("action", "alert")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHO PERFORMED THE ACTION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
User Identity: {user_identity.get("type", "Unknown")}
User Name: {user_identity.get("userName", "Unknown")}
User ARN: {user_identity.get("arn", "Unknown")}
Access Key ID: {user_identity.get("accessKeyId", "Unknown")}
Session Context: {user_identity.get("sessionContext", {}).get("sessionIssuer", {}).get("type", "N/A")}
Principal ID: {user_identity.get("principalId", "Unknown")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WHAT ACTION WAS PERFORMED
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Event Name: {event_name}
Event Source: {violation.get("event_source", "Unknown")}
Event Time: {violation.get("timestamp", "Unknown")}
AWS Region: {original_event.get("awsRegion", "Unknown")}
Source IP: {original_event.get("sourceIPAddress", "Unknown")}
User Agent: {original_event.get("userAgent", "Unknown")}"""

        # Add IAM-specific details based on event type
        if event_name in ["AttachUserPolicy", "AttachRolePolicy"]:
            policy_arn = request_params.get("policyArn", "Unknown")
            target_name = request_params.get("userName") or request_params.get(
                "roleName", "Unknown"
            )
            target_type = "User" if "userName" in request_params else "Role"

            message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POLICY ATTACHMENT DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target {target_type}: {target_name}
Policy ARN: {policy_arn}
Policy Type: {"AWS Managed" if "aws:policy" in policy_arn else "Customer Managed"}"""

        elif event_name in ["PutUserPolicy", "PutRolePolicy"]:
            policy_name = request_params.get("policyName", "Unknown")
            target_name = request_params.get("userName") or request_params.get(
                "roleName", "Unknown"
            )
            target_type = "User" if "userName" in request_params else "Role"
            policy_document = request_params.get("policyDocument", "Not available")

            message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
INLINE POLICY CREATION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Target {target_type}: {target_name}
Policy Name: {policy_name}
Policy Document: {policy_document}"""

        elif event_name == "CreatePolicy":
            policy_name = request_params.get("policyName", "Unknown")
            policy_document = request_params.get("policyDocument", "Not available")
            policy_arn = response_elements.get("policy", {}).get("arn", "Unknown")

            message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
MANAGED POLICY CREATION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Policy Name: {policy_name}
Policy ARN: {policy_arn}
Policy Document: {policy_document}"""

        # Add resource information
        resources = original_event.get("resources", [])
        if resources:
            message += """

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
AFFECTED RESOURCES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for resource in resources:
                resource_type = resource.get("type", "Unknown")
                resource_arn = resource.get("ARN", "Unknown")
                message += f"\n• {resource_type}: {resource_arn}"

        # Add request parameters details
        if request_params:
            message += """

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REQUEST PARAMETERS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""
            for key, value in request_params.items():
                if key not in ["policyDocument"]:  # Skip policy doc as it's shown above
                    message += f"\n• {key}: {value}"

        # Add correlation information
        if violation_event.correlation_id:
            message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRACKING INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Correlation ID: {violation_event.correlation_id}
Event ID: {original_event.get("eventID", "Unknown")}"""

        message += (
            "\n\n⚠️  IMMEDIATE ATTENTION REQUIRED - Review and take appropriate action"
        )

        # Add Bedrock AI risk analysis if available
        bedrock_analysis = violation.get("bedrock_analysis")
        if bedrock_analysis:
            risk_score = bedrock_analysis.get("risk_score", "Unknown")
            risk_level = bedrock_analysis.get("risk_level", "Unknown")
            summary = bedrock_analysis.get("summary", "Not available")
            potential_impact = bedrock_analysis.get("potential_impact", "Not assessed")
            confidence = bedrock_analysis.get("confidence", 0.0)
            recommendations = bedrock_analysis.get("recommendations", [])

            message += f"""

🤖 AI RISK ANALYSIS 🤖
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Risk Score: {risk_score}/10 ({risk_level})
Summary: {summary}
Potential Impact: {potential_impact}
Confidence: {confidence:.2f}

Recommendations:"""
            for i, rec in enumerate(recommendations, 1):
                message += f"\n  {i}. {rec}"

        return message


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for SNS publishing.

    Args:
        event: EventBridge event containing violation or remediation details
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
        # Get SNS topic from environment
        topic_arn = os.environ.get("SNS_TOPIC_ARN")
        if not topic_arn:
            logger.error("SNS_TOPIC_ARN environment variable not set")
            return {"statusCode": 400, "body": "SNS topic not configured"}

        # Determine event type and process accordingly
        detail_type = event.get("detail-type", "")
        detail = event.get("detail", {})

        if detail_type == "IAM Policy Violation":
            # Handle violation events
            violation_event = ViolationEvent.from_eventbridge_event(event)
            logger.info(
                f"Processing violation event: {violation_event.get_rule_name()} "
                f"(Severity: {violation_event.get_severity()})"
            )

            publisher = SNSPublisher(topic_arn)
            success = publisher.publish_violation_alert(violation_event)
            correlation_id = violation_event.correlation_id

        elif detail_type == "IAM Policy Remediation Status":
            # Handle remediation status events
            remediation = detail.get("remediation", {})
            rule_name = remediation.get("rule_name", "Unknown")
            status = remediation.get("status", "Unknown")

            logger.info(f"Processing remediation event: {rule_name} (Status: {status})")

            # Format remediation notification
            subject = f"IAM Policy Remediation {status}: {rule_name}"
            message = _format_remediation_message(detail)

            # Create publisher and send notification
            publisher = SNSPublisher(topic_arn)
            try:
                response = publisher.sns.publish(
                    TopicArn=topic_arn, Subject=subject, Message=message
                )
                message_id = response.get("MessageId")
                logger.info(f"Remediation SNS alert published: {message_id}")
                success = True
            except Exception as e:
                logger.error(f"Failed to publish remediation alert: {e!s}")
                success = False

            correlation_id = detail.get("correlationId")

        else:
            logger.error(f"Unknown event type: {detail_type}")
            return {
                "statusCode": 400,
                "body": f"Unsupported event type: {detail_type}",
            }

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "SNS alert published successfully",
                        "correlationId": correlation_id,
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to publish SNS alert",
                        "correlationId": correlation_id,
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in SNS publisher handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


def _format_remediation_message(detail: dict[str, Any]) -> str:
    """Format detailed remediation status message for SNS.

    Args:
        detail: EventBridge event detail containing remediation info

    Returns:
        str: Formatted message for SNS
    """
    remediation = detail.get("remediation", {})
    original_event = detail.get("originalEvent", {})
    original_violation = detail.get("originalViolation", {})
    user_identity = original_event.get("userIdentity", {})
    request_params = original_event.get("requestParameters", {})

    status = remediation.get("status", "Unknown")
    rule_name = remediation.get("rule_name", "Unknown")
    action = remediation.get("action", "Unknown")
    severity = remediation.get("severity", "Unknown")
    remediation_details = remediation.get("details", {})

    # Determine success emoji
    status_emoji = "✅" if status == "SUCCESS" else "❌"

    message = f"""
{status_emoji} IAM POLICY REMEDIATION COMPLETED {status_emoji}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REMEDIATION SUMMARY
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Rule: {rule_name}
Original Severity: {severity} ⚠️
Remediation Action: {action}
Status: {status}
Timestamp: {detail.get("timestamp", "Unknown")}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ORIGINAL VIOLATION DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Description: {original_violation.get("description", "N/A")}
Event: {original_violation.get("event_name", "N/A")}
Performed By: {user_identity.get("userName", "Unknown")}
User ARN: {user_identity.get("arn", "Unknown")}
User Type: {user_identity.get("type", "Unknown")}
Source IP: {original_event.get("sourceIPAddress", "Unknown")}
AWS Region: {original_event.get("awsRegion", "Unknown")}"""

    # Add IAM-specific original violation details
    event_name = original_violation.get("event_name", "Unknown")
    if event_name in ["AttachUserPolicy", "AttachRolePolicy"]:
        policy_arn = request_params.get("policyArn", "Unknown")
        target_name = request_params.get("userName") or request_params.get(
            "roleName", "Unknown"
        )
        target_type = "User" if "userName" in request_params else "Role"

        message += f"""

Original Action Details:
• {event_name}: Attached dangerous policy to {target_type.lower()}
• Target {target_type}: {target_name}
• Policy ARN: {policy_arn}"""

    elif event_name in ["PutUserPolicy", "PutRolePolicy"]:
        policy_name = request_params.get("policyName", "Unknown")
        target_name = request_params.get("userName") or request_params.get(
            "roleName", "Unknown"
        )
        target_type = "User" if "userName" in request_params else "Role"

        message += f"""

Original Action Details:
• {event_name}: Created dangerous inline policy
• Target {target_type}: {target_name}
• Policy Name: {policy_name}"""

    # Add remediation action details
    if remediation_details:
        message += """

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
REMEDIATION ACTION TAKEN
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"""

        if action == "detach_policy":
            detached_from = remediation_details.get("detached_from", [])
            policy_arn = remediation_details.get("policy_arn", "Unknown")

            message += f"""
Action: Policy Detachment
Policy ARN: {policy_arn}
Detached From: {len(detached_from)} entities"""

            for entity in detached_from[:5]:  # Show first 5 entities
                entity_type = entity.get("type", "Unknown")
                entity_name = entity.get("name", "Unknown")
                message += f"\n• {entity_type}: {entity_name}"

            if len(detached_from) > 5:
                message += f"\n• ... and {len(detached_from) - 5} more entities"

        elif action == "delete_inline_policy":
            deleted_policies = remediation_details.get("deleted_policies", [])

            message += f"""
Action: Inline Policy Deletion
Policies Deleted: {len(deleted_policies)}"""

            for policy in deleted_policies[:5]:  # Show first 5 policies
                target_type = policy.get("target_type", "Unknown")
                target_name = policy.get("target_name", "Unknown")
                policy_name = policy.get("policy_name", "Unknown")
                message += f"\n• {target_type} {target_name}: {policy_name}"

            if len(deleted_policies) > 5:
                message += f"\n• ... and {len(deleted_policies) - 5} more policies"

        else:
            # Generic remediation details
            message += f"\n{json.dumps(remediation_details, indent=2)}"

    # Add error details if remediation failed
    if remediation.get("error"):
        message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ERROR DETAILS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Error: {remediation.get("error", "")}"""

    # Add tracking information
    message += f"""

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TRACKING INFORMATION
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
Correlation ID: {detail.get("correlationId", "Unknown")}
Original Event ID: {original_event.get("eventID", "Unknown")}
Remediation Timestamp: {detail.get("timestamp", "Unknown")}"""

    if status == "SUCCESS":
        message += "\n\n✅ SECURITY VIOLATION SUCCESSFULLY REMEDIATED"
    else:
        message += "\n\n❌ REMEDIATION FAILED - MANUAL INTERVENTION REQUIRED"

    return message


# Mock for testing
class MockSNSPublisher(SNSPublisher):
    """Mock SNS publisher for testing."""

    def __init__(
        self, topic_arn: str = "mock-topic-arn", aws_clients: Any = None
    ) -> None:
        """Initialize mock publisher."""
        self.topic_arn = topic_arn
        self.logger = setup_logging()
        self.published_messages: list[dict[str, Any]] = []

    def publish_violation_alert(self, violation_event: ViolationEvent) -> bool:
        """Mock publish - store message for testing."""
        subject = self._format_subject(violation_event)
        message = self._format_message(violation_event)

        self.published_messages.append(
            {
                "subject": subject,
                "message": message,
                "topic_arn": self.topic_arn,
            }
        )

        self.logger.info(f"MOCK: Published SNS alert - {subject}")
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
                "rule_name": "DangerousInlinePolicy",
                "severity": "HIGH",
                "description": "Inline policy with overly broad permissions",
                "event_name": "PutUserPolicy",
                "event_source": "iam.amazonaws.com",
                "timestamp": "2024-01-01T12:00:00Z",
            },
            "originalEvent": {
                "eventName": "PutUserPolicy",
                "userIdentity": {
                    "userName": "test-user",
                    "arn": "arn:aws:iam::123456789012:user/test-user",
                },
                "sourceIPAddress": "203.0.113.12",
                "userAgent": "aws-cli/2.0.0",
                "awsRegion": "us-east-1",
                "resources": [
                    {
                        "type": "AWS::IAM::User",
                        "ARN": "arn:aws:iam::123456789012:user/test-user",
                    }
                ],
            },
        },
    }

    # Test with mock
    os.environ["SNS_TOPIC_ARN"] = "arn:aws:sns:us-east-1:123456789012:test-topic"
    result = lambda_handler(sample_event, None)
    print(f"Result: {result}")
