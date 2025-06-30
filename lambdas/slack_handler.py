#!/usr/bin/env python3
"""Slack Handler Lambda Function.

This Lambda function receives IAM policy violation events from EventBridge
and sends formatted notifications to Slack channels.
"""

import json
import os
from typing import Any

import boto3
from botocore.exceptions import ClientError
from slack_notifier import SlackNotifier, setup_logging
from violation_event import ViolationEvent


def get_slack_webhook_url(parameter_name: str | None) -> str:
    """Get Slack webhook URL from AWS Systems Manager Parameter Store.

    Args:
        parameter_name: The parameter store path for the webhook URL

    Returns:
        The webhook URL from parameter store

    Raises:
        ValueError: If parameter name is empty or parameter not found
        ClientError: If AWS API call fails
    """
    if not parameter_name:
        raise ValueError("SLACK_WEBHOOK_PARAMETER environment variable not set")

    try:
        ssm_client = boto3.client("ssm")
        response = ssm_client.get_parameter(Name=parameter_name, WithDecryption=True)
        return response["Parameter"]["Value"]
    except ClientError as e:
        error_code = e.response.get("Error", {}).get("Code", "Unknown")
        if error_code == "ParameterNotFound":
            raise ValueError(
                f"Slack webhook parameter '{parameter_name}' "
                f"not found in Parameter Store"
            ) from e
        raise


def lambda_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for Slack notifications.

    This handler processes both violation and remediation events and
    sends notifications to Slack.

    Args:
        event: EventBridge event containing violation or remediation details
        context: Lambda context

    Returns:
        Dict containing processing results
    """
    logger = setup_logging()

    try:
        # Determine event type and route accordingly
        detail_type = event.get("detail-type", "")

        if detail_type == "IAM Policy Violation":
            return _handle_violation_event(event, context)
        elif detail_type == "IAM Policy Remediation Status":
            return _handle_remediation_event(event, context)
        else:
            logger.error(f"Unknown event type: {detail_type}")
            return {
                "statusCode": 400,
                "body": f"Unsupported event type: {detail_type}",
            }

    except Exception as e:
        logger.error(f"Error in Slack handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


def _handle_violation_event(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle violation events (original logic)."""
    logger = setup_logging()

    try:
        # Get Slack configuration from environment
        webhook_parameter = os.environ.get("SLACK_WEBHOOK_PARAMETER")
        direct_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        config_bucket = os.environ.get("RULES_BUCKET") or os.environ.get(
            "CONFIG_BUCKET_NAME"
        )

        # Get webhook URL - either from Parameter Store or directly from env var
        if direct_webhook_url:
            webhook_url = direct_webhook_url
        elif webhook_parameter:
            webhook_url = get_slack_webhook_url(webhook_parameter)
        else:
            logger.error("Slack webhook not configured")
            return {"statusCode": 400, "body": "Slack webhook not configured"}

        if not config_bucket:
            logger.error("Config bucket environment variable not set")
            return {"statusCode": 400, "body": "Config bucket not configured"}

        # Parse violation event
        violation_event = ViolationEvent.from_eventbridge_event(event)

        logger.info(
            "Processing violation notification for: %s (Severity: %s)",
            violation_event.get_rule_name(),
            violation_event.get_severity(),
        )

        # Convert to format expected by SlackNotifier
        violation_data = _convert_to_slack_format(violation_event)

        # Ensure Event ID is present for Slack (used as unique identifier)
        original_event_with_id = violation_event.original_event.copy()
        original_event_with_id["event_id"] = violation_event.event_id

        # Create Slack notifier
        notifier = SlackNotifier(
            webhook_url=webhook_url,
            rules_bucket=config_bucket,
            aws_clients=None,
        )

        # Send notification
        success = notifier.send_slack_notification(
            violation=violation_data,
            event=original_event_with_id,
        )

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "Violation notification sent successfully",
                        "correlationId": violation_event.correlation_id,
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to send violation notification",
                        "correlationId": violation_event.correlation_id,
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in violation Slack handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


def _handle_remediation_event(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """Handle remediation status events."""
    logger = setup_logging()

    try:
        # Get Slack configuration from environment
        webhook_parameter = os.environ.get("SLACK_WEBHOOK_PARAMETER")
        direct_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        config_bucket = os.environ.get("RULES_BUCKET") or os.environ.get(
            "CONFIG_BUCKET_NAME"
        )

        # Get webhook URL - either from Parameter Store or directly from env var
        if direct_webhook_url:
            webhook_url = direct_webhook_url
        elif webhook_parameter:
            webhook_url = get_slack_webhook_url(webhook_parameter)
        else:
            logger.error("Slack webhook not configured")
            return {"statusCode": 400, "body": "Slack webhook not configured"}

        if not config_bucket:
            logger.error("Config bucket environment variable not set")
            return {"statusCode": 400, "body": "Config bucket not configured"}

        # Parse remediation event
        detail = event.get("detail", {})
        remediation = detail.get("remediation", {})
        rule_name = remediation.get("rule_name", "Unknown")
        status = remediation.get("status", "Unknown")

        logger.info(f"Processing remediation notification: {rule_name} ({status})")

        # Prepare violation payload and embed correlation ID for Slack
        violation_payload = detail.get("originalViolation", {}).copy()
        violation_payload["event_id"] = detail.get("originalEventId") or detail.get(
            "eventId"
        )

        # Create Slack notifier
        notifier = SlackNotifier(
            webhook_url=webhook_url,
            rules_bucket=config_bucket,
            aws_clients=None,
        )

        # Send remediation notification including correlation ID
        success = notifier.send_remediation_notification(
            violation=violation_payload,
            action=remediation.get("action", "unknown"),
            result={
                "success": status == "SUCCESS",
                "details": remediation.get("details", {}),
                "error": remediation.get("error"),
                "timestamp": detail.get("timestamp"),
                "event_id": detail.get("originalEventId") or detail.get("eventId"),
            },
        )

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": "Remediation notification sent successfully",
                        "correlationId": detail.get("originalEventId")
                        or detail.get("eventId"),
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to send remediation notification",
                        "correlationId": detail.get("originalEventId")
                        or detail.get("eventId"),
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in remediation Slack handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


def _convert_to_slack_format(
    violation_event: ViolationEvent,
) -> dict[str, Any]:
    """Convert ViolationEvent to format expected by SlackNotifier.

    Args:
        violation_event: ViolationEvent from EventBridge

    Returns:
        Dict formatted for SlackNotifier
    """
    violation = violation_event.violation
    original_event = violation_event.original_event
    user_identity = violation_event.get_user_identity()

    return {
        # Core violation data
        "rule_name": violation.get("rule_name", "Unknown"),
        "severity": violation.get("severity", "MEDIUM"),
        "description": violation.get("description", "No description available"),
        "category": violation.get("category", "Policy"),
        "risk_score": violation.get("risk_score"),
        # Event context
        "event_name": original_event.get("eventName", "Unknown"),
        "event_source": original_event.get("eventSource", "Unknown"),
        "event_time": original_event.get("eventTime", violation_event.timestamp),
        "aws_region": original_event.get("awsRegion", "Unknown"),
        "source_ip": original_event.get("sourceIPAddress", "Unknown"),
        "user_agent": original_event.get("userAgent", "Unknown"),
        "request_id": original_event.get("requestID", "Unknown"),
        # User information
        "user_name": user_identity.get("userName", "Unknown"),
        "user_arn": user_identity.get("arn", "Unknown"),
        "user_type": user_identity.get("type", "Unknown"),
        "account_id": user_identity.get("accountId", "Unknown"),
        "principal_id": user_identity.get("principalId", "Unknown"),
        # Request details
        "request_parameters": original_event.get("requestParameters", {}),
        "response_elements": original_event.get("responseElements", {}),
        # Resources
        "resources": original_event.get("resources", []),
        # Bedrock AI analysis (if present)
        "bedrock_analysis": violation.get("bedrock_analysis"),
        # Correlation tracking
        "event_id": violation_event.event_id,
        "correlation_id": violation_event.correlation_id,
        "timestamp": violation_event.timestamp,
        # Additional context
        "additional_event_data": original_event.get("additionalEventData", {}),
        "vpc_endpoint_id": original_event.get("vpcEndpointId"),
        "recipient_account_id": original_event.get("recipientAccountId"),
    }


# Handler specifically for remediation notifications
def remediation_handler(event: dict[str, Any], context: Any) -> dict[str, Any]:
    """AWS Lambda handler for Slack remediation notifications.

    This handler processes remediation results and
    send notifications to Slack.

    It expects a different event structure than violation events.

    Args:
        event: EventBridge event containing remediation details
        context: Lambda context

    Returns:
        Dict containing processing results
    """
    logger = setup_logging()

    try:
        # Get Slack configuration from environment
        webhook_parameter = os.environ.get("SLACK_WEBHOOK_PARAMETER")
        direct_webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        config_bucket = os.environ.get("RULES_BUCKET") or os.environ.get(
            "CONFIG_BUCKET_NAME"
        )

        # Get webhook URL - either from Parameter Store or directly from env var
        if direct_webhook_url:
            webhook_url = direct_webhook_url
        elif webhook_parameter:
            webhook_url = get_slack_webhook_url(webhook_parameter)
        else:
            logger.error("Slack webhook not configured")
            return {"statusCode": 400, "body": "Slack webhook not configured"}

        if not config_bucket:
            logger.error("Config bucket environment variable not set")
            return {"statusCode": 400, "body": "Config bucket not configured"}

        # Parse remediation event (different structure than violation events)
        detail = event.get("detail", {})

        logger.info(
            "Processing remediation notification for: %s",
            detail.get("originalViolation", {}).get("rule_name", "Unknown"),
        )

        # Create Slack notifier
        notifier = SlackNotifier(
            webhook_url=webhook_url,
            rules_bucket=config_bucket,
            aws_clients=None,
        )

        # Send remediation notification
        success = notifier.send_remediation_notification(
            violation=detail.get("originalViolation", {}),
            action=detail.get("remediationAction", "unknown"),
            result=detail.get("remediationResult", {}),
        )

        if success:
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "message": ("Remediation notification sent successfully"),
                        "correlationId": detail.get("eventId"),
                    }
                ),
            }
        else:
            return {
                "statusCode": 500,
                "body": json.dumps(
                    {
                        "message": "Failed to send remediation notification",
                        "correlationId": detail.get("eventId"),
                    }
                ),
            }

    except Exception as e:
        logger.error(f"Error in remediation Slack handler: {e!s}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)}),
        }


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
                "description": ("Inline policy with overly broad permissions detected"),
                "category": "Policy",
                "risk_score": 8.5,
            },
            "originalEvent": {
                "eventName": "PutUserPolicy",
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
                    "userName": "test-user",
                    "policyName": "TestPolicy",
                    "policyDocument": (
                        '{"Version":"2012-10-17","Statement":'
                        '[{"Effect":"Allow","Action":"*","Resource":"*"}]}'
                    ),
                },
                "responseElements": None,
                "resources": [
                    {
                        "type": "AWS::IAM::User",
                        "ARN": "arn:aws:iam::123456789012:user/test-user",
                    }
                ],
            },
        },
    }

    # Test with environment variables
    os.environ["SLACK_WEBHOOK_PARAMETER"] = "/test/slack-webhook"
    os.environ["RULES_BUCKET"] = "test-config-bucket"
    os.environ["CONFIG_KEY"] = "notification-config.yaml"

    result = lambda_handler(sample_event, None)
    print(f"Result: {result}")
