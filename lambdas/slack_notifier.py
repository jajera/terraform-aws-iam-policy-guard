#!/usr/bin/env python3
"""Slack Notification Module for IAM Policy Violations.

Supports configurable field mapping, status colors,
and retry logic with exponential backoff.
"""

import json
import logging
import os
import time
import urllib.request
from typing import Any

import yaml


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


class SlackNotifier:
    """Handles Slack notifications for IAM policy violations."""

    def __init__(
        self,
        webhook_url: str,
        aws_clients: Any = None,
        rules_bucket: str = "",
    ) -> None:
        """Initialize Slack notifier.

        Args:
            webhook_url: Slack webhook URL for sending messages
            aws_clients: AWS clients interface (optional)
            rules_bucket: S3 bucket for notification config (optional)
        """
        self.webhook_url = webhook_url
        self.aws_clients = aws_clients
        self.rules_bucket = rules_bucket
        self.logger = setup_logging()
        self.debug = os.getenv("DEBUG", "false").lower() == "true"

        # Initialize config as None - will be loaded on first use
        self._config: dict[str, Any] | None = None
        self._config_loaded = False

    @property
    def config(self) -> dict[str, Any]:
        """Lazy load configuration from S3 or use default."""
        if not self._config_loaded:
            self._config = self._load_notification_config()
            self._config_loaded = True
        return self._config or {}

    def _load_notification_config(self) -> dict[str, Any]:
        """Load notification configuration from S3."""
        try:
            if not self.rules_bucket or not self.aws_clients:
                self.logger.warning(
                    "No rules bucket or AWS clients configured, using default "
                    "notification config"
                )
                return self._get_default_config()

            response = self.aws_clients.get_object(
                Bucket=self.rules_bucket, Key="notification-config.yaml"
            )
            if response is None:
                raise ValueError("Failed to load notification config")

            content = response["Body"].read().decode("utf-8")
            config = yaml.safe_load(content)
            return config if isinstance(config, dict) else self._get_default_config()

        except Exception as e:
            self.logger.error(f"Error loading notification config: {e!s}")
            return self._get_default_config()

    def _get_default_config(self) -> dict[str, Any]:
        """Get default notification configuration."""
        return {
            "severity_colors": {
                "CRITICAL": "#E01E5A",
                "HIGH": "#FF5733",
                "MEDIUM": "#FFCC00",
                "LOW": "#36C5F0",
                "INFO": "#2EB67D",
            },
            "slack_config": {
                "message_title": "🚨 IAM Policy Violation Detected",
                "message_fields": [
                    "rule_name",
                    "severity",
                    "event_name",
                    "user_identity.userName",
                    "sourceIPAddress",
                    "awsRegion",
                    "description",
                ],
            },
            "event_status_mapping": {},
            "status_colors": {},
            "emoji_mapping": {
                "CRITICAL": "🚨",
                "HIGH": "⚠️",
                "MEDIUM": "📋",
                "LOW": "📄",
            },
        }

    def debug_log(self, message: str) -> None:
        """Print debug messages only if DEBUG is enabled."""
        if self.debug:
            self.logger.debug(message)

    def exponential_backoff(self, retries: int) -> int:
        """Calculate exponential backoff delay."""
        return int(min(2**retries, 60))

    def extract_field(self, message: dict[str, Any], field_path: str) -> str:
        """Extract field value using dot notation."""
        keys = field_path.split(".")
        value = message
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return "N/A"
        return str(value) if value is not None else "N/A"

    def map_custom_state(self, status: str) -> str:
        """Map status using state mapping."""
        state_map = self.config.get("event_status_mapping", {})
        mapped_value = state_map.get(status, status)
        return str(mapped_value) if mapped_value is not None else status

    def get_status(self, message: dict[str, Any]) -> str:
        """Get status from message (severity or mapped event status)."""
        # First try to get severity
        severity = str(message.get("severity", ""))
        if severity:
            return severity

        # Fall back to event name mapping
        event_name = str(message.get("event_name", ""))
        return self.map_custom_state(event_name)

    def get_status_color(self, status: str) -> str | None:
        """Get color for status."""
        # Build status color mapping from config and environment variable
        status_color_map = {}

        # 1. ENV variable overrides (expects JSON mapping)
        env_colors = os.environ.get("SEVERITY_COLORS")
        if env_colors:
            try:
                status_color_map.update(json.loads(env_colors))
            except ValueError:
                self.logger.warning("SEVERITY_COLORS env var is not valid JSON")

        # 2. Config file / S3
        status_color_map.update(self.config.get("severity_colors", {}))
        status_color_map.update(self.config.get("status_colors", {}))

        if not status_color_map:
            # Provide sane defaults if config missing
            status_color_map = {
                "CRITICAL": "#E01E5A",  # red
                "HIGH": "#E01E5A",  # red
                "MEDIUM": "#FFA500",  # orange
                "LOW": "#FFCC00",  # yellow
                "SUCCESS": "#2EB67D",  # green
            }
        return status_color_map.get(
            status, "#E01E5A" if status in ["CRITICAL", "HIGH"] else None
        )

    def format_slack_message(
        self, violation: dict[str, Any], event: dict[str, Any]
    ) -> dict[str, Any]:
        """Format detailed Slack message with IAM-specific information."""
        # Get message fields from config
        slack_config = self.config.get("slack_config", {})
        message_title = slack_config.get(
            "message_title", "🚨 IAM Policy Violation Detected"
        )

        # Extract key information with fallbacks for CloudTrail naming
        rule_name = violation.get("rule_name", "Unknown")
        severity = violation.get("severity", "MEDIUM")

        # Support both snake_case (internal) and CamelCase (raw CloudTrail) keys
        event_name = event.get("event_name") or event.get("eventName") or "Unknown"
        user_name = event.get("user_name") or event.get("userName") or "Unknown"
        user_arn = event.get("user_arn") or event.get("userArn") or "Unknown"
        request_params = (
            event.get("request_parameters") or event.get("requestParameters") or {}
        )
        source_ip = event.get("source_ip") or event.get("sourceIPAddress") or "Unknown"
        aws_region = event.get("aws_region") or event.get("awsRegion") or "Unknown"

        status = self.get_status({**violation, **event})
        color = self.get_status_color(status) or {
            "CRITICAL": "#E01E5A",
            "HIGH": "#E01E5A",
            "MEDIUM": "#FFA500",
            "LOW": "#FFCC00",
        }.get(severity, "#AAAAAA")
        emoji = self._get_severity_emoji(severity)

        # Build comprehensive fields list
        formatted_fields = [
            {
                "title": "Rule",
                "value": f"`{rule_name}`",
                "short": True,
            },
            {
                "title": "Severity",
                "value": f"{emoji} {severity}",
                "short": True,
            },
            {
                "title": "Event",
                "value": f"`{event_name}`",
                "short": True,
            },
            {
                "title": "User",
                "value": f"`{user_name}`",
                "short": True,
            },
            {
                "title": "Source IP",
                "value": source_ip,
                "short": True,
            },
            {
                "title": "AWS Region",
                "value": aws_region,
                "short": True,
            },
        ]

        # Add IAM-specific details based on event type
        if event_name in ["AttachUserPolicy", "AttachRolePolicy"]:
            policy_arn = request_params.get("policyArn", "Unknown")
            target_name = request_params.get("userName") or request_params.get(
                "roleName", "Unknown"
            )
            target_type = "User" if "userName" in request_params else "Role"

            formatted_fields.extend(
                [
                    {
                        "title": f"Target {target_type}",
                        "value": f"`{target_name}`",
                        "short": True,
                    },
                    {
                        "title": "Policy ARN",
                        "value": policy_arn,
                        "short": False,
                    },
                ]
            )

        elif event_name in ["PutUserPolicy", "PutRolePolicy"]:
            policy_name = request_params.get("policyName", "Unknown")
            target_name = request_params.get("userName") or request_params.get(
                "roleName", "Unknown"
            )
            target_type = "User" if "userName" in request_params else "Role"

            formatted_fields.extend(
                [
                    {
                        "title": f"Target {target_type}",
                        "value": f"`{target_name}`",
                        "short": True,
                    },
                    {
                        "title": "Inline Policy Name",
                        "value": f"`{policy_name}`",
                        "short": True,
                    },
                ]
            )

        elif event_name == "CreatePolicy":
            policy_name = request_params.get("policyName", "Unknown")
            formatted_fields.append(
                {
                    "title": "Policy Name",
                    "value": f"`{policy_name}`",
                    "short": True,
                }
            )

        # Add user ARN if available
        if user_arn and user_arn != "Unknown":
            formatted_fields.append(
                {
                    "title": "User ARN",
                    "value": user_arn,
                    "short": False,
                }
            )

        # Collect blocks for richer formatting (optional)
        blocks: list[dict[str, Any]] = []

        # Header block (always)
        blocks.append(
            {
                "type": "section",
                "text": {
                    "type": "mrkdwn",
                    "text": f"*{message_title}*\n{violation.get('description', 'IAM policy violation detected')}",
                },
            }
        )

        # --- AI Risk Analysis Field & Block ---
        bedrock_analysis = violation.get("bedrock_analysis")
        if bedrock_analysis:
            risk_score = bedrock_analysis.get("risk_score", "Unknown")
            risk_level = bedrock_analysis.get("risk_level", "Unknown")
            summary = bedrock_analysis.get("summary", "Not available")
            confidence = bedrock_analysis.get("confidence", 0.0)

            ai_text = (
                f"*Risk Score:* {risk_score}/10 ({risk_level})\n"
                f"*Summary:* {summary}\n"
                f"*Confidence:* {confidence:.2f}"
            )

            formatted_fields.append(
                {
                    "title": "🤖 AI Risk Analysis",
                    "value": ai_text,
                    "short": False,
                }
            )

            # Add rich AI analysis block
            blocks.append({"type": "divider"})
            blocks.append(
                {
                    "type": "section",
                    "text": {
                        "type": "mrkdwn",
                        "text": f"🤖 *AI Risk Analysis*\n{ai_text}",
                    },
                }
            )

        # --- Details Block ---
        details_text = f"*Rule:* `{rule_name}`\n"
        details_text += f"*Severity:* `{emoji} {severity}`\n"
        details_text += f"*Event:* `{event_name}`\n"
        details_text += f"*User:* `{user_name}`\n"
        details_text += f"*Source IP:* `{source_ip}`\n"
        details_text += f"*AWS Region:* `{aws_region}`\n"

        formatted_fields.append(
            {
                "title": "Details",
                "value": details_text,
                "short": False,
            }
        )

        slack_message: dict[str, Any] = {
            "blocks": blocks,
            "attachments": [
                {
                    "pretext": message_title,
                    "fallback": violation.get(
                        "description", "IAM policy violation detected"
                    ),
                    "text": violation.get(
                        "description", "IAM policy violation detected"
                    ),
                    "color": color,
                    "fields": formatted_fields,
                    "footer": "IAM Policy Monitor",
                    "ts": int(time.time()),
                }
            ],
        }

        self.debug_log(f"Extracted status: {status}")
        self.debug_log(f"Mapped Color: {color}")

        return slack_message

    def _get_severity_emoji(self, severity: str) -> str:
        """Get emoji for severity level."""
        emoji_map = self.config.get(
            "emoji_mapping",
            {"CRITICAL": "🚨", "HIGH": "⚠️", "MEDIUM": "📋", "LOW": "📄"},
        )
        return str(emoji_map.get(severity, "📋"))

    def send_slack_notification(
        self, violation: dict[str, Any], event: dict[str, Any]
    ) -> bool:
        """Send violation notification to Slack with retry logic."""
        try:
            formatted_message = self.format_slack_message(violation, event)
            data = json.dumps(formatted_message).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )

            retries = 0
            while retries < 5:
                try:
                    with urllib.request.urlopen(req) as response:
                        response_body = response.read().decode("utf-8")
                        if response.status == 200:
                            self.logger.info(
                                f"✅ Slack notification sent successfully! "
                                f"Response: {response_body}"
                            )
                            return True
                        else:
                            self.logger.warning(
                                f"⚠️ Slack responded with status "
                                f"{response.status}: {response_body}"
                            )
                except Exception as e:
                    self.logger.error(
                        f"❌ Failed to send to Slack (Attempt {retries + 1}): {e!s}"
                    )
                    time.sleep(self.exponential_backoff(retries))
                    retries += 1

            self.logger.error("Slack API failed after multiple retries")
            return False

        except Exception as e:
            self.logger.error(f"Error sending Slack notification: {e!s}")
            return False

    def send_remediation_notification(
        self, violation: dict[str, Any], action: str, result: dict[str, Any]
    ) -> bool:
        """Send detailed remediation notification to Slack with retry logic."""
        try:
            # Create detailed remediation message
            success = result.get("success", False)
            status_emoji = "✅" if success else "❌"
            color = "#2EB67D" if success else "#E01E5A"
            details = result.get("details", {})

            # Basic fields
            fields = [
                {
                    "title": "Rule",
                    "value": f"`{violation.get('rule_name', 'Unknown')}`",
                    "short": True,
                },
                {
                    "title": "Original Severity",
                    "value": f"⚠️ {violation.get('severity', 'Unknown')}",
                    "short": True,
                },
                {"title": "Action", "value": f"`{action}`", "short": True},
                {
                    "title": "Status",
                    "value": (f"{status_emoji} {'SUCCESS' if success else 'FAILED'}"),
                    "short": True,
                },
            ]

            # Add original violation context
            if violation.get("event_name"):
                fields.append(
                    {
                        "title": "Original Event",
                        "value": f"`{violation.get('event_name')}`",
                        "short": True,
                    }
                )

            if violation.get("user_name"):
                fields.append(
                    {
                        "title": "User",
                        "value": f"`{violation.get('user_name')}`",
                        "short": True,
                    }
                )

            # Add remediation-specific details
            if success and details:
                if action == "detach_policy":
                    detached_from = details.get("detached_from", [])
                    policy_arn = details.get("policy_arn", "Unknown")

                    fields.extend(
                        [
                            {
                                "title": "Policy Detached",
                                "value": policy_arn,
                                "short": False,
                            },
                            {
                                "title": "Entities Affected",
                                "value": f"{len(detached_from)} entities",
                                "short": True,
                            },
                        ]
                    )

                    # Show first few affected entities
                    if detached_from:
                        entity_list = []
                        for entity in detached_from[:3]:  # Show first 3
                            entity_type = entity.get("type", "Unknown")
                            entity_name = entity.get("name", "Unknown")
                            entity_list.append(f"• {entity_type}: {entity_name}")

                        if len(detached_from) > 3:
                            entity_list.append(
                                f"• ... and {len(detached_from) - 3} more"
                            )

                        fields.append(
                            {
                                "title": "Detached From",
                                "value": "\n".join(entity_list),
                                "short": False,
                            }
                        )

                elif action == "delete_inline_policy":
                    deleted_policies = details.get("deleted_policies", [])

                    fields.append(
                        {
                            "title": "Policies Deleted",
                            "value": f"{len(deleted_policies)} inline policies",
                            "short": True,
                        }
                    )

                    # Show first few deleted policies
                    if deleted_policies:
                        policy_list = []
                        for policy in deleted_policies[:3]:  # Show first 3
                            target_type = policy.get("target_type", "Unknown")
                            target_name = policy.get("target_name", "Unknown")
                            policy_name = policy.get("policy_name", "Unknown")
                            policy_list.append(
                                f"• {target_type} {target_name}: {policy_name}"
                            )

                        if len(deleted_policies) > 3:
                            policy_list.append(
                                f"• ... and {len(deleted_policies) - 3} more"
                            )

                        fields.append(
                            {
                                "title": "Deleted Policies",
                                "value": "\n".join(policy_list),
                                "short": False,
                            }
                        )

            # Add error details if remediation failed
            if not success and result.get("error"):
                fields.append(
                    {
                        "title": "Error Details",
                        "value": f"```{result['error']}```",
                        "short": False,
                    }
                )

            # Add timestamp
            if result.get("timestamp"):
                fields.append(
                    {
                        "title": "Completed At",
                        "value": result["timestamp"],
                        "short": True,
                    }
                )

            slack_message = {
                "attachments": [
                    {
                        "pretext": f"*🛠️ IAM Policy Remediation "
                        f"{'Completed' if success else 'Failed'}*",
                        "text": violation.get(
                            "description",
                            "Remediation completed for IAM policy violation",
                        ),
                        "fields": fields,
                        "color": color,
                        "footer": "IAM Policy Monitor - Remediator",
                        "ts": int(time.time()),
                    }
                ]
            }

            # Send message using same retry logic
            data = json.dumps(slack_message).encode("utf-8")
            req = urllib.request.Request(
                self.webhook_url,
                data=data,
                headers={"Content-Type": "application/json"},
            )

            retries = 0
            while retries < 5:
                try:
                    with urllib.request.urlopen(req) as response:
                        if response.status == 200:
                            self.logger.info(
                                "✅ Remediation notification sent successfully!"
                            )
                            return True
                except Exception as e:
                    self.logger.error(
                        f"❌ Failed to send remediation notification "
                        f"(Attempt {retries + 1}): {e!s}"
                    )
                    time.sleep(self.exponential_backoff(retries))
                    retries += 1

            return False

        except Exception as e:
            self.logger.error(f"Error sending remediation notification: {e!s}")
            return False


class MockSlackNotifier(SlackNotifier):
    """Mock Slack notifier for testing."""

    def __init__(
        self,
        webhook_url: str = "mock://webhook",
        aws_clients: Any = None,
        rules_bucket: str = "",
    ) -> None:
        """Initialize mock notifier."""
        self.webhook_url = webhook_url
        self.aws_clients = aws_clients
        self.rules_bucket = rules_bucket
        self.logger = setup_logging()
        self.debug = os.getenv("DEBUG", "false").lower() == "true"

        # Use default config for testing - no S3 loading
        self._config: dict[str, Any] = self._get_default_config()
        self._config_loaded = True

        # Store sent messages for testing
        self.sent_messages: list[dict[str, Any]] = []

    def send_slack_notification(
        self, violation: dict[str, Any], event: dict[str, Any]
    ) -> bool:
        """Mock send notification - just store the message."""
        formatted_message = self.format_slack_message(violation, event)
        self.sent_messages.append(formatted_message)

        self.logger.info(
            f"MOCK: Sent Slack notification for rule "
            f"{violation.get('rule_name', 'Unknown')}"
        )
        return True

    def send_remediation_notification(
        self, violation: dict[str, Any], action: str, result: dict[str, Any]
    ) -> bool:
        """Mock send remediation notification."""
        # Create the same message format as real implementation
        success = result.get("success", False)
        status_emoji = "✅" if success else "❌"
        color = "#2EB67D" if success else "#E01E5A"

        fields = [
            {
                "title": "Rule",
                "value": f"`{violation.get('rule_name', 'Unknown')}`",
                "short": True,
            },
            {"title": "Action", "value": f"`{action}`", "short": True},
            {
                "title": "Status",
                "value": (f"{status_emoji} {'SUCCESS' if success else 'FAILED'}"),
                "short": True,
            },
        ]

        if not success and result.get("error"):
            fields.append(
                {
                    "title": "Error",
                    "value": result["error"],
                    "short": False,
                }
            )

        # Add timestamp
        if result.get("timestamp"):
            fields.append(
                {
                    "title": "Completed At",
                    "value": result["timestamp"],
                    "short": True,
                }
            )

        slack_message = {
            "attachments": [
                {
                    "pretext": f"*🛠️ IAM Policy Remediation "
                    f"{'Completed' if success else 'Failed'}*",
                    "fields": fields,
                    "color": color,
                    "footer": "IAM Policy Monitor - Remediator",
                    "ts": int(time.time()),
                }
            ]
        }

        self.sent_messages.append(slack_message)
        self.logger.info(
            f"MOCK: Sent remediation notification for "
            f"rule {violation.get('rule_name')} with action {action}"
        )
        return True
