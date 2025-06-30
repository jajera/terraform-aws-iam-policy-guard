#!/usr/bin/env python3
"""IAM Policy Violation Event Schema.

This module defines the standard event structure for IAM policy violations
that will be published to EventBridge and consumed by various handlers.
"""

import json
import logging
import os
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any


@dataclass
class ViolationEvent:
    """Standard event structure for IAM policy violations."""

    # Event metadata (required fields first)
    event_id: str
    timestamp: str
    violation: dict[str, Any]
    original_event: dict[str, Any]

    # Optional fields with defaults
    source: str = "iam.policy.monitor"
    detail_type: str = "IAM Policy Violation"
    correlation_id: str | None = None

    @classmethod
    def create(
        cls,
        violation_result: Any,
        cloudtrail_event: dict[str, Any],
        correlation_id: str | None = None,
    ) -> "ViolationEvent":
        """Create a ViolationEvent from detection results.

        Args:
            violation_result: ViolationResult from detector
            cloudtrail_event: Original CloudTrail event
            correlation_id: Optional correlation ID for tracing

        Returns:
            ViolationEvent: Formatted event for EventBridge
        """
        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc).isoformat(),
            violation=violation_result.to_dict(),
            original_event=cloudtrail_event,
            correlation_id=correlation_id or str(uuid.uuid4()),
        )

    def to_eventbridge_entry(self) -> dict[str, Any]:
        """Convert to EventBridge PutEvents entry format.

        Returns:
            Dict formatted for EventBridge PutEvents API
        """
        return {
            "Source": self.source,
            "DetailType": self.detail_type,
            "Detail": json.dumps(
                {
                    "eventId": self.event_id,
                    "timestamp": self.timestamp,
                    "correlationId": self.correlation_id,
                    "violation": self.violation,
                    "originalEvent": self.original_event,
                }
            ),
            "Time": datetime.fromisoformat(self.timestamp.replace("Z", "+00:00")),
            "EventBusName": os.environ.get("EVENTBRIDGE_BUS_NAME", "default"),
        }

    @classmethod
    def from_eventbridge_event(cls, event: dict[str, Any]) -> "ViolationEvent":
        """Parse ViolationEvent from EventBridge Lambda event.

        Args:
            event: EventBridge Lambda event

        Returns:
            ViolationEvent: Parsed violation event
        """
        detail = event["detail"]
        return cls(
            event_id=detail["eventId"],
            timestamp=detail["timestamp"],
            source=event["source"],
            detail_type=event["detail-type"],
            violation=detail["violation"],
            original_event=detail["originalEvent"],
            correlation_id=detail.get("correlationId"),
        )

    def get_severity(self) -> str:
        """Get violation severity."""
        return str(self.violation.get("severity", "MEDIUM"))

    def get_rule_name(self) -> str:
        """Get violation rule name."""
        return str(self.violation.get("rule_name", "Unknown"))

    def get_event_name(self) -> str:
        """Get original CloudTrail event name."""
        return str(self.original_event.get("eventName", "Unknown"))

    def get_user_identity(self) -> dict[str, Any]:
        """Get user identity from original event, with sensible fallbacks.

        AWS CloudTrail events can have slightly different structures depending
        on whether the caller was an IAM user, an assumed role, an SSO session,
        etc.  We attempt to surface the most useful identity details for
        notifications even when the standard *userName* field is missing.
        """
        user_identity: dict[str, Any] = self.original_event.get("userIdentity", {})

        # Fast-path if userName already present
        if user_identity.get("userName"):
            return dict(user_identity)

        # Fallback 1: SSO / STS assumed roles often have a sessionIssuer block
        session_issuer: dict[str, Any] = (
            user_identity.get("sessionContext", {}).get("sessionIssuer", {})
            if isinstance(user_identity.get("sessionContext"), dict)
            else {}
        )
        if session_issuer:
            fallback_identity = {
                **user_identity,  # retain original keys
                # Promote useful fields from sessionIssuer
                "userName": session_issuer.get("userName")
                or session_issuer.get("principalId"),
                "arn": session_issuer.get("arn"),
                "type": session_issuer.get("type", user_identity.get("type")),
            }
            return {k: v for k, v in fallback_identity.items() if v is not None}

        # Fallback 2: Derive userName from ARN if possible (last ARN segment)
        arn = user_identity.get("arn")
        if arn and ":" in arn:
            candidate_name = arn.split("/")[-1]
            if candidate_name:
                fallback_identity = {
                    **user_identity,
                    "userName": candidate_name,
                }
                return fallback_identity

        # As a last resort return the raw structure: notifier will mark N/A
        return dict(user_identity)

    def add_ai_analysis(self, analysis_text):
        """Adds the AI-generated risk analysis to the event details."""
        if "custom_fields" not in self.violation:
            self.violation["custom_fields"] = {}
        self.violation["custom_fields"]["ai_risk_analysis"] = analysis_text

    def to_json(self):
        """
        Returns the complete violation event as a JSON string.
        """
        return json.dumps(self.violation)


class ViolationEventPublisher:
    """Publishes violation events to EventBridge."""

    def __init__(self, aws_clients: Any) -> None:
        """Initialize publisher.

        Args:
            aws_clients: AWS clients interface
        """
        self.aws_clients = aws_clients

    def publish_violation(
        self, violation_result: Any, cloudtrail_event: dict[str, Any]
    ) -> bool:
        """Publish violation event to EventBridge.

        Args:
            violation_result: ViolationResult from detector
            cloudtrail_event: Original CloudTrail event

        Returns:
            bool: True if published successfully
        """
        try:
            # Create violation event
            violation_event = ViolationEvent.create(violation_result, cloudtrail_event)

            # Publish to EventBridge
            response = self.aws_clients.put_events(
                Entries=[violation_event.to_eventbridge_entry()]
            )

            # Check for failures
            if response and "FailedEntryCount" in response:
                failed_count = response["FailedEntryCount"]
                if failed_count > 0:
                    failures = response.get("Entries", [])
                    for entry in failures:
                        if "ErrorCode" in entry:
                            raise Exception(
                                f"EventBridge publish failed: "
                                f"{entry['ErrorCode']} - "
                                f"{entry.get('ErrorMessage', '')}"
                            )
                    return False

            return True

        except Exception as e:
            logger = logging.getLogger(__name__)
            logger.error(f"Failed to publish violation event: {e!s}")
            return False


class MockViolationEventPublisher(ViolationEventPublisher):
    """Mock publisher for testing."""

    def __init__(self, aws_clients: Any = None) -> None:
        """Initialize mock publisher."""
        self.aws_clients = aws_clients
        self.published_events: list[ViolationEvent] = []

    def publish_violation(
        self, violation_result: Any, cloudtrail_event: dict[str, Any]
    ) -> bool:
        """Mock publish - just store the event."""
        violation_event = ViolationEvent.create(violation_result, cloudtrail_event)
        self.published_events.append(violation_event)

        logger = logging.getLogger(__name__)
        logger.info(
            f"MOCK: Published violation event for rule "
            f"{violation_event.get_rule_name()}"
        )
        return True
