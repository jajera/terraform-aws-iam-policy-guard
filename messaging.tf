# IAM Policy Monitor - Messaging Resources
# SNS topics, SQS queues, and EventBridge event routing

# ===== SNS TOPICS =====

# SNS Topic for Alerts (conditional)
resource "aws_sns_topic" "alerts" {
  count = var.enable_sns_alerts ? 1 : 0
  name  = "${var.name_prefix}-alerts"
  tags  = local.common_tags
}

resource "aws_sns_topic_subscription" "email_alerts" {
  count     = var.enable_sns_alerts && var.sns_alert_email != "" ? 1 : 0
  topic_arn = aws_sns_topic.alerts[0].arn
  protocol  = "email"
  endpoint  = var.sns_alert_email
}

# Priority SNS Topic for High Severity Violations
resource "aws_sns_topic" "priority_alerts" {
  count = var.enable_priority_alerts ? 1 : 0
  name  = "${var.name_prefix}-priority-alerts"
  tags  = local.common_tags
}

# ===== SQS QUEUES =====

# SQS Queue for Remediation (conditional)
resource "aws_sqs_queue" "remediation" {
  count                      = var.enable_remediation ? 1 : 0
  name                       = "${var.name_prefix}-remediation"
  message_retention_seconds  = 1209600 # 14 days
  visibility_timeout_seconds = 300

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.remediation_dlq[0].arn
    maxReceiveCount     = 3
  })

  tags = local.common_tags
}

resource "aws_sqs_queue" "remediation_dlq" {
  count = var.enable_remediation ? 1 : 0
  name  = "${var.name_prefix}-remediation-dlq"
  tags  = local.common_tags
}

# Dead Letter Queue for Failed Events
resource "aws_sqs_queue" "eventbridge_dlq" {
  name                      = "${var.name_prefix}-eventbridge-dlq"
  message_retention_seconds = 1209600 # 14 days
  tags                      = local.common_tags
}

# ===== EVENTBRIDGE =====

# Custom EventBridge Bus for IAM Violations
resource "aws_cloudwatch_event_bus" "iam_violations" {
  name = "${var.name_prefix}-iam-violations"
  tags = local.common_tags
}

# EventBridge Rule - IAM Policy Violations
resource "aws_cloudwatch_event_rule" "iam_violations" {
  name           = "${var.name_prefix}-iam-violations"
  description    = "Capture IAM policy violations from detector Lambda"
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name

  event_pattern = jsonencode({
    source      = ["iam.policy.monitor"]
    detail-type = ["IAM Policy Violation"]
  })

  tags = local.common_tags
}

# EventBridge Rule for High Severity Violations (conditional)
resource "aws_cloudwatch_event_rule" "high_severity_violations" {
  count = var.enable_priority_alerts ? 1 : 0

  name           = "${var.name_prefix}-high-severity-violations"
  description    = "High/Critical severity IAM violations requiring immediate attention"
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name

  event_pattern = jsonencode({
    source      = ["iam.policy.monitor"]
    detail-type = ["IAM Policy Violation"]
    detail = {
      violation = {
        severity = ["HIGH", "CRITICAL"]
      }
    }
  })

  tags = local.common_tags
}

# EventBridge Rule for Remediation Status Events
resource "aws_cloudwatch_event_rule" "remediation_status" {
  name           = "${var.name_prefix}-remediation-status"
  description    = "Capture remediation status events from remediator Lambda"
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name

  event_pattern = jsonencode({
    source      = ["iam.policy.remediator"]
    detail-type = ["IAM Policy Remediation Status"]
  })

  tags = local.common_tags
}

# CloudWatch Event Rule for CloudTrail IAM Events
resource "aws_cloudwatch_event_rule" "iam_events" {
  name        = "${var.name_prefix}-iam-events"
  description = "Capture IAM events from CloudTrail"

  event_pattern = jsonencode({
    source      = ["aws.iam"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["iam.amazonaws.com"]
      eventName = [
        "AttachUserPolicy",
        "AttachRolePolicy",
        "CreatePolicy",
        "CreateRole",
        "CreateUser",
        "PutUserPolicy",
        "PutRolePolicy",
        "UpdateAssumeRolePolicy"
      ]
    }
  })

  tags = local.common_tags
}

# ===== EVENTBRIDGE TARGETS =====

# SNS Publisher Lambda Target
resource "aws_cloudwatch_event_target" "sns_publisher" {
  count = var.enable_sns_alerts ? 1 : 0

  rule           = aws_cloudwatch_event_rule.iam_violations.name
  target_id      = "SNSPublisherTarget"
  arn            = aws_lambda_function.sns_publisher[0].arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Slack Handler Lambda Target
resource "aws_cloudwatch_event_target" "slack_handler" {
  count = var.enable_slack_alerts ? 1 : 0

  rule           = aws_cloudwatch_event_rule.iam_violations.name
  target_id      = "SlackHandlerTarget"
  arn            = aws_lambda_function.slack_handler[0].arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Audit Logger Lambda Target (always enabled for compliance)
resource "aws_cloudwatch_event_target" "audit_logger" {
  rule           = aws_cloudwatch_event_rule.iam_violations.name
  target_id      = "AuditLoggerTarget"
  arn            = aws_lambda_function.audit_logger.arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Metrics Publisher Lambda Target (always enabled for monitoring)
resource "aws_cloudwatch_event_target" "metrics_publisher" {
  rule           = aws_cloudwatch_event_rule.iam_violations.name
  target_id      = "MetricsPublisherTarget"
  arn            = aws_lambda_function.metrics_publisher.arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Detector Lambda Target for CloudTrail events
resource "aws_cloudwatch_event_target" "detector" {
  rule      = aws_cloudwatch_event_rule.iam_events.name
  target_id = "DetectorLambdaTarget"
  arn       = aws_lambda_function.detector.arn
}

# EventBridge Target for Priority Alerts
resource "aws_cloudwatch_event_target" "priority_sns" {
  count = var.enable_priority_alerts ? 1 : 0

  rule           = aws_cloudwatch_event_rule.high_severity_violations[0].name
  target_id      = "PrioritySNSTarget"
  arn            = aws_sns_topic.priority_alerts[0].arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name

  # Simple message without input transformation
  input = jsonencode({
    message   = "🚨 CRITICAL IAM VIOLATION DETECTED 🚨 - Check CloudWatch logs and EventBridge for details"
    timestamp = "$.time"
  })
}

# ===== REMEDIATION STATUS EVENT TARGETS =====

# SNS Publisher Target for Remediation Status
resource "aws_cloudwatch_event_target" "remediation_sns_publisher" {
  count = var.enable_sns_alerts ? 1 : 0

  rule           = aws_cloudwatch_event_rule.remediation_status.name
  target_id      = "RemediationSNSPublisherTarget"
  arn            = aws_lambda_function.sns_publisher[0].arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Slack Handler Target for Remediation Status
resource "aws_cloudwatch_event_target" "remediation_slack_handler" {
  count = var.enable_slack_alerts ? 1 : 0

  rule           = aws_cloudwatch_event_rule.remediation_status.name
  target_id      = "RemediationSlackHandlerTarget"
  arn            = aws_lambda_function.slack_handler[0].arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Audit Logger Target for Remediation Status (always enabled)
resource "aws_cloudwatch_event_target" "remediation_audit_logger" {
  rule           = aws_cloudwatch_event_rule.remediation_status.name
  target_id      = "RemediationAuditLoggerTarget"
  arn            = aws_lambda_function.audit_logger.arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# Metrics Publisher Target for Remediation Status (always enabled)
resource "aws_cloudwatch_event_target" "remediation_metrics_publisher" {
  rule           = aws_cloudwatch_event_rule.remediation_status.name
  target_id      = "RemediationMetricsPublisherTarget"
  arn            = aws_lambda_function.metrics_publisher.arn
  event_bus_name = aws_cloudwatch_event_bus.iam_violations.name
}

# ===== LAMBDA PERMISSIONS FOR EVENTBRIDGE =====

# SNS Publisher Lambda Permission
resource "aws_lambda_permission" "sns_publisher_eventbridge" {
  count = var.enable_sns_alerts ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_publisher[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_violations.arn
}

# Slack Handler Lambda Permission
resource "aws_lambda_permission" "slack_handler_eventbridge" {
  count = var.enable_slack_alerts ? 1 : 0

  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_handler[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_violations.arn
}

# Audit Logger Lambda Permission
resource "aws_lambda_permission" "audit_logger_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_logger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_violations.arn
}

# Metrics Publisher Lambda Permission
resource "aws_lambda_permission" "metrics_publisher_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metrics_publisher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_violations.arn
}

# Detector Lambda Permission for CloudTrail events
resource "aws_lambda_permission" "detector_eventbridge" {
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detector.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_events.arn
}

# ===== SNS TOPIC POLICIES =====

# SNS Topic Policy for EventBridge
resource "aws_sns_topic_policy" "priority_alerts" {
  count = var.enable_priority_alerts ? 1 : 0
  arn   = aws_sns_topic.priority_alerts[0].arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Service = "events.amazonaws.com"
        }
        Action   = "SNS:Publish"
        Resource = aws_sns_topic.priority_alerts[0].arn
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      }
    ]
  })
}

# ===== LAMBDA PERMISSIONS FOR REMEDIATION STATUS EVENTS =====

# SNS Publisher Lambda Permission for Remediation Status
resource "aws_lambda_permission" "remediation_sns_publisher_eventbridge" {
  count = var.enable_sns_alerts ? 1 : 0

  statement_id  = "AllowExecutionFromRemediationEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.sns_publisher[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation_status.arn
}

# Slack Handler Lambda Permission for Remediation Status
resource "aws_lambda_permission" "remediation_slack_handler_eventbridge" {
  count = var.enable_slack_alerts ? 1 : 0

  statement_id  = "AllowExecutionFromRemediationEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.slack_handler[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation_status.arn
}

# Audit Logger Lambda Permission for Remediation Status
resource "aws_lambda_permission" "remediation_audit_logger_eventbridge" {
  statement_id  = "AllowExecutionFromRemediationEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.audit_logger.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation_status.arn
}

# Metrics Publisher Lambda Permission for Remediation Status
resource "aws_lambda_permission" "remediation_metrics_publisher_eventbridge" {
  statement_id  = "AllowExecutionFromRemediationEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.metrics_publisher.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.remediation_status.arn
}
