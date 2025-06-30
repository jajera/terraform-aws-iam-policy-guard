# IAM Policy Monitor - Monitoring Resources
# CloudWatch log groups, dashboards, alarms, and metrics

# ===== CLOUDWATCH LOG GROUPS =====

# Detector Lambda Log Group
resource "aws_cloudwatch_log_group" "detector" {
  name              = "/aws/lambda/${var.name_prefix}-detector"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Remediator Lambda Log Group (conditional)
resource "aws_cloudwatch_log_group" "remediator" {
  count             = var.enable_remediation ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-remediator"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# SNS Publisher Lambda Log Group (conditional)
resource "aws_cloudwatch_log_group" "sns_publisher" {
  count             = var.enable_sns_alerts ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-sns-publisher"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Slack Handler Lambda Log Group (conditional)
resource "aws_cloudwatch_log_group" "slack_handler" {
  count             = var.enable_slack_alerts ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-slack-handler"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Audit Logger Lambda Log Group
resource "aws_cloudwatch_log_group" "audit_logger" {
  name              = "/aws/lambda/${var.name_prefix}-audit-logger"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Metrics Publisher Lambda Log Group
resource "aws_cloudwatch_log_group" "metrics_publisher" {
  name              = "/aws/lambda/${var.name_prefix}-metrics-publisher"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Athena Table Creator Lambda Log Group
resource "aws_cloudwatch_log_group" "athena_table_creator" {
  count             = var.enable_athena_table ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-athena-table-creator"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Analytics Scheduler Lambda Log Group
resource "aws_cloudwatch_log_group" "analytics_scheduler" {
  count             = var.enable_athena_table ? 1 : 0
  name              = "/aws/lambda/${var.name_prefix}-analytics-scheduler"
  retention_in_days = var.log_retention_days
  skip_destroy      = !var.force_destroy_logs
  tags              = local.common_tags
}

# Alarm for SNS Delivery Failures

locals {
  sns_topics = merge(
    var.enable_sns_alerts ? {
      "alerts" = {
        name = aws_sns_topic.alerts[0].name
        arn  = aws_sns_topic.alerts[0].arn
      }
    } : {},
    var.enable_priority_alerts ? {
      "priority_alerts" = {
        name = aws_sns_topic.priority_alerts[0].name
        arn  = aws_sns_topic.priority_alerts[0].arn
      }
    } : {}
  )

  _sns_widgets_raw = [
    for t in values(local.sns_topics) : {
      title = "SNS – ${t.name}"
      metrics = [
        ["AWS/SNS", "NumberOfMessagesPublished", "TopicName", t.name],
        [".", "NumberOfNotificationsDelivered", ".", "."],
        [".", "NumberOfNotificationsFailed", ".", "."]
      ]
    }
  ]
}

resource "aws_cloudwatch_metric_alarm" "sns_delivery_failures" {
  for_each = local.sns_topics

  alarm_name          = "${var.name_prefix}-sns-failures-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "NumberOfNotificationsFailed"
  namespace           = "AWS/SNS"
  period              = 300
  statistic           = "Sum"
  threshold           = 0
  alarm_description   = "Alarm if SNS topic '${each.value.name}' fails to deliver notifications"

  dimensions = {
    TopicName = each.value.name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_composite_alarm" "sns_delivery_composite" {
  count             = length(local.sns_topics) > 0 ? 1 : 0
  alarm_name        = "${var.name_prefix}-sns-failures-composite"
  alarm_description = "Composite alarm triggered if any SNS topic fails to deliver messages"

  alarm_rule = join(" OR ", [
    for key in keys(local.sns_topics) :
    "ALARM(${aws_cloudwatch_metric_alarm.sns_delivery_failures[key].alarm_name})"
  ])
}

# Alarm for SQS queue backlogs

locals {
  sqs_queues = merge(
    {
      "eventbridge_dlq" = {
        name = aws_sqs_queue.eventbridge_dlq.name
        arn  = aws_sqs_queue.eventbridge_dlq.arn
      }
    },
    var.enable_remediation ? {
      "remediation" = {
        name = aws_sqs_queue.remediation[0].name
        arn  = aws_sqs_queue.remediation[0].arn
      },
      "remediation_dlq" = {
        name = aws_sqs_queue.remediation_dlq[0].name
        arn  = aws_sqs_queue.remediation_dlq[0].arn
      }
    } : {}
  )

  _sqs_widgets_raw = [
    for q in values(local.sqs_queues) : {
      title = "SQS – ${q.name}"
      metrics = [
        ["AWS/SQS", "ApproximateNumberOfMessagesVisible", "QueueName", q.name],
        ["AWS/SQS", "ApproximateNumberOfMessagesNotVisible", "QueueName", q.name],
        ["AWS/SQS", "ApproximateAgeOfOldestMessage", "QueueName", q.name]
      ]
    }
  ]
}

resource "aws_cloudwatch_metric_alarm" "sqs_backlog" {
  for_each = local.sqs_queues

  alarm_name          = "${var.name_prefix}-sqs-backlog-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "ApproximateNumberOfMessagesVisible"
  namespace           = "AWS/SQS"
  period              = 300
  statistic           = "Sum"
  threshold           = 10
  alarm_description   = "Alarm if queue '${each.value.name}' has message backlog"

  dimensions = {
    QueueName = each.value.name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_composite_alarm" "sqs_backlog_composite" {
  count             = length(local.sqs_queues) > 0 ? 1 : 0
  alarm_name        = "${var.name_prefix}-sqs-backlog-composite"
  alarm_description = "Composite alarm triggered if any SQS queue has backlog"

  alarm_rule = join(" OR ", [
    for key in keys(local.sqs_queues) :
    "ALARM(${aws_cloudwatch_metric_alarm.sqs_backlog[key].alarm_name})"
  ])
}

# Alarm for Lambda functions errors

locals {
  lambda_functions = merge(
    {
      "detector" = {
        name = aws_lambda_function.detector.function_name
        arn  = aws_lambda_function.detector.arn
      },
      "audit_logger" = {
        name = aws_lambda_function.audit_logger.function_name
        arn  = aws_lambda_function.audit_logger.arn
      },
      "metrics_publisher" = {
        name = aws_lambda_function.metrics_publisher.function_name
        arn  = aws_lambda_function.metrics_publisher.arn
      }
    },
    var.enable_remediation ? {
      "remediator" = {
        name = aws_lambda_function.remediator[0].function_name
        arn  = aws_lambda_function.remediator[0].arn
      }
    } : {},
    var.enable_sns_alerts ? {
      "sns_publisher" = {
        name = aws_lambda_function.sns_publisher[0].function_name
        arn  = aws_lambda_function.sns_publisher[0].arn
      }
    } : {},
    var.enable_slack_alerts ? {
      "slack_handler" = {
        name = aws_lambda_function.slack_handler[0].function_name
        arn  = aws_lambda_function.slack_handler[0].arn
      }
    } : {},
    var.enable_athena_table ? {
      "athena_table_creator" = {
        name = aws_lambda_function.athena_table_creator[0].function_name
        arn  = aws_lambda_function.athena_table_creator[0].arn
      },
      "analytics_scheduler" = {
        name = aws_lambda_function.analytics_scheduler[0].function_name
        arn  = aws_lambda_function.analytics_scheduler[0].arn
      }
    } : {}
  )

  _lambda_widgets_raw = [
    for l in values(local.lambda_functions) : {
      title = "Lambda – ${l.name}"
      metrics = [
        ["AWS/Lambda", "Duration", "FunctionName", l.name],
        [".", "Errors", ".", "."],
        [".", "Invocations", ".", "."]
      ]
    }
  ]

  # Combine all widget content and apply unified layout
  widgets_all = concat(
    local._sns_widgets_raw,
    local._sqs_widgets_raw,
    local._lambda_widgets_raw
  )

  # Analytics widgets (when Athena is enabled)
  analytics_widgets = var.enable_athena_table ? [
    {
      title     = "Analytics – High Risk Principals"
      analytics = true
      metrics = [
        ["IAMPolicyMonitor/Analytics", "HighRiskPrincipals"]
      ]
    },
    {
      title     = "Analytics – Potential Attacks"
      analytics = true
      metrics = [
        ["IAMPolicyMonitor/Analytics", "PotentialAttacks"]
      ]
    },
    {
      title     = "Analytics – Violation Trends"
      analytics = true
      metrics = [
        ["IAMPolicyMonitor/Analytics", "ViolationTrends_CRITICAL"],
        [".", "ViolationTrends_HIGH"],
        [".", "ViolationTrends_MEDIUM"]
      ]
    }
  ] : []

  # Combine all widgets
  all_widgets = concat(
    local.widgets_all,
    local.analytics_widgets
  )

  metric_widgets = [
    for idx, w in local.all_widgets : {
      type   = "metric"
      x      = (idx % 3) * 8
      y      = 3 + floor(idx / 3) * 6 # Start after alarm widgets
      width  = 8
      height = 6
      properties = merge(w, {
        region  = data.aws_region.current.region
        view    = "timeSeries"
        stacked = false
        period  = contains(keys(w), "analytics") ? 3600 : 300 # 1 hour for analytics, 5 min for others
      })
    }
  ]
}

resource "aws_cloudwatch_metric_alarm" "lambda_errors_alarms" {
  for_each = local.lambda_functions

  alarm_name          = "${var.name_prefix}-lambda-errors-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "Errors"
  namespace           = "AWS/Lambda"
  period              = 300
  statistic           = "Sum"
  threshold           = 1
  alarm_description   = "Alarm if Lambda ${each.key} has errors"

  dimensions = {
    FunctionName = each.value.name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_composite_alarm" "lambda_errors_composite" {
  count             = length(local.lambda_functions) > 0 ? 1 : 0
  alarm_name        = "${var.name_prefix}-lambda-errors-composite"
  alarm_description = "Composite alarm triggered if any Lambda function has errors"

  alarm_rule = join(" OR ", [
    for key in keys(local.lambda_functions) :
    "ALARM(${aws_cloudwatch_metric_alarm.lambda_errors_alarms[key].alarm_name})"
  ])
}

# Alarm for EventBridge Rule Failures

locals {
  eventbridge_rules = merge(
    {
      "iam_violations" = {
        name = aws_cloudwatch_event_rule.iam_violations.name
        arn  = aws_cloudwatch_event_rule.iam_violations.arn
      },
      "remediation_status" = {
        name = aws_cloudwatch_event_rule.remediation_status.name
        arn  = aws_cloudwatch_event_rule.remediation_status.arn
      },
      "iam_events" = {
        name = aws_cloudwatch_event_rule.iam_events.name
        arn  = aws_cloudwatch_event_rule.iam_events.arn
      }
    },
    var.enable_priority_alerts ? {
      "high_severity_violations" = {
        name = aws_cloudwatch_event_rule.high_severity_violations[0].name
        arn  = aws_cloudwatch_event_rule.high_severity_violations[0].arn
      }
    } : {}
  )
}

resource "aws_cloudwatch_metric_alarm" "eventbridge_failures" {
  for_each = local.eventbridge_rules

  alarm_name          = "${var.name_prefix}-eventbridge-failures-${each.key}"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "FailedInvocations"
  namespace           = "AWS/Events"
  period              = "300"
  statistic           = "Sum"
  threshold           = "3"
  alarm_description   = "This metric monitors EventBridge rule failures"

  dimensions = {
    RuleName = each.value.name
  }

  tags = local.common_tags
}

resource "aws_cloudwatch_composite_alarm" "eventbridge_failures_composite" {
  count             = length(local.eventbridge_rules) > 0 ? 1 : 0
  alarm_name        = "${var.name_prefix}-eventbridge-failures-composite"
  alarm_description = "Composite alarm triggered if EventBridge rule fails"

  alarm_rule = join(" OR ", [
    for key in keys(local.eventbridge_rules) :
    "ALARM(${aws_cloudwatch_metric_alarm.eventbridge_failures[key].alarm_name})"
  ])
}

locals {
  alarms = compact([
    try(aws_cloudwatch_composite_alarm.sns_delivery_composite[0].arn, null),
    try(aws_cloudwatch_composite_alarm.sqs_backlog_composite[0].arn, null),
    try(aws_cloudwatch_composite_alarm.lambda_errors_composite[0].arn, null),
    try(aws_cloudwatch_composite_alarm.eventbridge_failures_composite[0].arn, null),
    try(aws_cloudwatch_metric_alarm.test_failures[0].arn, null),
    try(aws_cloudwatch_metric_alarm.high_risk_principals_alarm[0].arn, null),
    try(aws_cloudwatch_metric_alarm.potential_attacks_alarm[0].arn, null),
    try(aws_cloudwatch_metric_alarm.critical_violation_spike[0].arn, null)
  ])

  # Alarm widgets
  alarm_widgets = [
    {
      type   = "alarm"
      x      = 0
      y      = 0
      width  = 24
      height = 3
      properties = {
        alarms = local.alarms
        title  = "IAM Monitor Alarms"
        region = data.aws_region.current.region
      }
    }
  ]
}

# ===== CLOUDWATCH DASHBOARD =====
resource "aws_cloudwatch_dashboard" "iam_policy_monitor" {
  count          = var.enable_cloudwatch_dashboard ? 1 : 0
  dashboard_name = "${var.name_prefix}-dashboard"

  dashboard_body = jsonencode({
    widgets = concat(
      local.alarm_widgets,
      local.metric_widgets
    )
  })
}

# ============================================================================
# Composite Alarms for Overall System Health
# ============================================================================

# Analytics-based Security Alarms (when Athena is enabled)
resource "aws_cloudwatch_metric_alarm" "high_risk_principals_alarm" {
  count               = var.enable_athena_table && var.enable_sns_alerts ? 1 : 0
  alarm_name          = "${var.name_prefix}-high-risk-principals"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "HighRiskPrincipals"
  namespace           = "IAMPolicyMonitor/Analytics"
  period              = "3600" # 1 hour
  statistic           = "Maximum"
  threshold           = "5"
  alarm_description   = "Multiple principals showing suspicious IAM activity patterns"
  alarm_actions       = var.enable_priority_alerts ? [aws_sns_topic.priority_alerts[0].arn] : [aws_sns_topic.alerts[0].arn]
  treat_missing_data  = "notBreaching"

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "potential_attacks_alarm" {
  count               = var.enable_athena_table && var.enable_sns_alerts ? 1 : 0
  alarm_name          = "${var.name_prefix}-potential-policy-attacks"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "1"
  metric_name         = "PotentialAttacks"
  namespace           = "IAMPolicyMonitor/Analytics"
  period              = "3600" # 1 hour
  statistic           = "Maximum"
  threshold           = "2"
  alarm_description   = "Potential coordinated policy manipulation attacks detected"
  alarm_actions       = var.enable_priority_alerts ? [aws_sns_topic.priority_alerts[0].arn] : [aws_sns_topic.alerts[0].arn]
  treat_missing_data  = "notBreaching"

  tags = local.common_tags
}

resource "aws_cloudwatch_metric_alarm" "critical_violation_spike" {
  count               = var.enable_athena_table && var.enable_sns_alerts ? 1 : 0
  alarm_name          = "${var.name_prefix}-critical-violation-spike"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "ViolationTrends_CRITICAL"
  namespace           = "IAMPolicyMonitor/Analytics"
  period              = "3600" # 1 hour
  statistic           = "Sum"
  threshold           = "10"
  alarm_description   = "Unusual spike in critical IAM policy violations"
  alarm_actions       = var.enable_priority_alerts ? [aws_sns_topic.priority_alerts[0].arn] : [aws_sns_topic.alerts[0].arn]
  treat_missing_data  = "notBreaching"

  tags = local.common_tags
}


# EventBridge rule to run analytics every hour
resource "aws_cloudwatch_event_rule" "analytics_schedule" {
  count               = var.enable_athena_table ? 1 : 0
  name                = "${var.name_prefix}-analytics-schedule"
  description         = "Run IAM policy analytics every hour"
  schedule_expression = "rate(1 hour)"
  tags                = local.common_tags
}

resource "aws_cloudwatch_event_target" "analytics_scheduler" {
  count     = var.enable_athena_table ? 1 : 0
  rule      = aws_cloudwatch_event_rule.analytics_schedule[0].name
  target_id = "AnalyticsSchedulerTarget"
  arn       = aws_lambda_function.analytics_scheduler[0].arn

  input = jsonencode({
    action = "run_analytics"
  })
}
