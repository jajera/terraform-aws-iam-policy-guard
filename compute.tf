# IAM Policy Monitor - Compute Resources
# Lambda functions, packaging, and event source mappings

# ===== DETECTOR LAMBDA =====

resource "aws_lambda_function" "detector" {
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-detector"
  role             = aws_iam_role.detector.arn
  handler          = "detector.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      RULES_BUCKET            = aws_s3_bucket.rules_and_logs.id
      RULES_KEY               = aws_s3_object.rules.key
      SUPPRESS_KEY            = aws_s3_object.suppress.key
      EVENTBRIDGE_BUS_NAME    = aws_cloudwatch_event_bus.iam_violations.name
      SQS_QUEUE_URL           = var.enable_remediation ? aws_sqs_queue.remediation[0].url : ""
      ENABLE_REMEDIATION      = var.enable_remediation
      DEBUG                   = var.debug_mode
      ENABLE_BEDROCK_ANALYSIS = var.enable_bedrock_analysis
      BEDROCK_MODEL_ID        = var.bedrock_model_id
      # Fallback configuration for direct mode
      SNS_TOPIC_ARN           = var.enable_sns_alerts && length(aws_sns_topic.alerts) > 0 ? aws_sns_topic.alerts[0].arn : ""
      SLACK_WEBHOOK_PARAMETER = local.slack_parameter_name
      SEVERITY_COLORS         = jsonencode(var.severity_colors)
    }
  }

  depends_on = [
    aws_iam_role_policy.detector,
    aws_cloudwatch_log_group.detector,
    aws_s3_object.rules,
    aws_s3_object.suppress,
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== REMEDIATOR LAMBDA =====

resource "aws_lambda_function" "remediator" {
  count            = var.enable_remediation ? 1 : 0
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-remediator"
  role             = aws_iam_role.remediator[0].arn
  handler          = "remediator.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.remediator_memory_size
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      RULES_BUCKET            = aws_s3_bucket.rules_and_logs.bucket
      CONFIG_KEY              = "remediator-config.json"
      SNS_TOPIC_ARN           = var.enable_sns_alerts && length(aws_sns_topic.alerts) > 0 ? aws_sns_topic.alerts[0].arn : ""
      SLACK_WEBHOOK_PARAMETER = local.slack_parameter_name
      DRY_RUN                 = var.dry_run_mode
      DEBUG                   = var.debug_mode ? "true" : "false"
      EVENTBRIDGE_BUS_NAME    = "${var.name_prefix}-iam-violations"
      SEVERITY_COLORS         = jsonencode(var.severity_colors)
    }
  }

  depends_on = [
    aws_iam_role_policy.remediator[0],
    aws_cloudwatch_log_group.remediator[0],
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# SQS trigger for remediator
resource "aws_lambda_event_source_mapping" "remediator_sqs" {
  count            = var.enable_remediation ? 1 : 0
  event_source_arn = aws_sqs_queue.remediation[0].arn
  function_name    = aws_lambda_function.remediator[0].arn
  batch_size       = 10
}

# ===== SNS PUBLISHER LAMBDA =====

resource "aws_lambda_function" "sns_publisher" {
  count            = var.enable_sns_alerts ? 1 : 0
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-sns-publisher"
  role             = aws_iam_role.sns_publisher[0].arn
  handler          = "sns_publisher.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      SNS_TOPIC_ARN   = aws_sns_topic.alerts[0].arn
      DEBUG           = var.debug_mode ? "true" : "false"
      SEVERITY_COLORS = jsonencode(var.severity_colors)
    }
  }

  depends_on = [
    aws_iam_role_policy.sns_publisher[0],
    aws_cloudwatch_log_group.sns_publisher[0],
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== SLACK HANDLER LAMBDA =====

resource "aws_lambda_function" "slack_handler" {
  count            = var.enable_slack_alerts ? 1 : 0
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-slack-handler"
  role             = aws_iam_role.slack_handler[0].arn
  handler          = "slack_handler.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      SLACK_WEBHOOK_PARAMETER = local.slack_parameter_name
      RULES_BUCKET            = aws_s3_bucket.rules_and_logs.bucket
      CONFIG_KEY              = "notification-config.yaml"
      DEBUG                   = var.debug_mode ? "true" : "false"
      SEVERITY_COLORS         = jsonencode(var.severity_colors)
    }
  }

  depends_on = [
    aws_iam_role_policy.slack_handler[0],
    aws_cloudwatch_log_group.slack_handler[0],
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== AUDIT LOGGER LAMBDA =====

resource "aws_lambda_function" "audit_logger" {
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-audit-logger"
  role             = aws_iam_role.audit_logger.arn
  handler          = "audit_logger.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      AUDIT_BUCKET     = aws_s3_bucket.rules_and_logs.bucket
      AUDIT_KEY_PREFIX = "violations"
      DEBUG            = var.debug_mode ? "true" : "false"
    }
  }

  depends_on = [
    aws_iam_role_policy.audit_logger,
    aws_cloudwatch_log_group.audit_logger,
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== METRICS PUBLISHER LAMBDA =====

resource "aws_lambda_function" "metrics_publisher" {
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-metrics-publisher"
  role             = aws_iam_role.metrics_publisher.arn
  handler          = "metrics_publisher.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = var.lambda_timeout
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      CLOUDWATCH_NAMESPACE = "IAMPolicyMonitor"
      DEBUG                = var.debug_mode ? "true" : "false"
    }
  }

  depends_on = [
    aws_iam_role_policy.metrics_publisher,
    aws_cloudwatch_log_group.metrics_publisher,
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== ATHENA TABLE CREATOR LAMBDA =====

resource "aws_lambda_function" "athena_table_creator" {
  count            = var.enable_athena_table ? 1 : 0
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-athena-table-creator"
  role             = aws_iam_role.athena_table_creator[0].arn
  handler          = "athena_table_creator.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = 60
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      ATHENA_DATABASE_NAME  = "${replace(var.name_prefix, "-", "_")}_violations"
      ATHENA_RESULTS_BUCKET = var.enable_athena_table ? aws_s3_bucket.athena_results[0].bucket : ""
      TABLE_LOCATION        = "s3://${aws_s3_bucket.rules_and_logs.bucket}/violations/"
      DEBUG                 = var.debug_mode ? "true" : "false"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.athena_table_creator[0],
    aws_iam_role_policy.athena_table_creator[0],
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# ===== ANALYTICS SCHEDULER LAMBDA =====

resource "aws_lambda_function" "analytics_scheduler" {
  count            = var.enable_athena_table ? 1 : 0
  s3_bucket        = aws_s3_object.lambda_package.bucket
  s3_key           = aws_s3_object.lambda_package.key
  function_name    = "${var.name_prefix}-analytics-scheduler"
  role             = aws_iam_role.athena_table_creator[0].arn
  handler          = "athena_table_creator.lambda_handler"
  runtime          = var.lambda_runtime
  memory_size      = var.lambda_memory
  timeout          = 300
  source_code_hash = aws_s3_object.lambda_package.etag

  environment {
    variables = {
      ATHENA_DATABASE_NAME  = aws_athena_database.violations[0].name
      ATHENA_RESULTS_BUCKET = aws_s3_bucket.athena_results[0].bucket
      TABLE_LOCATION        = "s3://${aws_s3_bucket.rules_and_logs.bucket}/violations/"
      ANALYTICS_MODE        = "scheduled"
    }
  }

  depends_on = [
    aws_cloudwatch_log_group.analytics_scheduler[0],
    aws_lambda_invocation.create_athena_table[0],
    aws_s3_object.lambda_package
  ]

  tags = local.common_tags
}

# Custom resource to trigger table creation
resource "aws_lambda_invocation" "create_athena_table" {
  count         = var.enable_athena_table ? 1 : 0
  function_name = aws_lambda_function.athena_table_creator[0].function_name

  input = jsonencode({
    action = "create_table"
  })

  depends_on = [aws_lambda_function.athena_table_creator[0]]
}

resource "aws_lambda_permission" "analytics_scheduler_eventbridge" {
  count         = var.enable_athena_table ? 1 : 0
  statement_id  = "AllowExecutionFromEventBridge"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.analytics_scheduler[0].function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.analytics_schedule[0].arn
}
