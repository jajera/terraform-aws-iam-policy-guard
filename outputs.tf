# S3 Outputs
output "rules_bucket_name" {
  description = "S3 bucket for rules and logs"
  value       = aws_s3_bucket.rules_and_logs.bucket
}

output "rules_bucket_arn" {
  description = "ARN of S3 bucket for rules and logs"
  value       = aws_s3_bucket.rules_and_logs.arn
}

# Lambda Outputs
output "detector_lambda_arn" {
  description = "IAM Detector Lambda ARN"
  value       = aws_lambda_function.detector.arn
}

output "detector_lambda_name" {
  description = "IAM Detector Lambda function name"
  value       = aws_lambda_function.detector.function_name
}

output "remediator_lambda_arn" {
  description = "IAM Remediator Lambda ARN"
  value       = var.enable_remediation ? aws_lambda_function.remediator[0].arn : null
}

output "remediator_lambda_name" {
  description = "IAM Remediator Lambda function name"
  value       = var.enable_remediation ? aws_lambda_function.remediator[0].function_name : null
}

# Event-Driven Lambda Outputs
output "sns_publisher_lambda_arn" {
  description = "SNS Publisher Lambda ARN"
  value       = var.enable_sns_alerts ? aws_lambda_function.sns_publisher[0].arn : null
}

output "slack_handler_lambda_arn" {
  description = "Slack Handler Lambda ARN"
  value       = var.enable_slack_alerts ? aws_lambda_function.slack_handler[0].arn : null
}

output "audit_logger_lambda_arn" {
  description = "Audit Logger Lambda ARN"
  value       = aws_lambda_function.audit_logger.arn
}

output "metrics_publisher_lambda_arn" {
  description = "Metrics Publisher Lambda ARN"
  value       = aws_lambda_function.metrics_publisher.arn
}

# EventBridge Outputs
output "eventbridge_rule_arn" {
  description = "EventBridge Rule ARN"
  value       = aws_cloudwatch_event_rule.iam_events.arn
}

output "eventbridge_rule_name" {
  description = "EventBridge Rule name"
  value       = aws_cloudwatch_event_rule.iam_events.name
}

output "eventbridge_bus_arn" {
  description = "EventBridge Bus ARN for IAM violations"
  value       = aws_cloudwatch_event_bus.iam_violations.arn
}

output "eventbridge_bus_name" {
  description = "EventBridge Bus name for IAM violations"
  value       = aws_cloudwatch_event_bus.iam_violations.name
}

# SNS Outputs
output "sns_topic_arn" {
  description = "SNS Topic ARN"
  value       = var.enable_sns_alerts ? aws_sns_topic.alerts[0].arn : null
}

output "sns_topic_name" {
  description = "SNS Topic name"
  value       = var.enable_sns_alerts ? aws_sns_topic.alerts[0].name : null
}

output "priority_sns_topic_arn" {
  description = "Priority SNS Topic ARN for high severity violations"
  value       = var.enable_priority_alerts ? aws_sns_topic.priority_alerts[0].arn : null
}

# SQS Outputs
output "sqs_queue_arn" {
  description = "SQS Queue ARN for remediation"
  value       = var.enable_remediation ? aws_sqs_queue.remediation[0].arn : null
}

output "sqs_queue_url" {
  description = "SQS Queue URL for remediation"
  value       = var.enable_remediation ? aws_sqs_queue.remediation[0].url : null
}

output "eventbridge_dlq_arn" {
  description = "EventBridge Dead Letter Queue ARN"
  value       = aws_sqs_queue.eventbridge_dlq.arn
}

# CloudWatch Outputs
output "cloudwatch_log_group_detector" {
  description = "CloudWatch Log Group for detector Lambda"
  value       = aws_cloudwatch_log_group.detector.name
}

output "cloudwatch_log_group_remediator" {
  description = "CloudWatch Log Group for remediator Lambda"
  value       = var.enable_remediation ? aws_cloudwatch_log_group.remediator[0].name : null
}

output "cloudwatch_dashboard_url" {
  description = "URL to the CloudWatch dashboard"
  value       = var.enable_cloudwatch_dashboard ? "https://${data.aws_region.current.region}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.region}#dashboards:name=${aws_cloudwatch_dashboard.iam_policy_monitor[0].dashboard_name}" : null
}

# Athena Outputs
output "athena_database_name" {
  description = "Athena database name for violations"
  value       = var.enable_athena_table ? aws_athena_database.violations[0].name : null
}
output "athena_table_name" {
  description = "Athena table name for violations (always 'violations' when enabled)"
  value       = var.enable_athena_table ? "violations" : null
}

output "athena_results_bucket" {
  description = "S3 bucket for Athena query results"
  value       = var.enable_athena_table ? aws_s3_bucket.athena_results[0].bucket : null
}

output "athena_table_creator_function_name" {
  value       = var.enable_athena_table ? aws_lambda_function.athena_table_creator[0].function_name : null
  description = "Name of the Lambda function that creates the Athena table automatically"
}

# IAM Outputs
output "detector_role_arn" {
  description = "IAM role ARN for Detector Lambda"
  value       = aws_iam_role.detector.arn
}

output "remediator_role_arn" {
  description = "IAM role ARN for Remediator Lambda"
  value       = var.enable_remediation ? aws_iam_role.remediator[0].arn : null
}

output "sns_publisher_role_arn" {
  description = "IAM role ARN for SNS Publisher Lambda"
  value       = var.enable_sns_alerts ? aws_iam_role.sns_publisher[0].arn : null
}

output "slack_handler_role_arn" {
  description = "IAM role ARN for Slack Handler Lambda"
  value       = var.enable_slack_alerts ? aws_iam_role.slack_handler[0].arn : null
}

output "audit_logger_role_arn" {
  description = "IAM role ARN for Audit Logger Lambda"
  value       = aws_iam_role.audit_logger.arn
}

output "metrics_publisher_role_arn" {
  description = "IAM role ARN for Metrics Publisher Lambda"
  value       = aws_iam_role.metrics_publisher.arn
}

# Configuration Outputs
output "rules_s3_key" {
  description = "S3 key for rules configuration"
  value       = aws_s3_object.rules.key
}

output "suppress_s3_key" {
  description = "S3 key for suppression configuration"
  value       = aws_s3_object.suppress.key
}

output "notification_config_s3_key" {
  description = "S3 key for notification configuration"
  value       = aws_s3_object.notification_config.key
}

output "remediator_config_s3_key" {
  description = "S3 key for remediator configuration"
  value       = aws_s3_object.remediator_config.key
}

# Monitoring Outputs
output "violation_metric_name" {
  description = "CloudWatch metric name for violations"
  value       = "ViolationCount"
}

output "name_prefix" {
  description = "Name prefix used for all resources"
  value       = var.name_prefix
}

output "remediation_metric_name" {
  description = "CloudWatch metric name for remediation"
  value       = "RemediationSuccess"
}

output "metrics_namespace" {
  description = "CloudWatch metrics namespace"
  value       = "IAMPolicyMonitor"
}

# Output the parameter name for reference
output "slack_webhook_parameter_name" {
  description = "AWS Systems Manager Parameter Store path for Slack webhook URL"
  value       = var.enable_slack_alerts && var.slack_webhook_url != "" ? local.slack_parameter_name : null
  sensitive   = true
}

# Configuration file outputs for validation
output "config_files_used" {
  description = "Map of configuration files actually used by the module"
  value = {
    rules_file          = local.rules_file_path
    suppress_file       = local.suppress_file_path
    notification_config = local.notification_config_file_path
    remediator_config   = local.remediator_config_file_path
  }
}

output "bedrock_model_arn_for_analysis" {
  value       = var.enable_bedrock_analysis ? data.aws_bedrock_foundation_model.claude_sonnet[0].model_arn : "Bedrock analysis is disabled."
  description = "The ARN of the Bedrock model used for analysis. If plan/apply fails referencing this output, enable the model in the Bedrock console."
}

# ============================================================================
# Testing Infrastructure Outputs
# ============================================================================

output "codebuild_project_name" {
  description = "Name of the CodeBuild project for manual testing"
  value       = var.create_tests ? aws_codebuild_project.iam_policy_monitor_tests[0].name : null
}

output "codebuild_project_arn" {
  description = "ARN of the CodeBuild project for manual testing"
  value       = var.create_tests ? aws_codebuild_project.iam_policy_monitor_tests[0].arn : null
}

output "testing_log_group_name" {
  description = "CloudWatch log group name for manual testing"
  value       = var.create_tests ? aws_cloudwatch_log_group.codebuild_testing[0].name : null
}
