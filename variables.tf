# General Configuration
variable "name_prefix" {
  description = "Prefix for all resource names"
  type        = string
  default     = "iam-policy-monitor"
}

variable "common_tags" {
  description = "Common tags to apply to all resources"
  type        = map(string)
  default     = {}
}

# S3 Configuration
variable "bucket_name" {
  description = "S3 bucket name for config and logs (if not provided, will be auto-generated)"
  type        = string
  default     = ""
}

variable "enable_s3_versioning" {
  description = "Enable versioning on S3 bucket"
  type        = bool
  default     = true
}

# Lambda Configuration
variable "lambda_memory" {
  description = "Default Lambda memory size in MB for detector and notification functions"
  type        = number
  default     = 256
}

variable "remediator_memory_size" {
  description = "Default Lambda memory size in MB for remediator function"
  type        = number
  default     = 512
}

variable "lambda_timeout" {
  description = "Lambda timeout in seconds"
  type        = number
  default     = 300
}

variable "lambda_runtime" {
  description = "Lambda runtime version"
  type        = string
  default     = "python3.13"

  validation {
    condition     = can(regex("^python3\\.(\\d+)$", var.lambda_runtime))
    error_message = "Only Python runtimes like 'python3.12' or 'python3.13' are allowed."
  }
}

# Remediation Configuration
variable "enable_remediation" {
  description = "Enable automatic remediation of violations"
  type        = bool
  default     = false
}

variable "remediation_actions" {
  description = "List of allowed remediation actions"
  type        = list(string)
  default     = ["delete_policy", "detach_user_policy", "detach_role_policy"]
}

# Alerting Configuration
variable "sns_alert_email" {
  description = "Optional email address for SNS alerts"
  type        = string
  default     = ""
}

variable "enable_slack_alerts" {
  description = "Enable Slack webhook alerts"
  type        = bool
  default     = false
}

variable "slack_webhook_url" {
  description = "Slack webhook URL for notifications (will be stored securely in Parameter Store)"
  type        = string
  default     = ""
  sensitive   = true
}

variable "slack_webhook_parameter_name" {
  description = "AWS Systems Manager Parameter Store path for Slack webhook URL (auto-generated if not provided)"
  type        = string
  default     = ""
}

# Monitoring Configuration
variable "enable_cloudwatch_dashboard" {
  description = "Create CloudWatch dashboard"
  type        = bool
  default     = true
}

variable "enable_cloudwatch_alarms" {
  description = "Create CloudWatch alarms for monitoring"
  type        = bool
  default     = true
}

variable "enable_athena_table" {
  description = "Create Athena table for historical reporting"
  type        = bool
  default     = true
}

# EventBridge Configuration
variable "eventbridge_rule_description" {
  description = "Description for EventBridge rule"
  type        = string
  default     = "Captures IAM-related events for policy monitoring"
}

variable "enable_sns_alerts" {
  description = "Enable SNS notifications for violations"
  type        = bool
  default     = true
}

variable "enable_priority_alerts" {
  description = "Enable priority SNS topic for high/critical severity violations"
  type        = bool
  default     = true
}

# Tags alias for backward compatibility
variable "tags" {
  description = "Common tags to apply to all resources (alias for common_tags)"
  type        = map(string)
  default     = {}
}

# SQS Configuration
variable "sqs_visibility_timeout" {
  description = "SQS message visibility timeout in seconds"
  type        = number
  default     = 900
}

variable "sqs_message_retention" {
  description = "SQS message retention period in seconds"
  type        = number
  default     = 1209600 # 14 days
}

# CloudWatch Configuration
variable "log_retention_days" {
  description = "CloudWatch logs retention period in days"
  type        = number
  default     = 30
}

# Dry Run Configuration
variable "dry_run_mode" {
  description = "Enable dry-run mode for remediator (no actual changes)"
  type        = bool
  default     = true
}

# Debug Configuration
variable "debug_mode" {
  description = "Enable debug logging for all Lambda functions"
  type        = bool
  default     = false
}

# Configuration File Overrides
variable "custom_rules_file" {
  description = "Path to custom rules.yaml file (overrides default templates/rules.yaml)"
  type        = string
  default     = ""
}

variable "custom_suppress_file" {
  description = "Path to custom suppress.yaml file (overrides default templates/suppress.yaml)"
  type        = string
  default     = ""
}

variable "custom_notification_config_file" {
  description = "Path to custom notification-config.yaml file (overrides default)"
  type        = string
  default     = ""
}

variable "custom_remediator_config_file" {
  description = "Path to custom remediator-config.json file (overrides default)"
  type        = string
  default     = ""
}

# Force destroy options (use with caution)
variable "force_destroy_s3" {
  description = "Force destroy S3 buckets even if they contain objects (use with caution in production)"
  type        = bool
  default     = false
}

variable "force_destroy_logs" {
  description = "Force destroy CloudWatch log groups even if they contain logs (use with caution in production)"
  type        = bool
  default     = false
}

variable "force_destroy_athena" {
  description = "Force destroy Athena database even if it contains tables/views (use with caution in production)"
  type        = bool
  default     = false
}

variable "enable_bedrock_analysis" {
  description = "Enable AI-powered risk analysis for IAM policy violations using Amazon Bedrock."
  type        = bool
  default     = false
}

variable "bedrock_model_id" {
  description = "The model ID to use for Bedrock analysis. E.g., 'anthropic.claude-v2'."
  type        = string
  default     = "anthropic.claude-3-sonnet-20240229-v1:0"
}

variable "severity_colors" {
  description = "Map of severity levels to hex color codes for Slack notifications. Pass as a map, not jsonencode()."
  type        = map(string)
  default = {
    CRITICAL = "#FF0000"
    HIGH     = "#FF4500"
    MEDIUM   = "#FFA500"
    LOW      = "#FFFF00"
    INFO     = "#D3D3D3"
  }
}

variable "create_tests" {
  description = "Create CodeBuild project for manual IAM Policy Monitor testing"
  type        = bool
  default     = false
}
