# AWS Systems Manager Parameter Store for Slack Configuration
# Automatically creates secure parameter store entries for Slack webhook URLs

locals {
  # Auto-generate parameter name if not provided
  slack_parameter_name = var.slack_webhook_parameter_name != "" ? var.slack_webhook_parameter_name : "/${var.name_prefix}/slack-webhook"
}

# Slack webhook URL parameter (created only if Slack alerts are enabled and URL is provided)
resource "aws_ssm_parameter" "slack_webhook" {
  count = var.enable_slack_alerts && var.slack_webhook_url != "" ? 1 : 0

  name        = local.slack_parameter_name
  description = "Slack webhook URL for IAM policy violation notifications"
  type        = "SecureString"
  value       = var.slack_webhook_url

  tags = merge(local.common_tags, {
    Component = "Slack Integration"
    Sensitive = "true"
  })
}
