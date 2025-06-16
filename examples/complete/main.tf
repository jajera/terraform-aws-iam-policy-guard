# Complete IAM Policy Monitor Example
# This example deploys ALL optional features: remediation, priority alerts, CloudWatch dashboard,
# Athena analytics table, and AI-powered risk analysis with Amazon Bedrock.

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 6.0"
    }
  }
}

# Configure the AWS Provider
# Using us-east-1 for IAM monitoring as CloudTrail global events originate here
# and it has the most comprehensive AWS service availability
provider "aws" {
  region = "us-east-1"
}

# Generate a random suffix for uniqueness
resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}

locals {
  name = "complete-example-${random_string.suffix.result}"
  tags = {
    Environment = "development"
    Project     = "terraform-aws-iam-policy-guard-complete"
    Owner       = "terraform"
    Example     = "complete"
  }
}

module "cloudtrail" {
  source = "tfstack/cloudtrail/aws"

  name = local.name

  # Enable CloudTrail and create the required S3 bucket
  create_s3_bucket = true

  # Force destroy for testing - allows easy cleanup
  s3_bucket_force_destroy = true

  # Minimal S3 lifecycle: expire logs quickly to stay under free tier (5GB/month)
  s3_bucket_lifecycle_configuration = [
    {
      id     = "free-tier-expire-fast"
      status = "Enabled"
      filter = {
        prefix = "" # Or use "AWSLogs/" depending on your CloudTrail config
      }
      expiration = {
        days = 7
      }
    }
  ]

  # Disable optional features that incur cost
  create_cloudwatch_log_group = false
  create_kms_key              = false
  create_sns_topic            = false

  tags = local.tags
}

# Full-featured deployment with production-ready features
module "iam_policy_monitor" {
  source = "../../"

  # Core configuration
  name_prefix       = local.name
  sns_alert_email   = var.alert_email
  slack_webhook_url = var.slack_webhook_url

  # Production features enabled
  enable_remediation          = true
  enable_slack_alerts         = true
  enable_sns_alerts           = true
  enable_priority_alerts      = true
  enable_cloudwatch_dashboard = true
  enable_athena_table         = true

  # Enable AI-powered risk analysis
  enable_bedrock_analysis = true
  bedrock_model_id        = "anthropic.claude-3-sonnet-20240229-v1:0"

  # Lambda configuration optimized for production
  lambda_memory          = 256 # Complete functions
  remediator_memory_size = 512 # More memory for complex operations

  # Production logging retention
  log_retention_days   = 30
  force_destroy_logs   = true # Only for demo - set to false in production
  force_destroy_s3     = true # Only for demo - set to false in production
  force_destroy_athena = true # Only for demo - set to false in production

  # Use local configuration files from this example
  custom_remediator_config_file = "${path.module}/remediator-config.json"

  severity_colors = {
    CRITICAL = "#FF0000"
    HIGH     = "#FF0000"
    MEDIUM   = "#FFA500"
    LOW      = "#FFFF00"
    SUCCESS  = "#2EB67D"
  }

  # Debug mode
  debug_mode = true

  # Testing
  create_tests = true

  common_tags = {
    Environment = "development"
    Purpose     = "iam-monitoring"
    Example     = "complete"
    Owner       = var.owner
  }
}

output "test_commands" {
  value = <<-EOT

    #################### 🧪 TESTING COMMANDS ####################

    🟢 [1] START TEST
    aws codebuild start-build \
      --project-name "${module.iam_policy_monitor.name_prefix}-iam-policy-monitor-tests" \
      --query "build.id" \
      --output text

    🟢 [2] OPEN DASHBOARD
    https://console.aws.amazon.com/cloudwatch/home?region=us-east-1#dashboards:name=${module.iam_policy_monitor.name_prefix}-dashboard

    🟢 [3] CHECK TEST STATUS
    aws codebuild batch-get-builds \
      --ids $(aws codebuild list-builds-for-project \
        --project-name "${module.iam_policy_monitor.name_prefix}-iam-policy-monitor-tests" \
        --query 'ids[0]' \
        --output text)

    🟢 [4] VIEW TEST LOGS
    aws logs get-log-events \
      --log-group-name "/aws/codebuild/${module.iam_policy_monitor.name_prefix}-iam-policy-monitor-tests" \
      --log-stream-name "$(aws logs describe-log-streams \
        --log-group-name "/aws/codebuild/${module.iam_policy_monitor.name_prefix}-iam-policy-monitor-tests" \
        --order-by LastEventTime \
        --descending \
        --query 'logStreams[0].logStreamName' \
        --output text)"

    EOT
}
