# IAM Policy Monitor - Core Infrastructure
# Data sources, locals, and shared resources

# ===== DATA SOURCES =====

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# ===== LOCALS =====

locals {
  bucket_name = "${var.name_prefix}-${data.aws_caller_identity.current.account_id}-${data.aws_region.current.region}"

  common_tags = merge(
    var.tags,
    {
      "Name"      = var.name_prefix
      "ManagedBy" = "terraform"
      "Project"   = "iam-policy-monitor"
    }
  )
}

# ===== BEDROCK PRE-FLIGHT CHECK =====
# This data source validates that the specified foundation model has been enabled
# in the AWS Bedrock console for this account and region. If 'terraform plan'
# fails here, it means you must manually enable model access.
data "aws_bedrock_foundation_model" "claude_sonnet" {
  count = var.enable_bedrock_analysis ? 1 : 0

  model_id = var.bedrock_model_id
}
