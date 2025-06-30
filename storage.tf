# IAM Policy Monitor - Storage Resources
# S3 buckets, objects, and Athena analytics

# S3 Bucket for Rules, Configs, and Logs
resource "aws_s3_bucket" "rules_and_logs" {
  bucket        = local.bucket_name
  force_destroy = var.force_destroy_s3
  tags          = local.common_tags
}

resource "aws_s3_bucket_versioning" "rules_and_logs" {
  bucket = aws_s3_bucket.rules_and_logs.id
  versioning_configuration {
    status = var.enable_s3_versioning ? "Enabled" : "Disabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "rules_and_logs" {
  bucket = aws_s3_bucket.rules_and_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "rules_and_logs" {
  bucket = aws_s3_bucket.rules_and_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# S3 Bucket for Athena Results (conditional)
resource "aws_s3_bucket" "athena_results" {
  count         = var.enable_athena_table ? 1 : 0
  bucket        = "${local.bucket_name}-athena-results"
  force_destroy = var.force_destroy_s3
  tags          = local.common_tags
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  count  = var.enable_athena_table ? 1 : 0
  bucket = aws_s3_bucket.athena_results[0].id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Locals for config file paths (allows overrides)
locals {
  rules_file_path               = var.custom_rules_file != "" ? var.custom_rules_file : "${path.module}/templates/rules.yaml"
  suppress_file_path            = var.custom_suppress_file != "" ? var.custom_suppress_file : "${path.module}/templates/suppress.yaml"
  notification_config_file_path = var.custom_notification_config_file != "" ? var.custom_notification_config_file : "${path.module}/templates/notification-config.yaml"
  remediator_config_file_path   = var.custom_remediator_config_file != "" ? var.custom_remediator_config_file : "${path.module}/templates/remediator-config.json"
}

# Upload Rules Configuration
resource "aws_s3_object" "rules" {
  bucket      = aws_s3_bucket.rules_and_logs.bucket
  key         = "rules.yaml"
  source      = local.rules_file_path
  source_hash = filemd5(local.rules_file_path)
  tags        = local.common_tags
}

# Upload Suppression Configuration
resource "aws_s3_object" "suppress" {
  bucket      = aws_s3_bucket.rules_and_logs.bucket
  key         = "suppress.yaml"
  source      = local.suppress_file_path
  source_hash = filemd5(local.suppress_file_path)
  tags        = local.common_tags
}

# Upload Notification Configuration
resource "aws_s3_object" "notification_config" {
  bucket      = aws_s3_bucket.rules_and_logs.bucket
  key         = "notification-config.yaml"
  source      = local.notification_config_file_path
  source_hash = filemd5(local.notification_config_file_path)
  tags        = local.common_tags
}

# Upload Remediator Configuration
resource "aws_s3_object" "remediator_config" {
  bucket      = aws_s3_bucket.rules_and_logs.bucket
  key         = "remediator-config.json"
  source      = local.remediator_config_file_path
  source_hash = filemd5(local.remediator_config_file_path)
  tags        = local.common_tags
}

# Lambda package
data "archive_file" "lambda_terraform" {
  type        = "zip"
  output_path = "${path.module}/lambdas/dist/lambda-terraform.zip"

  source {
    content  = file("${path.module}/lambdas/detector.py")
    filename = "detector.py"
  }

  source {
    content  = file("${path.module}/lambdas/remediator.py")
    filename = "remediator.py"
  }

  source {
    content  = file("${path.module}/lambdas/sns_publisher.py")
    filename = "sns_publisher.py"
  }

  source {
    content  = file("${path.module}/lambdas/slack_handler.py")
    filename = "slack_handler.py"
  }

  source {
    content  = file("${path.module}/lambdas/audit_logger.py")
    filename = "audit_logger.py"
  }

  source {
    content  = file("${path.module}/lambdas/metrics_publisher.py")
    filename = "metrics_publisher.py"
  }

  source {
    content  = file("${path.module}/lambdas/athena_table_creator.py")
    filename = "athena_table_creator.py"
  }

  source {
    content  = file("${path.module}/lambdas/violation_event.py")
    filename = "violation_event.py"
  }

  source {
    content  = file("${path.module}/lambdas/slack_notifier.py")
    filename = "slack_notifier.py"
  }

  source {
    content  = file("${path.module}/lambdas/requirements.txt")
    filename = "requirements.txt"
  }
}

# Upload Lambda package to S3
resource "aws_s3_object" "lambda_package" {
  bucket = aws_s3_bucket.rules_and_logs.bucket
  key    = "lambda-artifacts/lambda-package.zip"

  # Use pre-built package if it exists, otherwise use Terraform-built package
  source      = fileexists("${path.module}/lambdas/dist/lambda-package.zip") ? "${path.module}/lambdas/dist/lambda-package.zip" : data.archive_file.lambda_terraform.output_path
  source_hash = fileexists("${path.module}/lambdas/dist/lambda-package.zip") ? filemd5("${path.module}/lambdas/dist/lambda-package.zip") : data.archive_file.lambda_terraform.output_md5

  tags = local.common_tags
}

# Athena Database (conditional)
resource "aws_athena_database" "violations" {
  count  = var.enable_athena_table ? 1 : 0
  name   = "${replace(var.name_prefix, "-", "_")}_violations"
  bucket = aws_s3_bucket.athena_results[0].bucket
}

# Athena cleanup resource for destroy-time table cleanup
# This runs during terraform destroy when force_destroy_athena = true
resource "null_resource" "athena_cleanup" {
  count = var.enable_athena_table && var.force_destroy_athena ? 1 : 0

  # This runs ONLY during destroy
  provisioner "local-exec" {
    when    = destroy
    command = <<-EOT
      # Get database name from triggers
      DB_NAME="${self.triggers.database_name}"

      # Delete all tables and views first
      echo "Cleaning up Athena database: $DB_NAME"

      # Get and delete all tables
      TABLES=$(aws glue get-tables --database-name "$DB_NAME" --query 'TableList[].Name' --output text 2>/dev/null || echo "")
      if [ -n "$TABLES" ] && [ "$TABLES" != "None" ]; then
        for table in $TABLES; do
          echo "Dropping table: $table"
          aws glue delete-table --database-name "$DB_NAME" --name "$table" || true
        done
      fi

      echo "Athena cleanup completed for database: $DB_NAME"
    EOT

    # Handle errors gracefully - don't fail the destroy if cleanup fails
    on_failure = continue
  }

  # Store values needed during destroy
  triggers = {
    database_name = aws_athena_database.violations[0].name
    force_destroy = var.force_destroy_athena
  }

  # Ensure this runs before database destruction
  depends_on = [aws_athena_database.violations[0]]
}
