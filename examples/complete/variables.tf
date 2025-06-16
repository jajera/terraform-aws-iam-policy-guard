variable "alert_email" {
  description = "Email address to receive IAM policy violation alerts"
  type        = string

  validation {
    condition     = can(regex("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", var.alert_email))
    error_message = "Please provide a valid email address."
  }
}

variable "slack_webhook_url" {
  description = "Slack Webhook URL for sending notifications"
  type        = string
}

variable "owner" {
  description = "Owner or team responsible for the IAM Policy Monitor"
  type        = string
  default     = "terraform"
}
