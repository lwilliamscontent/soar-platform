variable "aws_account_id" {
  type        = string
  description = "The only AWS account authorized for this deployment."

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "aws_region" {
  type        = string
  description = "Primary deployment Region."
}

variable "environment" {
  type        = string
  description = "Environment name."
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "environment must be dev, staging, or prod."
  }
}

variable "lambda_artifact_bucket" {
  type        = string
  description = "Existing bucket containing immutable Lambda artifacts."
}

variable "ingestor_artifact_key" {
  type = string
}

variable "enricher_artifact_key" {
  type = string
}

variable "responder_artifact_key" {
  type = string
}

variable "allowed_response_accounts" {
  type        = list(string)
  description = "AWS accounts eligible for approved response actions."
  default     = []
}

variable "monthly_budget_usd" {
  type        = number
  description = "Monthly cost budget for the playground."
  default     = 25

  validation {
    condition     = var.monthly_budget_usd > 0
    error_message = "monthly_budget_usd must be greater than zero."
  }
}

variable "budget_alert_email" {
  type        = string
  description = "Email address for AWS Budget alerts. Leave empty to omit the budget subscription."
  default     = ""

  validation {
    condition     = var.budget_alert_email == "" || can(regex("^[^@[:space:]]+@[^@[:space:]]+\\.[^@[:space:]]+$", var.budget_alert_email))
    error_message = "budget_alert_email must be empty or a valid email address."
  }
}
