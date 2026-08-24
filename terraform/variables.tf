variable "project_id" {
  description = "The GCP Project ID where RoleFlux will be deployed."
  type        = string
}

variable "region" {
  description = "The GCP region to deploy resources (e.g., us-central1)."
  type        = string
  default     = "us-central1"
}

variable "slack_webhook_url" {
  description = "The Slack Webhook URL for alerting. (Passed via CLI or terraform.tfvars)"
  type        = string
  sensitive   = true
}

variable "monitor_org_level" {
  description = "Set to true to monitor the entire GCP Organization, false to monitor just this project."
  type        = bool
  default     = false
}

variable "organization_id" {
  description = "The GCP Organization ID (required if monitor_org_level is true)."
  type        = string
  default     = ""
}
