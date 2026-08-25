output "pubsub_topic" {
  description = "The Pub/Sub topic to publish audit logs to."
  value       = google_pubsub_topic.roleflux_logs.id
}

output "service_account_email" {
  description = "The service account email running the RoleFlux engine."
  value       = google_service_account.roleflux_sa.email
}

output "bigquery_dataset" {
  description = "The BigQuery dataset where findings are stored."
  value       = google_bigquery_dataset.roleflux_analytics.dataset_id
}

output "cloud_function_url" {
  description = "The URL of the deployed Cloud Function engine."
  value       = google_cloudfunctions2_function.roleflux_engine.service_config[0].uri
}
