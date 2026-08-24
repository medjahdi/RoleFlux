output "pubsub_topic" {
  description = "The Pub/Sub topic to send mock logs to for testing."
  value       = google_pubsub_topic.roleflux_logs.id
}

output "cloud_function_name" {
  description = "The deployed Cloud Function name."
  value       = google_cloudfunctions2_function.roleflux_engine.name
}

output "service_account_email" {
  description = "The Service Account the function runs as."
  value       = google_service_account.roleflux_sa.email
}
