output "service_account_email" {
  value       = google_service_account.decoy.email
  description = "Decoy service account email"
}

output "service_account_key" {
  value       = google_service_account_key.decoy.private_key
  sensitive   = true
  description = "Decoy service account key (store in Vault)"
}
