output "client_id" {
  value       = azuread_application.decoy.client_id
  description = "Decoy application client ID"
}

output "client_secret" {
  value       = azuread_service_principal_password.decoy.value
  sensitive   = true
  description = "Decoy client secret (store in Vault)"
}
