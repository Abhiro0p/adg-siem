output "access_key_id" {
  value       = aws_iam_access_key.decoy.id
  description = "Decoy access key ID"
}

output "secret_access_key" {
  value       = aws_iam_access_key.decoy.secret
  sensitive   = true
  description = "Decoy secret key (store in Vault)"
}
