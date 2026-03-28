terraform {
  required_providers {
    azuread = {
      source  = "hashicorp/azuread"
      version = "~> 2.0"
    }
  }
}

provider "azuread" {}

resource "azuread_application" "decoy" {
  display_name = var.app_name
}

resource "azuread_service_principal" "decoy" {
  client_id = azuread_application.decoy.client_id
}

resource "azuread_service_principal_password" "decoy" {
  service_principal_id = azuread_service_principal.decoy.id
  display_name         = "decoy-secret"
}
