terraform {
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 5.0"
    }
  }
}

provider "google" {}

resource "google_service_account" "decoy" {
  account_id   = var.account_id
  display_name = "Decoy Service Account"
}

resource "google_service_account_key" "decoy" {
  service_account_id = google_service_account.decoy.name
}
