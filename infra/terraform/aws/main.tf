terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "aws" {}

resource "aws_iam_user" "decoy" {
  name = var.user_name
  tags = {
    Purpose = "Honeytoken"
  }
}

resource "aws_iam_access_key" "decoy" {
  user = aws_iam_user.decoy.name
}
