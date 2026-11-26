# Fake-repo fixture for Tier 3 infra tests. Placeholder values only.
terraform {
  required_version = "1.6.0"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "5.0.0"
    }
    random = {
      source = "hashicorp/random"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

provider "random" {}
