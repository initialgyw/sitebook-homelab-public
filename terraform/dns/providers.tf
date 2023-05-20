terraform {
  required_providers {
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.5"
    }
  }
}

# CLOUDFLARE_API_TOKEN env var set
provider "cloudflare" {}
