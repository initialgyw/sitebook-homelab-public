variable "cloudflare_account_id" {}

locals {
  cloudflare_zones = toset(keys(yamldecode(file("config-dns.yml"))["cloudflare"]["zones"]))
}

resource "cloudflare_zone" "zone" {
  for_each   = local.cloudflare_zones
  account_id = var.cloudflare_account_id
  zone       = each.key
}

output "cloudflare_zones" {
  value = { for zone in cloudflare_zone.zone : zone.zone => zone.id }
}
