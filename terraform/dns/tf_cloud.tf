terraform {
  cloud {
    organization = "homelab-ricebucket"

    workspaces {
      name = "dns"
    }
  }
}