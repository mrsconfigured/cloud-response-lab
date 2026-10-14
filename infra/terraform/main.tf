terraform {
  required_version = ">= 1.5.0, < 2.0.0"
}

# Plan-only description of existing-host deployment. No provider or resource,
# provisioner, SSH, Docker socket, local-exec, credentials or cloud billing API.
variable "existing_host_label" {
  type        = string
  default     = "personal-existing-host"
  description = "Inventory label only, never an address or credential."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{2,40}$", var.existing_host_label))
    error_message = "Use a non-sensitive inventory label."
  }
}

variable "window_minutes" {
  type    = number
  default = 25
  validation {
    condition     = var.window_minutes >= 5 && var.window_minutes <= 25 && floor(var.window_minutes) == var.window_minutes
    error_message = "Bounded reviewed windows must be 5 through 25 whole minutes."
  }
}

locals {
  v1      = jsondecode(file("${path.module}/../compose.v1.json"))
  shuffle = jsondecode(file("${path.module}/../compose.staged.json"))
  manifest = {
    mode                = "plan-only-no-deployment"
    host                = var.existing_host_label
    window_minutes      = var.window_minutes
    minimum_free_ram_gib = 4
    minimum_free_disk_gib = 10
    v1_compose_sha256    = filesha256("${path.module}/../compose.v1.json")
    staged_compose_sha256 = filesha256("${path.module}/../compose.staged.json")
    v1_services         = keys(local.v1.services)
    shuffle_services    = keys(local.shuffle.services)
    preserve_volumes     = true
    activation_blockers = ["persistent host isolation review", "secrets generated on host", "reviewed stop-before-rollback timer", "Shuffle worker isolation and execution proof"]
  }
}

output "deployment_manifest" {
  value = local.manifest
  precondition {
    condition     = alltrue([for s in values(local.v1.services) : s.restart == "no" && length(try(s.ports, [])) == 0])
    error_message = "V1 must have no published ports and no restart policy."
  }
  precondition {
    condition     = alltrue([for n in values(local.v1.networks) : n.internal])
    error_message = "V1 networks must be internal. This alone does not isolate the host gateway."
  }
}
