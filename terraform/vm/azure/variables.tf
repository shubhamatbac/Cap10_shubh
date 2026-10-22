variable "lab_name" {
  type        = string
  description = "Unique lab name (lowercase letters, digits, hyphens)."
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,23}$", var.lab_name))
    error_message = "lab_name must be 2-24 chars: lowercase letters, digits, hyphens, starting with a letter."
  }
}

variable "region" {
  type = string
}

variable "size" {
  type    = string
  default = "small"
  validation {
    condition     = contains(["small", "medium", "large"], var.size)
    error_message = "size must be small, medium or large."
  }
}

variable "os" {
  type    = string
  default = "ubuntu-24.04"
  validation {
    condition     = contains(["ubuntu-24.04", "ubuntu-22.04"], var.os)
    error_message = "os must be ubuntu-24.04 or ubuntu-22.04."
  }
}

variable "vm_count" {
  type    = number
  default = 1
  validation {
    condition     = var.vm_count >= 1 && var.vm_count <= 5
    error_message = "vm_count must be between 1 and 5."
  }
}

variable "disk_gb" {
  type    = number
  default = 20
  validation {
    condition     = var.disk_gb >= 10 && var.disk_gb <= 200
    error_message = "disk_gb must be between 10 and 200."
  }
}

variable "ssh_public_key" {
  type = string
}

variable "allowed_cidr" {
  type        = string
  description = "Source CIDR allowed to SSH (use your own IP as /32)."
  validation {
    condition     = can(cidrhost(var.allowed_cidr, 0)) && var.allowed_cidr != "0.0.0.0/0"
    error_message = "allowed_cidr must be a valid CIDR and may not be 0.0.0.0/0."
  }
}

variable "expires_at" {
  type        = string
  description = "UTC expiry timestamp, recorded as a tag/label. Enforced by the reaper workflow."
}

variable "owner" {
  type    = string
  default = "unknown"
}
