terraform {
  required_version = ">= 1.6"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "~> 6.12"
    }
  }
  backend "gcs" {}
}

provider "google" {
  project = var.project
  region  = var.region
}

locals {
  zone   = "${var.region}-a"
  sizes  = { small = "e2-micro", medium = "e2-small", large = "e2-medium" }
  family = { "ubuntu-24.04" = "ubuntu-2404-lts-amd64", "ubuntu-22.04" = "ubuntu-2204-lts" }
  labels = {
    lab_name       = var.lab_name
    lab_owner      = replace(lower(var.owner), "/[^a-z0-9_-]/", "-")
    lab_expires_at = replace(lower(var.expires_at), "/[^a-z0-9_-]/", "-")
    lab_managed_by = "github-actions-lab"
  }
}

resource "google_compute_network" "lab" {
  name                    = "lab-${var.lab_name}"
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "lab" {
  name          = "lab-${var.lab_name}"
  ip_cidr_range = "10.70.1.0/24"
  region        = var.region
  network       = google_compute_network.lab.id
}

resource "google_compute_firewall" "ssh" {
  name          = "lab-${var.lab_name}-ssh"
  network       = google_compute_network.lab.name
  source_ranges = [var.allowed_cidr]
  target_tags   = ["lab-${var.lab_name}"]
  allow {
    protocol = "tcp"
    ports    = ["22"]
  }
}

resource "google_compute_firewall" "internal" {
  name          = "lab-${var.lab_name}-internal"
  network       = google_compute_network.lab.name
  source_ranges = [google_compute_subnetwork.lab.ip_cidr_range]
  target_tags   = ["lab-${var.lab_name}"]
  allow {
    protocol = "tcp"
  }
  allow {
    protocol = "udp"
  }
  allow {
    protocol = "icmp"
  }
}

resource "google_compute_instance" "vm" {
  count        = var.vm_count
  name         = "${var.lab_name}-${count.index + 1}"
  machine_type = local.sizes[var.size]
  zone         = local.zone
  tags         = ["lab-${var.lab_name}"]
  labels       = local.labels

  boot_disk {
    initialize_params {
      image = "ubuntu-os-cloud/${local.family[var.os]}"
      size  = var.disk_gb
      type  = "pd-balanced"
    }
  }
  network_interface {
    subnetwork = google_compute_subnetwork.lab.id
    access_config {}
  }
  metadata = {
    ssh-keys               = "ubuntu:${var.ssh_public_key}"
    block-project-ssh-keys = "true"
  }
  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }
}
