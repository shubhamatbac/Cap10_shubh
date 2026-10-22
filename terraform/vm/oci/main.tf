terraform {
  required_version = ">= 1.6"
  required_providers {
    oci = {
      source  = "oracle/oci"
      version = "~> 6.20"
    }
  }
  # State lives in OCI Object Storage through its S3-compatible API (configured at init).
  backend "s3" {}
}

provider "oci" {
  tenancy_ocid = var.tenancy_ocid
  user_ocid    = var.user_ocid
  fingerprint  = var.fingerprint
  private_key  = var.private_key
  region       = var.region
}

locals {
  # Flexible shape: OCPU / memory per size.
  shapes = {
    small  = { ocpus = 1, memory = 4 }
    medium = { ocpus = 2, memory = 8 }
    large  = { ocpus = 4, memory = 16 }
  }
  os_version = replace(var.os, "ubuntu-", "")
  tags = {
    lab_name       = var.lab_name
    lab_owner      = var.owner
    lab_expires_at = var.expires_at
    lab_managed_by = "github-actions-lab"
  }
}

data "oci_identity_availability_domains" "ads" {
  compartment_id = var.tenancy_ocid
}

data "oci_core_images" "ubuntu" {
  compartment_id           = var.compartment_ocid
  operating_system         = "Canonical Ubuntu"
  operating_system_version = local.os_version
  shape                    = "VM.Standard.E4.Flex"
  sort_by                  = "TIMECREATED"
  sort_order               = "DESC"
}

resource "oci_core_vcn" "lab" {
  compartment_id = var.compartment_ocid
  cidr_blocks    = ["10.80.0.0/16"]
  display_name   = "lab-${var.lab_name}"
  dns_label      = "lab${substr(replace(var.lab_name, "-", ""), 0, 10)}"
  freeform_tags  = local.tags
}

resource "oci_core_internet_gateway" "lab" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "lab-${var.lab_name}"
  freeform_tags  = local.tags
}

resource "oci_core_route_table" "lab" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "lab-${var.lab_name}"
  freeform_tags  = local.tags
  route_rules {
    destination       = "0.0.0.0/0"
    destination_type  = "CIDR_BLOCK"
    network_entity_id = oci_core_internet_gateway.lab.id
  }
}

resource "oci_core_security_list" "lab" {
  compartment_id = var.compartment_ocid
  vcn_id         = oci_core_vcn.lab.id
  display_name   = "lab-${var.lab_name}"
  freeform_tags  = local.tags

  egress_security_rules {
    destination = "0.0.0.0/0"
    protocol    = "all"
  }
  ingress_security_rules {
    source   = var.allowed_cidr
    protocol = "6"
    tcp_options {
      min = 22
      max = 22
    }
  }
  ingress_security_rules {
    source   = "10.80.0.0/16"
    protocol = "all"
  }
}

resource "oci_core_subnet" "lab" {
  compartment_id    = var.compartment_ocid
  vcn_id            = oci_core_vcn.lab.id
  cidr_block        = "10.80.1.0/24"
  display_name      = "lab-${var.lab_name}"
  route_table_id    = oci_core_route_table.lab.id
  security_list_ids = [oci_core_security_list.lab.id]
  freeform_tags     = local.tags
}

resource "oci_core_instance" "vm" {
  count               = var.vm_count
  compartment_id      = var.compartment_ocid
  availability_domain = data.oci_identity_availability_domains.ads.availability_domains[0].name
  display_name        = "${var.lab_name}-${count.index + 1}"
  shape               = "VM.Standard.E4.Flex"
  freeform_tags       = local.tags

  shape_config {
    ocpus         = local.shapes[var.size].ocpus
    memory_in_gbs = local.shapes[var.size].memory
  }
  source_details {
    source_type = "image"
    source_id   = data.oci_core_images.ubuntu.images[0].id
    # OCI boot volumes are at least 50 GB.
    boot_volume_size_in_gbs = max(var.disk_gb, 50)
  }
  create_vnic_details {
    subnet_id        = oci_core_subnet.lab.id
    assign_public_ip = true
    hostname_label   = "${substr(replace(var.lab_name, "-", ""), 0, 10)}${count.index + 1}"
  }
  metadata = {
    ssh_authorized_keys = var.ssh_public_key
  }
  lifecycle {
    ignore_changes = [source_details[0].source_id]
  }
}
