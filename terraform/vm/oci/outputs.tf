output "ssh_user" {
  value = "ubuntu"
}

output "expires_at" {
  value = var.expires_at
}

output "vms" {
  value = [for v in oci_core_instance.vm : {
    name       = v.display_name
    public_ip  = v.public_ip
    private_ip = v.private_ip
  }]
}
