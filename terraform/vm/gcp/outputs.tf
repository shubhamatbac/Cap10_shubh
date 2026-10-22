output "ssh_user" {
  value = "ubuntu"
}

output "expires_at" {
  value = var.expires_at
}

output "vms" {
  value = [for v in google_compute_instance.vm : {
    name       = v.name
    public_ip  = v.network_interface[0].access_config[0].nat_ip
    private_ip = v.network_interface[0].network_ip
  }]
}
