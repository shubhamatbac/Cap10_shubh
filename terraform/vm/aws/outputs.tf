output "ssh_user" {
  value = "ubuntu"
}

output "expires_at" {
  value = var.expires_at
}

output "vms" {
  value = [for i, v in aws_instance.vm : {
    name       = "${var.lab_name}-${i + 1}"
    public_ip  = v.public_ip
    private_ip = v.private_ip
  }]
}
