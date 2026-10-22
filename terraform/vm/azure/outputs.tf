output "ssh_user" {
  value = "azureuser"
}

output "expires_at" {
  value = var.expires_at
}

output "vms" {
  value = [for i, v in azurerm_linux_virtual_machine.vm : {
    name       = v.name
    public_ip  = azurerm_public_ip.vm[i].ip_address
    private_ip = v.private_ip_address
  }]
}
