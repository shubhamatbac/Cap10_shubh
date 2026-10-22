terraform {
  required_version = ">= 1.6"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 4.10"
    }
  }
  backend "azurerm" {}
}

# Credentials come from ARM_* environment variables (OIDC); nothing is stored in code.
provider "azurerm" {
  features {}
}

locals {
  sizes = { small = "Standard_B1s", medium = "Standard_B2s", large = "Standard_B2ms" }
  image = {
    "ubuntu-24.04" = { offer = "ubuntu-24_04-lts", sku = "server" }
    "ubuntu-22.04" = { offer = "0001-com-ubuntu-server-jammy", sku = "22_04-lts-gen2" }
  }
  tags = {
    "lab-name"       = var.lab_name
    "lab-owner"      = var.owner
    "lab-expires-at" = var.expires_at
    "lab-managed-by" = "github-actions-lab"
  }
}

resource "azurerm_resource_group" "lab" {
  name     = "rg-lab-${var.lab_name}"
  location = var.region
  tags     = local.tags
}

resource "azurerm_virtual_network" "lab" {
  name                = "vnet-${var.lab_name}"
  address_space       = ["10.60.0.0/16"]
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags
}

resource "azurerm_subnet" "lab" {
  name                 = "lab"
  resource_group_name  = azurerm_resource_group.lab.name
  virtual_network_name = azurerm_virtual_network.lab.name
  address_prefixes     = ["10.60.1.0/24"]
}

resource "azurerm_network_security_group" "lab" {
  name                = "nsg-${var.lab_name}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  security_rule {
    name                       = "ssh"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = var.allowed_cidr
    destination_address_prefix = "*"
  }
}

resource "azurerm_subnet_network_security_group_association" "lab" {
  subnet_id                 = azurerm_subnet.lab.id
  network_security_group_id = azurerm_network_security_group.lab.id
}

resource "azurerm_public_ip" "vm" {
  count               = var.vm_count
  name                = "pip-${var.lab_name}-${count.index + 1}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  allocation_method   = "Static"
  sku                 = "Standard"
  tags                = local.tags
}

resource "azurerm_network_interface" "vm" {
  count               = var.vm_count
  name                = "nic-${var.lab_name}-${count.index + 1}"
  location            = azurerm_resource_group.lab.location
  resource_group_name = azurerm_resource_group.lab.name
  tags                = local.tags

  ip_configuration {
    name                          = "primary"
    subnet_id                     = azurerm_subnet.lab.id
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm[count.index].id
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  count                           = var.vm_count
  name                            = "${var.lab_name}-${count.index + 1}"
  computer_name                   = "${var.lab_name}-${count.index + 1}"
  location                        = azurerm_resource_group.lab.location
  resource_group_name             = azurerm_resource_group.lab.name
  size                            = local.sizes[var.size]
  admin_username                  = "azureuser"
  disable_password_authentication = true
  network_interface_ids           = [azurerm_network_interface.vm[count.index].id]
  tags                            = local.tags

  admin_ssh_key {
    username   = "azureuser"
    public_key = var.ssh_public_key
  }
  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "StandardSSD_LRS"
    disk_size_gb         = var.disk_gb
  }
  source_image_reference {
    publisher = "Canonical"
    offer     = local.image[var.os].offer
    sku       = local.image[var.os].sku
    version   = "latest"
  }
}
