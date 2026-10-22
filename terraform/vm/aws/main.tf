terraform {
  required_version = ">= 1.6"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.80"
    }
  }
  backend "s3" {}
}

provider "aws" {
  region = var.region
  default_tags {
    tags = local.tags
  }
}

locals {
  sizes = { small = "t3.micro", medium = "t3.small", large = "t3.medium" }
  ami_param = {
    "ubuntu-24.04" = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
    "ubuntu-22.04" = "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id"
  }
  tags = {
    "lab:name"       = var.lab_name
    "lab:owner"      = var.owner
    "lab:expires_at" = var.expires_at
    "lab:managed_by" = "github-actions-lab"
  }
}

data "aws_ssm_parameter" "ami" {
  name = local.ami_param[var.os]
}

data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_vpc" "lab" {
  cidr_block           = "10.50.0.0/16"
  enable_dns_hostnames = true
  tags                 = { Name = "lab-${var.lab_name}" }
}

resource "aws_internet_gateway" "lab" {
  vpc_id = aws_vpc.lab.id
}

resource "aws_subnet" "lab" {
  vpc_id                  = aws_vpc.lab.id
  cidr_block              = "10.50.1.0/24"
  availability_zone       = data.aws_availability_zones.available.names[0]
  map_public_ip_on_launch = true
  tags                    = { Name = "lab-${var.lab_name}" }
}

resource "aws_route_table" "lab" {
  vpc_id = aws_vpc.lab.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.lab.id
  }
}

resource "aws_route_table_association" "lab" {
  subnet_id      = aws_subnet.lab.id
  route_table_id = aws_route_table.lab.id
}

resource "aws_security_group" "lab" {
  name_prefix = "lab-${var.lab_name}-"
  vpc_id      = aws_vpc.lab.id

  ingress {
    description = "SSH from the allowed source"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.allowed_cidr]
  }
  ingress {
    description = "Traffic between lab VMs"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    self        = true
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_key_pair" "lab" {
  key_name   = "lab-${var.lab_name}"
  public_key = var.ssh_public_key
}

resource "aws_instance" "vm" {
  count                  = var.vm_count
  ami                    = data.aws_ssm_parameter.ami.insecure_value
  instance_type          = local.sizes[var.size]
  subnet_id              = aws_subnet.lab.id
  vpc_security_group_ids = [aws_security_group.lab.id]
  key_name               = aws_key_pair.lab.key_name
  user_data              = "#!/bin/bash\nhostnamectl set-hostname ${var.lab_name}-${count.index + 1}\n"

  metadata_options {
    http_tokens   = "required"
    http_endpoint = "enabled"
  }
  root_block_device {
    volume_size = var.disk_gb
    volume_type = "gp3"
    encrypted   = true
  }
  tags = { Name = "${var.lab_name}-${count.index + 1}" }
  lifecycle {
    ignore_changes = [ami, user_data]
  }
}
