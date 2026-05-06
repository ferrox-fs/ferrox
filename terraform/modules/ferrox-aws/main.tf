terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

resource "aws_security_group" "ferrox" {
  name        = "${var.name}-sg"
  description = "Ferrox: HTTP 9000 + HTTPS 9443"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 9000
    to_port     = 9000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 9443
    to_port     = 9443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = var.ssh_cidrs
  }
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  tags = var.tags
}

resource "aws_ebs_volume" "data" {
  availability_zone = var.availability_zone
  size              = var.data_volume_size_gb
  type              = "gp3"
  encrypted         = true
  tags              = merge(var.tags, { Name = "${var.name}-data" })
}

resource "aws_instance" "ferrox" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.ferrox.id]
  key_name               = var.ssh_key_name
  availability_zone      = var.availability_zone

  user_data = templatefile("${path.module}/user_data.sh.tftpl", {
    image_tag    = var.image_tag,
    access_key   = var.access_key,
    secret_key   = var.secret_key,
    enable_acme  = var.enable_acme,
    domain_name  = var.domain_name,
  })

  tags = merge(var.tags, { Name = var.name })
}

resource "aws_volume_attachment" "data" {
  device_name = "/dev/sdf"
  volume_id   = aws_ebs_volume.data.id
  instance_id = aws_instance.ferrox.id
}

resource "aws_eip" "ferrox" {
  count    = var.allocate_eip ? 1 : 0
  instance = aws_instance.ferrox.id
  domain   = "vpc"
  tags     = var.tags
}
