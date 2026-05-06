terraform {
  required_version = ">= 1.5"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
  }
}

module "ferrox" {
  source = "../../modules/ferrox-aws"

  name              = "ferrox"
  vpc_id            = data.aws_vpc.default.id
  subnet_id         = data.aws_subnets.default.ids[0]
  availability_zone = "${var.region}a"
  ami_id            = var.ami_id

  instance_type        = "t3.medium"
  data_volume_size_gb  = 50
  ssh_key_name         = var.ssh_key_name
  ssh_cidrs            = var.ssh_cidrs

  access_key  = var.access_key
  secret_key  = var.secret_key
  domain_name = ""
  enable_acme = false

  tags = {
    project = "ferrox"
    env     = "dev"
  }
}

output "endpoint" {
  value = module.ferrox.endpoint_url
}
