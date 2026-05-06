variable "name" {
  type    = string
  default = "ferrox"
}

variable "vpc_id" { type = string }
variable "subnet_id" { type = string }
variable "availability_zone" { type = string }

variable "ami_id" {
  description = "Linux AMI for ferroxd (Ubuntu 22.04 or Amazon Linux 2023)"
  type        = string
}

variable "instance_type" {
  type    = string
  default = "t3.medium"
}

variable "data_volume_size_gb" {
  type    = number
  default = 50
}

variable "ssh_key_name" {
  type    = string
  default = null
}

variable "ssh_cidrs" {
  type    = list(string)
  default = []
}

variable "image_tag" {
  type    = string
  default = "latest"
}

variable "access_key" { type = string }
variable "secret_key" {
  type      = string
  sensitive = true
}

variable "domain_name" {
  type    = string
  default = ""
}

variable "enable_acme" {
  type    = bool
  default = false
}

variable "allocate_eip" {
  type    = bool
  default = true
}

variable "tags" {
  type    = map(string)
  default = {}
}
