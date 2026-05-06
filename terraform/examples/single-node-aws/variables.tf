variable "region" {
  type    = string
  default = "us-east-1"
}

variable "ami_id" {
  type        = string
  description = "Linux AMI (Ubuntu 22.04 or AL2023) — region-specific"
}

variable "ssh_key_name" {
  type    = string
  default = null
}

variable "ssh_cidrs" {
  type    = list(string)
  default = []
}

variable "access_key" { type = string }
variable "secret_key" {
  type      = string
  sensitive = true
}
