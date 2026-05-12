variable "release_name" {
  type    = string
  default = "ferrox"
}

variable "namespace" {
  type    = string
  default = "ferrox"
}

variable "chart_repository" {
  type    = string
  default = "https://ferrox-rs.github.io/ferrox"
}

variable "chart_name" {
  type    = string
  default = "ferrox"
}

variable "chart_version" {
  type    = string
  default = "1.0.0"
}

variable "image_repository" {
  type    = string
  default = "ghcr.io/ferrox-rs/ferrox"
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

variable "persistence_size" {
  type    = string
  default = "10Gi"
}

variable "max_req_per_sec" {
  type    = number
  default = 0
}
