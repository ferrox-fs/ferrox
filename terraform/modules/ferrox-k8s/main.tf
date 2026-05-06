terraform {
  required_version = ">= 1.5"
  required_providers {
    helm = {
      source  = "hashicorp/helm"
      version = ">= 2.12"
    }
  }
}

resource "helm_release" "ferrox" {
  name       = var.release_name
  namespace  = var.namespace
  repository = var.chart_repository
  chart      = var.chart_name
  version    = var.chart_version
  create_namespace = true

  values = [
    yamlencode({
      image = {
        repository = var.image_repository
        tag        = var.image_tag
      }
      credentials = {
        accessKey = var.access_key
        secretKey = var.secret_key
      }
      persistence = {
        enabled = true
        size    = var.persistence_size
      }
      maxReqPerSec = var.max_req_per_sec
    })
  ]
}
