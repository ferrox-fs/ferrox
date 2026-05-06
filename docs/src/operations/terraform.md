# Terraform

Modules live under `terraform/modules/`:

- `ferrox-aws/` — single-node EC2 deployment with Elastic IP + EBS data volume.
- `ferrox-k8s/` — wrapper around the Helm chart via `helm_release`.

## Single-node AWS example

```hcl
module "ferrox" {
  source = "./terraform/modules/ferrox-aws"

  instance_type        = "t3.medium"
  data_volume_size_gb  = 50
  access_key           = var.access_key
  secret_key           = var.secret_key
  domain_name          = "ferrox.example.com"
  enable_acme          = true
}

output "endpoint" {
  value = module.ferrox.endpoint_url
}
```

Run:

```sh
terraform init
terraform validate
terraform apply
```

## Upgrading

Bump `var.image_tag` or the AMI ID and re-apply. State migrations are idempotent.
