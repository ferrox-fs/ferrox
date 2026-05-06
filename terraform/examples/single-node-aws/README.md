# Single-node AWS deployment

Provisions a single EC2 instance running ferroxd via Docker, backed by an encrypted EBS gp3 volume and fronted by an Elastic IP.

## Run

```sh
cd terraform/examples/single-node-aws
terraform init
terraform validate
terraform apply \
  -var "ami_id=ami-0xxxxxxxx" \
  -var "access_key=AKIA..." \
  -var "secret_key=..." \
  -var 'ssh_cidrs=["203.0.113.10/32"]'
```

`terraform apply` prints the public endpoint, e.g. `http://203.0.113.42:9000`.

## Upgrade

Bump the AMI id or rebuild the user-data with a newer `image_tag`:

```sh
terraform apply -var "image_tag=v1.0.1"
```

The launch template re-runs user-data so a fresh ferroxd container pulls the new tag.

## Security group

Inbound rules:

- 9000/tcp — S3 plain HTTP, open to the world
- 9443/tcp — S3 HTTPS, open to the world
- 22/tcp  — SSH, restricted to `var.ssh_cidrs`
