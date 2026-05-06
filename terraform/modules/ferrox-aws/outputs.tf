output "instance_id" {
  value = aws_instance.ferrox.id
}

output "public_ip" {
  value = var.allocate_eip ? aws_eip.ferrox[0].public_ip : aws_instance.ferrox.public_ip
}

output "endpoint_url" {
  value = format(
    "http://%s:9000",
    var.allocate_eip ? aws_eip.ferrox[0].public_ip : aws_instance.ferrox.public_ip,
  )
}

output "security_group_id" {
  value = aws_security_group.ferrox.id
}
