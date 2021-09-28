output "public_ip_address" {
  description = "The public ip of the instance."
  value       = module.ec2.*.public_ip
}
