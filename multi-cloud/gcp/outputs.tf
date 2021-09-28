output "public_ip_address" {
  description = "The public ip of the instance."
  value       = google_compute_instance.instance.*.network_interface.0.access_config.0.nat_ip
}
