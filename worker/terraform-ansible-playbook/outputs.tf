output "status" {
  value = join("", null_resource.ansible_run.*.id) == "" ? "Node NOT configured...." : "Node Configured! - ${join("", null_resource.ansible_run.*.id)}"
}

output "ip" {
  value = var.ip
}

output "ansible_sh" {
  value = data.template_file.ansible_sh.rendered
}

output "ansible_cfg" {
  value = data.template_file.ansible_cfg.rendered
}

output "ssh_cfg" {
  value = data.template_file.ssh_cfg.rendered
}
