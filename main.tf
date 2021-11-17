# workspace
resource "random_id" "this" {
  byte_length = 8
}

resource "null_resource" "workspace" {
  triggers = {
    workspace = random_id.this.hex
  }

  provisioner "local-exec" {
    command = "mkdir -p workspace/${random_id.this.hex}/ssh"
  }

  provisioner "local-exec" {
    when    = destroy
    command = "rm -rf workspace/${self.triggers.workspace}"
  }
}

resource "null_resource" "ssh-key" {
  triggers = {
    ssh_key = random_id.this.hex
  }

  provisioner "local-exec" {
    command = "ssh-keygen -t rsa -P '' -f workspace/${random_id.this.hex}/ssh/id_rsa <<<y"
  }
  depends_on = [null_resource.workspace]
}


# aws | gcp | ...
module "node" {
  # source          = "./multi-cloud/aws"
  source          = "./multi-cloud/gcp"
  region          = var.vm.region
  instance_count  = var.vm.instance_count
  instance_type   = var.vm.instance_type
  volume_type     = var.vm.volume_type
  volume_size     = var.vm.volume_size
  public_key_file = abspath("workspace/${random_id.this.hex}/ssh/id_rsa.pub")
  id              = random_id.this.hex
}


# ansible
resource "local_file" "ansible-inventory" {
  filename = "workspace/${random_id.this.hex}/ansible_inventory"
  content  = templatefile("${path.module}/ansible/ansible_inventory.tpl", {
    public_ips  = module.node.public_ip_address
  })
}

module "ansible" {
  source = "./terraform-ansible-playbook"

  user               = "ubuntu"
  ips                = module.node.public_ip_address
  playbook_file_path = "ansible/playbook.yml"
  private_key_path   = "workspace/${random_id.this.hex}/ssh/id_rsa"
  inventory_file     = local_file.ansible-inventory.filename
  playbook_vars      = {
    base_image         = var.node.base_image
    start_cmd          = var.node.start_cmd
    node_name          = var.node.name
    chain_spec         = var.node.chain_spec

    node_exporter_enabled         = var.node_exporter.node_exporter_enabled
    node_exporter_binary_url      = var.node_exporter.node_exporter_binary_url
    node_exporter_binary_checksum = var.node_exporter.node_exporter_binary_checksum
    node_exporter_port            = var.node_exporter.node_exporter_port
    node_exporter_user            = var.node_exporter.node_exporter_user
    node_exporter_password        = var.node_exporter.node_exporter_password
  }
  temporary_path     = "workspace/${random_id.this.hex}"
}

output "ip_address" {
  description = ""
  value = module.node.public_ip_address
}
