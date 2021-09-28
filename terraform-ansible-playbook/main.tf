terraform {
  required_version = ">= 0.12"
}


locals {
  // Order of precedence is inventory_file > inventory_yaml > ips > ip
  inventory = var.inventory_file != "" ? var.inventory_file : var.inventory_template != "" ? "${var.temporary_path}/ansible_inventory" : var.ips != null ? "%{for ip in var.ips}${ip},%{endfor}" : var.ip != "" ? "${var.ip}," : ""

  playbook = var.playbook_template_path == "" ? var.playbook_file_path : "${var.temporary_path}/playbook_template.yml"
}

resource "null_resource" "requirements" {
  count = var.requirements_file_path == "" || ! var.create ? 0 : 1

  triggers = {
    apply_time = timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
ansible-galaxy install -r ${var.requirements_file_path} -f
EOT
  }
}

resource "null_resource" "inventory_template" {
  count = var.inventory_template == "" ? 0 : 1

  triggers = {
    apply_time = timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
cat<<EOF > ${var.temporary_path}/ansible_inventory
${templatefile(var.inventory_template, var.inventory_template_vars)}
EOF
EOT
  }
}

resource "null_resource" "playbook_template" {
  count = var.playbook_template_path == "" ? 0 : 1

  triggers = {
    apply_time = timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
cat<<EOF > ${var.temporary_path}/playbook_template.yml
${templatefile(var.playbook_template_path, var.playbook_template_vars)}
EOF
EOT
  }
}

data "template_file" "ssh_cfg" {
  template = <<-EOF
%{for cidr in var.cidr_block_matches}
Host ${cidr}
  ProxyCommand    ssh -A -W %h:%p ${var.bastion_user}@${var.bastion_ip} -F ${var.temporary_path}/ssh.cfg
  IdentityFile    ${var.private_key_path}
  StrictHostKeyChecking no
  UserKnownHostsFile=/dev/null
%{endfor}

Host ${var.bastion_ip}
  Hostname ${var.bastion_ip}
  User ${var.bastion_user}
  IdentitiesOnly yes
  IdentityFile ${var.private_key_path}
  ControlMaster auto
  ControlPath ~/.ssh/ansible-%r@%h:%p
  ControlPersist 5m
  StrictHostKeyChecking=no
  UserKnownHostsFile=/dev/null
EOF
}

data "template_file" "ansible_cfg" {
  template = <<-EOF
[ssh_connection]
ssh_args = -C -F ${var.temporary_path}/ssh.cfg
EOF
}

data "template_file" "ansible_sh" {
  template = <<-EOT
%{if var.bastion_ip != ""}
while ! nc -vz ${var.bastion_ip} 22; do
  sleep 1
done
%{endif}
ANSIBLE_SCP_IF_SSH=true
ANSIBLE_FORCE_COLOR=true
export ANSIBLE_SSH_RETRIES=10
export ANSIBLE_HOST_KEY_CHECKING=False
%{if var.roles_dir != ""}ANSIBLE_ROLES_PATH='${var.roles_dir}' %{endif}
%{if var.bastion_ip != ""}export ANSIBLE_CONFIG='${var.temporary_path}/ansible.cfg'%{endif}
ansible-playbook '${local.playbook}' \
--inventory=${local.inventory} \
--user=${var.user} \
%{if var.ask_vault_pass}--ask-vault-pass %{endif}\
%{if var.become_method != "sudo"}--become-method='${var.become_method}' %{endif}\
%{if var.become_user != "root"}--become-user='${var.become_user}' %{endif}\
%{if var.become}--become %{endif}\
%{if var.flush_cache}--flush-cache %{endif}\
%{if var.force_handlers}--force-handlers %{endif}\
%{if var.scp_extra_args != ""}--scp-extra-args='${var.scp_extra_args}' %{endif}\
%{if var.sftp_extra_args != ""}--sftp-extra-args='${var.sftp_extra_args}' %{endif}\
%{if var.skip_tags != ""}--skip-tags='${var.skip_tags}' %{endif}\
%{if var.ssh_common_args != ""}--ssh-common-args='${var.ssh_common_args}' %{endif}\
%{if var.ssh_extra_args != ""}--ssh-extra-args='${var.ssh_extra_args}' %{endif}\
%{if var.start_at_task != ""}--start-at-task='${var.start_at_task}' %{endif}\
%{if var.step}--step %{endif}\
%{if var.tags != ""}--tags='${var.tags}' %{endif}\
%{if var.vault_id != ""}--vault-id %{endif}\
%{if var.vault_password_file != ""}--vault-password-file='${var.vault_password_file}' %{endif}\
--forks=${var.forks} \
%{if var.verbose}-vvvv %{endif}\
--private-key='${var.private_key_path}' \
%{if var.playbook_vars != {} }--extra-vars='${jsonencode(var.playbook_vars)}' %{endif} \
%{if var.playbook_vars_file != ""}--extra-vars=@${var.playbook_vars_file} %{endif}
EOT
}

resource "local_file" "ssh_cfg" {
  content  = data.template_file.ssh_cfg.rendered
  filename = "${var.temporary_path}/ssh.cfg"
}

resource "local_file" "ansible_cfg" {
  content  = data.template_file.ansible_cfg.rendered
  filename = "${var.temporary_path}/ansible.cfg"
}

resource "local_file" "ansible_sh" {
  content         = data.template_file.ansible_sh.rendered
  filename        = "${var.temporary_path}/ansible.sh"
  file_permission = "0755"
}

resource "null_resource" "ansible_run" {
  count = var.create ? 1 : 0

  triggers = {
    ansible_cfg  = local_file.ansible_cfg.content
    ssh_cfg      = local_file.ssh_cfg.content
    ansible_sh   = local_file.ansible_sh.content
    playbook     = local.playbook
    inventory    = local.inventory
    force_create = var.force_create ? timestamp() : ""
  }

  provisioner "local-exec" {
    command = "${var.temporary_path}/ansible.sh"
  }

  depends_on = [local_file.ansible_sh, local_file.ansible_cfg, local_file.ssh_cfg, null_resource.requirements, null_resource.inventory_template, var.module_depends_on]
}

resource "null_resource" "cleanup" {
  count = var.cleanup && var.create ? 1 : 0

  triggers = {
    apply_time = timestamp()
  }

  provisioner "local-exec" {
    command = <<-EOT
%{if var.bastion_ip != ""}
rm -f ${var.temporary_path}/ssh.cfg
rm -f ${var.temporary_path}/ansible.cfg
%{endif}
%{if var.playbook_template_path != ""}
rm -f ${var.temporary_path}/playbook_template.yml
%{endif}
rm -f ${var.temporary_path}/ansible.sh
EOT
  }

  depends_on = [null_resource.ansible_run, var.module_depends_on]
}
