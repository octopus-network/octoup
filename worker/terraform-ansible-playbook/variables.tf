variable "create" {
  description = "Boolean to ignore resource creation"
  type        = bool
  default     = true
}

variable "force_create" {
  description = "Force apply resources - overrides normal watcher for change in resources to apply."
  type        = bool
  default     = false
}

variable "module_depends_on" {
  description = "Any to have module depend on"
  type        = any
  default     = null
}

variable "requirements_file_path" {
  description = "The path to a requirements file for ansible galaxy"
  type        = string
  default     = ""
}

###################
# Playbook Env Vars
###################
variable "private_key_path" {
  description = "Path to SSH private key to configure the node"
  type        = string
}

variable "playbook_file_path" {
  description = "Absolute path to playbook file to configure the node"
  type        = string
  default     = ""
}

variable "playbook_template_path" {
  description = "A path to a go templated playbook yml file"
  type        = string
  default     = ""
}

variable "playbook_template_vars" {
  description = "A map of variables for the playbook go template"
  type        = map(string)
  default     = {}
}

variable "roles_dir" {
  description = "Absolute path to roles directory to configure the node"
  type        = string
  default     = ""
}

#################
# Inventory Items
#################
variable "ip" {
  description = "The elastic ip address of the node being configured."
  default     = ""
}

variable "ips" {
  description = "A list of IPs to run against"
  type        = list(string)
  default     = null
}

variable "inventory" {
  description = "Not implemented"
  type        = map(string)
  default     = {}
}

variable "inventory_file" {
  description = "The path to an inventory file"
  type        = string
  default     = ""
}

variable "inventory_template" {
  description = "The path to a template to run against"
  type        = string
  default     = ""
}

variable "inventory_template_vars" {
  description = "A map of values to render the inventory template with"
  type        = map(string)
  default     = {}
}

############
# ssh Config
############
variable "cidr_block_matches" {
  description = "CIDR blocks to use for the bastion host"
  type        = list(string)
  default     = ["10.*.*.*", "17.??.*.*", "192.168.*.*"]
}

variable "bastion_user" {
  description = "The bastion user name"
  type        = string
  default     = ""
}

variable "bastion_ip" {
  description = "The IP of the bastion host"
  type        = string
  default     = ""
}

###############
# Playbook Args
###############
variable "user" {
  description = "The user used to configure the node"
  type        = string
}

variable "verbose" {
  description = "Boolean to force verbose mode on ansible call"
  type        = bool
  default     = false
}

variable "playbook_vars" {
  description = "Extra vars to include in run"
  type        = map(any)
  default     = {}
}

variable "playbook_vars_file" {
  description = "A path to a json / yaml for extra vars"
  type        = string
  default     = ""
}

variable "forks" {
  description = "specify number of parallel processes to use (default=5)"
  type        = number
  default     = 5
}

variable "become" {
  description = "Become root flag"
  type        = bool
  default     = false
}

variable "become_user" {
  description = "The user to become"
  type        = string
  default     = "root"
}

variable "become_method" {
  description = "privilege escalation method to use (default=%(default)s)"
  type        = string
  default     = "sudo"
}

variable "ask_vault_pass" {
  description = "ask for vault password"
  type        = bool
  default     = false
}

variable "flush_cache" {
  description = "clear the fact cache for every host in inventory"
  type        = bool
  default     = false
}

variable "force_handlers" {
  description = "run handlers even if a task fails"
  type        = bool
  default     = false
}

variable "scp_extra_args" {
  description = "specify extra arguments to pass to scp only (e.g. -l)"
  type        = string
  default     = ""
}

variable "sftp_extra_args" {
  description = "specify extra arguments to pass to sftp only (e.g. -f, -l)"
  type        = string
  default     = ""
}

variable "skip_tags" {
  description = "only run plays and tasks whose tags do not match these values"
  type        = string
  default     = ""
}

variable "ssh_common_args" {
  description = "specify common arguments to pass to sftp/scp/ssh (e.g. ProxyCommand)"
  type        = string
  default     = ""
}

variable "ssh_extra_args" {
  description = "specify extra arguments to pass to ssh only (e.g. -R)"
  type        = string
  default     = "-p 22 -o ConnectTimeout=10 -o ConnectionAttempts=10 -o StrictHostKeyChecking=no -o IdentitiesOnly=yes"
}

variable "start_at_task" {
  description = "start the playbook at the task matching this name"
  type        = string
  default     = ""
}

variable "step" {
  description = "one-step-at-a-time: confirm each task before running"
  type        = bool
  default     = false
}

variable "tags" {
  description = "only run plays and tasks tagged with these values"
  type        = string
  default     = ""
}

variable "vault_id" {
  description = "the vault identity to use"
  type        = string
  default     = ""
}

variable "vault_password_file" {
  description = "vault password file"
  type        = string
  default     = ""
}

#######
# Other
#######
variable "cleanup" {
  description = "Debugging boolean to leave rendered files after call"
  type        = bool
  default     = false
}

#######
# Other
#######
variable "temporary_path" {
  description = ""
  type        = string
}

