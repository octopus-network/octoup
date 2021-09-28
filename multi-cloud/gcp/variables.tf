variable "region" {
  description = "Region"
  type        = string
}

variable "instance_type" {
  description = "Instance type"
  type        = string
  default     = "e2-small"
}

variable "instance_count" {
  description = "Instance count"
  type        = number
  default     = 1
}

variable "volume_type" {
  description = ""
  type        = string
  default     = "pd-standard"
}

variable "volume_size" {
  description = ""
  type        = number
  default     = 80
}

variable "public_key_file" {
  description = "SSH public key file path"
  type        = string
}

variable "id" {
  description = ""
  type        = string
}
