#
variable "node" {
  description = "Validator config"
  type = object({
    base_image         = string
    start_cmd          = string
    name               = string
    chain_spec          = string
  })
}

# 
variable "vm" {
  description = "vm config"
  type = object({
    region         = string
    instance_type  = string
    instance_count = number
    volume_type    = string
    volume_size    = number
  })
  default = {
    # aws
    region         = "ap-northeast-1"
    instance_type  = "t3.small"
    instance_count = 1
    volume_type    = "gp2"
    volume_size    = 80
    # gcp
    # project        = ""
    # region         = "asia-northeast1"
    # instance_type  = "e2-small"
    # instance_count = 1
    # volume_type    = "pd-standard"
    # volume_size    = 80
  }
}

#
variable "node_exporter" {
  description = "Prometheus node exporter"
  type = object({
    node_exporter_enabled         = bool
    node_exporter_binary_url      = string
    node_exporter_binary_checksum = string
    node_exporter_port            = number
    node_exporter_user            = string
    node_exporter_password        = string
  })
  default = {
    node_exporter_enabled         = false
    node_exporter_binary_url      = "https://github.com/prometheus/node_exporter/releases/download/v1.1.2/node_exporter-1.1.2.linux-amd64.tar.gz"
    node_exporter_binary_checksum = "sha256:8c1f6a317457a658e0ae68ad710f6b4098db2cad10204649b51e3c043aa3e70d"
    node_exporter_port            = 9100
    node_exporter_user            = "prometheus"
    node_exporter_password        = "node_exporter"
  }
}
