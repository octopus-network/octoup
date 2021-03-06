
provider "google" {
  project = var.project
  region  = var.region
}

data "google_client_config" "default" {
}

data "google_container_cluster" "default" {
  name     = var.cluster
  location = var.region
}

resource "google_compute_address" "default" {
  count = var.bootnodes
  name  = "ip-${var.chain_name}-${count.index}"
}

locals {
  keys_octoup = [
    for i in fileset(path.module, "${var.keys_octoup}/*/peer-id"): {
      peer_id = chomp(file(i))
      node_key = chomp(file(replace(i, "peer-id", "node-key")))
      key_dir = dirname(abspath(i))
    }
  ]

  bootnodes = [
    for idx, addr in google_compute_address.default.*.address:
      "/ip4/${addr}/tcp/30333/p2p/${local.keys_octoup[idx]["peer_id"]}"
  ]
}

provider "kubernetes" {
  host                   = "https://${data.google_container_cluster.default.endpoint}"
  token                  = data.google_client_config.default.access_token
  cluster_ca_certificate = base64decode(data.google_container_cluster.default.master_auth[0].cluster_ca_certificate)
}

resource "kubernetes_namespace" "default" {
  metadata {
    labels = {
      name = var.chain_name
    }
    name = var.chain_name
  }
}

resource "kubernetes_config_map" "default" {
  metadata {
    name      = "${var.chain_name}-config-map"
    namespace = kubernetes_namespace.default.metadata.0.name
  }
  data = {
    for i, v in local.keys_octoup: "node-key-${i}" => v["node_key"]
  }
}

resource "kubernetes_stateful_set" "default" {
  metadata {
    name      = var.chain_name
    namespace = kubernetes_namespace.default.metadata.0.name
  }
  spec {
    service_name           = "${var.chain_name}"
    pod_management_policy  = "Parallel"
    replicas               = var.bootnodes
    revision_history_limit = 5
    selector {
      match_labels = {
        k8s-app = "${var.chain_name}"
      }
    }
    template {
      metadata {
        labels = {
          k8s-app = "${var.chain_name}"
        }
      }
      spec {
        init_container {
          name              = "${var.chain_name}-init-chainspec"
          image             = "busybox"
          image_pull_policy = "IfNotPresent"
          command           = ["wget", "-O", "/substrate/chainSpec.json", var.chainspec_url]
          resources {
            limits = {
              cpu    = "100m"
              memory = "100Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "100Mi"
            }
          }
          volume_mount {
            name       = "${var.chain_name}-data"
            mount_path = "/substrate"
          }
        }
        init_container {
          name              = "${var.chain_name}-init-nodekey"
          image             = "busybox"
          image_pull_policy = "IfNotPresent"
          command           = ["sh", "-c", "cp /tmp/node-key-$${HOSTNAME##*-} /substrate/.node-key"]
          resources {
            limits = {
              cpu    = "100m"
              memory = "100Mi"
            }
            requests = {
              cpu    = "100m"
              memory = "100Mi"
            }
          }
          volume_mount {
            name       = "${var.chain_name}-data"
            mount_path = "/substrate"
          }
          volume_mount {
            name       = "${var.chain_name}-config"
            mount_path = "/tmp"
          }
        }
        container {
          name              = "${var.chain_name}-bootnodes"
          image             = var.base_image
          image_pull_policy = "IfNotPresent"
          command = [var.start_cmd]
          args = concat([
            "--chain",
            "/substrate/chainSpec.json",
            "--node-key-file",
            "/substrate/.node-key",
            "--base-path",
            "/substrate/data",
            "--port",
            "30333",
            "--rpc-external",
            "--rpc-cors",
            "all",
            "--rpc-methods",
            "Unsafe",
            "--validator",
            "--no-telemetry",
            "--prometheus-external",
            "--prometheus-port",
            "9615",
            "--wasm-execution",
            "Compiled",
            "--enable-offchain-indexing",
            "true",
          ], flatten([for i, x in local.bootnodes: ["--bootnodes", x]]))
          port {
            container_port = 9933
          }
          port {
            container_port = 30333
          }
          port {
            container_port = 9615
          }
          resources {
            limits = {
              cpu    = var.cpu_limits
              memory = var.memory_limits
            }
            requests = {
              cpu    = var.cpu_requests
              memory = var.memory_requests
            }
          }
          volume_mount {
            name       = "${var.chain_name}-data"
            mount_path = "/substrate"
          }
          readiness_probe {
            http_get {
              path = "/metrics"
              port = 9615
            }
            initial_delay_seconds = 10
            timeout_seconds       = 1
          }
          liveness_probe {
            http_get {
              path   = "/metrics"
              port   = 9615
            }
            initial_delay_seconds = 10
            timeout_seconds       = 1
          }
        }
        volume {
          name = "${var.chain_name}-config"
          config_map {
            name = kubernetes_config_map.default.metadata.0.name
          }
        }
        security_context {
          fs_group = 1000
        }
        termination_grace_period_seconds = 300
      }
    }
    volume_claim_template {
      metadata {
        name = "${var.chain_name}-data"
      }
      spec {
        access_modes       = ["ReadWriteOnce"]
        storage_class_name = var.volume_type
        resources {
          requests = {
            storage = var.volume_size
          }
        }
      }
    }
  }
}

resource "kubernetes_service" "default" {
  count = var.bootnodes
  metadata {
    name      = "${var.chain_name}-${count.index}"
    namespace = kubernetes_namespace.default.metadata.0.name
  }
  spec {
    selector = {
      "statefulset.kubernetes.io/pod-name" = "${var.chain_name}-${count.index}"
    }
    session_affinity = "ClientIP"
    port {
      name        = "p2p"
      protocol    = "TCP"
      port        = 30333
      target_port = 30333
    }
    port {
      name        = "metrics"
      port        = 9615
      target_port = 9615
    }
    type                    = "LoadBalancer"
    load_balancer_ip        = google_compute_address.default[count.index].address
    external_traffic_policy = "Local"
  }
}

resource "kubernetes_service" "internal" {
  count = var.bootnodes
  metadata {
    name      = "${var.chain_name}-${count.index}-internal"
    namespace = kubernetes_namespace.default.metadata.0.name
  }
  spec {
    selector = {
      "statefulset.kubernetes.io/pod-name" = "${var.chain_name}-${count.index}"
    }
    port {
      name        = "rpc"
      port        = 9933
      target_port = 9933
    }
    type = "ClusterIP"
  }
}

module "add-keys" {
  source            = "./add-keys"
  chain_name        = var.chain_name
  dirs              = [for i in local.keys_octoup: i["key_dir"]]
  keys              = ["babe.json", "gran.json", "imon.json", "beef.json", "octo.json"]
  module_depends_on = [kubernetes_stateful_set.default]
}

output "bootnodes_output" {
  description = ""
  value       = local.bootnodes
}
