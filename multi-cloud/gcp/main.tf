provider "google" {
  region = var.region
}

data "google_compute_image" "ubuntu" {
  family  = "ubuntu-minimal-2004-lts"
  project = "ubuntu-os-cloud"
}

data "google_compute_zones" "default" {
}

resource "google_compute_instance" "instance" {
  count        = var.instance_count
  name         = "vm-${var.id}-${count.index}"
  machine_type = var.instance_type
  zone         = data.google_compute_zones.default.names[0]

  metadata = {
    ssh-keys = "ubuntu:${file(var.public_key_file)}"
  }

  boot_disk {
    auto_delete = true
    initialize_params {
      size  = var.volume_size
      type  = var.volume_type
      image = data.google_compute_image.ubuntu.self_link
    }
  }

  network_interface {
    network = "default"
    access_config {
      nat_ip = null
    }
  }
}

resource "google_compute_firewall" "default" {
  name    = "fw-${var.id}-9933-9944-30333"
  network = "default"

  allow {
    protocol = "tcp"
    ports    = ["9933", "9944", "30333"]
  }
}
