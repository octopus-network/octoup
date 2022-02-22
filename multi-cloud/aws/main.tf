provider "aws" {
  region = var.region
}

# data "aws_vpc" "default" {
#   default = true
# }

# data "aws_subnet_ids" "default" {
#   vpc_id = data.aws_vpc.default.id
# }

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }
  filter {
    name   = "root-device-type"
    values = ["ebs"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"]
}

module "vpc" {
  source     = "terraform-aws-modules/vpc/aws"
  name       = "vpc-${var.id}"

  cidr               = "10.0.0.0/16"
  azs                = ["${var.region}a"]
  public_subnets     = ["10.0.1.0/24"]
}

module "default_sg" {
  source = "terraform-aws-modules/security-group/aws"
  name   = "default-sg-${var.id}"

  vpc_id                   = module.vpc.vpc_id
  egress_cidr_blocks       = ["0.0.0.0/0"]
  egress_ipv6_cidr_blocks  = ["::/0"]
  egress_rules             = ["all-all"]
  ingress_cidr_blocks      = ["0.0.0.0/0"]
  ingress_rules            = ["ssh-tcp"]
  ingress_with_cidr_blocks = [
    {
      from_port   = 9933
      to_port     = 9933
      protocol    = "tcp"
      description = "rpc port"
      cidr_blocks = "0.0.0.0/0"
      # ipv6_cidr_block = "::/0"
      rule_no     = 101
    },
    {
      from_port   = 9944
      to_port     = 9944
      protocol    = "tcp"
      description = "ws port"
      cidr_blocks = "0.0.0.0/0"
      # ipv6_cidr_block = "::/0"
      rule_no     = 102
    },
    {
      from_port   = 30333
      to_port     = 30333
      protocol    = "tcp"
      description = "p2p port"
      cidr_blocks = "0.0.0.0/0"
      # ipv6_cidr_block = "::/0"
      rule_no     = 103
    },
    {
      from_port   = 9100
      to_port     = 9100
      protocol    = "tcp"
      description = "node exporter port"
      cidr_blocks = "0.0.0.0/0"
      # ipv6_cidr_block = "::/0"
      rule_no     = 104
    },
  ]
}

resource "aws_key_pair" "key_pair" {
  key_name   = "kp-${var.id}"
  public_key = file(var.public_key_file)
}

module "ec2" {
  count  = var.instance_count
  source = "terraform-aws-modules/ec2-instance/aws"
  name   = "ec2-${var.id}"

  ami                         = data.aws_ami.ubuntu.id
  instance_type               = var.instance_type
  monitoring                  = true
  vpc_security_group_ids      = [module.default_sg.security_group_id]
  subnet_id                   = module.vpc.public_subnets[0]
  associate_public_ip_address = true
  root_block_device = [
    {
      volume_type           = var.volume_type
      volume_size           = var.volume_size
      delete_on_termination = true
    },
  ]
  key_name                    = aws_key_pair.key_pair.key_name
}
