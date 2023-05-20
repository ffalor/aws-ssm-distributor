provider "aws" {
  region = local.region
}

data "aws_availability_zones" "available" {}
data "http" "ip" {
  url    = "https://ipinfo.io"
  method = "GET"
}

locals {
  vpc_name      = "SSMTerraformVPC"
  vpc_cidr      = "10.0.0.0/16"
  azs           = slice(data.aws_availability_zones.available.names, 0, 3)
  region        = var.region
  instance_name = "SSMTerraformTestInstance"
  ip            = jsondecode(data.http.ip.response_body)["ip"]
}

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 3.0"

  name = local.vpc_name
  cidr = local.vpc_cidr

  azs             = local.azs
  public_subnets  = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k)]
  private_subnets = [for k, v in local.azs : cidrsubnet(local.vpc_cidr, 8, k + 10)]

  enable_nat_gateway   = true
  single_nat_gateway   = true
  enable_dns_hostnames = true

  # Manage so we can name
  manage_default_network_acl    = true
  default_network_acl_tags      = { Name = "${local.vpc_name}-default" }
  manage_default_route_table    = true
  default_route_table_tags      = { Name = "${local.vpc_name}-default" }
  manage_default_security_group = true
  default_security_group_tags   = { Name = "${local.vpc_name}-default" }

  public_subnet_tags = {
    "ssm/terraform/${local.vpc_name}" = "shared"
  }

  private_subnet_tags = {
    "ssm/terraform/${local.vpc_name}" = "shared"
  }
}

resource "aws_security_group" "instance_sg" {
  name        = "${local.instance_name}-sg"
  description = "Security group for ${local.instance_name}"

  vpc_id = module.vpc.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["${local.ip}/32"]
  }

  # Allow all outbound traffic
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

module "ec2_instance" {
  source  = "terraform-aws-modules/ec2-instance/aws"
  version = "4.3.0"

  for_each = { for idx, instance in var.instance : idx => instance }

  name                        = local.instance_name
  ami_ssm_parameter           = each.value.ami
  associate_public_ip_address = true

  instance_type = each.value.instance_type

  create_iam_instance_profile = true
  iam_role_policies = {
    "AmazonSSMManagedInstanceCore": "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
  }

  subnet_id              = module.vpc.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.instance_sg.id]

  tags = {
    cstag-department = "Sales"
    cstag-accounting = "dev"
    "Created by" = "ffalor"
    usage = "ssm-terraform-test"
    ami = each.value.ami
  }
}

resource "aws_ssm_document" "sensor_deploy" {
  name = "CrowdStrike-FalconSensorDeployV2"

  document_format = "YAML"
  document_type   = "Automation"

  content = file("${path.module}/../aws-automation-doc/CrowdStrike-FalconSensorDeploy.yml")
}

data "aws_iam_role" "ssm_assume_role" {
  name = "crowdstrike-ssm-assume-role"
}

resource "aws_ssm_association" "sensor_deploy" {
  name = aws_ssm_document.sensor_deploy.name

  targets {
    key = "InstanceIds"
    values = ["*"]
  }

  automation_target_parameter_name = "InstanceIds"

  parameters = {
    AutomationAssumeRole = data.aws_iam_role.ssm_assume_role.arn
  }
}