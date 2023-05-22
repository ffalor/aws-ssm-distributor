variable "region" {
  type = string
  default = "us-east-1"
  description = "AWS Region to deploy to"
}

variable "instance" {
  description = "Instances to create"
  default     = [
    # {
    #     "ami": "/aws/service/suse/sles/12-sp5/x86_64/latest",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/22.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/20.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/18.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/16.04/stable/current/amd64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/22.04/stable/current/arm64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t4g.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/20.04/stable/current/arm64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t4g.medium"
    # },
    # {
    #     "ami": "/aws/service/canonical/ubuntu/server/18.04/stable/current/arm64/hvm/ebs-gp2/ami-id",
    #     "instance_type": "t4g.medium"
    # },
    # {
    #     "ami": "/aws/service/debian/release/11/latest/amd64",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/debian/release/10/latest/amd64",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-x86_64-gp2",
    #     "instance_type": "t2.medium"
    # },
    # {
    #     "ami": "/aws/service/ami-amazon-linux-latest/amzn2-ami-kernel-5.10-hvm-arm64-gp2",
    #     "instance_type": "t4g.medium"
    # },
    # {
    #     "ami": "/aws/service/suse/sles/15-sp4/x86_64/latest",
    #     "instance_type": "t2.medium"
    # },
    {
        "ami": "/aws/service/ami-windows-latest/Windows_Server-2022-English-Full-Base",
        "instance_type": "t2.medium"
    },
    {
        "ami": "/aws/service/ami-windows-latest/Windows_Server-2016-English-Full-Base",
        "instance_type": "t2.medium"
    },
    {
        "ami": "/aws/service/ami-windows-latest/Windows_Server-2019-English-Full-Base",
        "instance_type": "t2.medium"
    }
]

  type        = list(map(string))
}