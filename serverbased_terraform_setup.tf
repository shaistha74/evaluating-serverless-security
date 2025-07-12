provider "aws" {
  region = "us-east-1"
}

# 1. VPC, Subnets, ALB, EC2 

module "network" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.1"

  name = "secure-network"
  cidr = "10.0.0.0/16"

  azs                  = ["us-east-1a", "us-east-1b"]
  public_subnets       = ["10.0.1.0/24", "10.0.2.0/24"]
  enable_dns_hostnames = true

  tags = {
    Project = "Monitoring"
  }
}

resource "aws_security_group" "ec2_sg" {
  name        = "ec2_sg"
  description = "Allow SSH and HTTP"
  vpc_id      = module.network.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}
resource "aws_iam_role" "ec2_instance_role" {
  name = "EC2CloudWatchAgentRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "ec2.amazonaws.com"
        },
        Action = "sts:AssumeRole"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudwatch_agent_policy" {
  role       = aws_iam_role.ec2_instance_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name = "ec2-instance-profile"
  role = aws_iam_role.ec2_instance_role.name
}

resource "aws_instance" "bastion" {
  ami                    = "ami-05ffe3c48a9991133"
  instance_type          = "t2.micro"
  subnet_id              = module.network.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

#Install CLoudwatch-agent
  user_data = <<-EOF
              #!/bin/bash
              yum update -y
              yum install -y amazon-cloudwatch-agent
              cat <<EOC > /opt/aws/amazon-cloudwatch-agent/bin/config.json
              {
                "metrics": {
                  "metrics_collected": {
                    "cpu": {
                      "measurement": ["cpu_usage_idle", "cpu_usage_user", "cpu_usage_system"],
                      "metrics_collection_interval": 60
                    },
                    "disk": {
                      "measurement": ["used_percent"],
                      "metrics_collection_interval": 60,
                      "resources": ["*"]
                    },
                    "mem": {
                      "measurement": ["mem_used_percent"],
                      "metrics_collection_interval": 60
                    }
                  }
                }
              }
              EOC
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \
                -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
              EOF

  tags = {
    Name = "Bastion"
  }
}

resource "aws_instance" "web" {
  ami                    = "ami-05ffe3c48a9991133"
  instance_type          = "t2.micro"
  subnet_id              = module.network.public_subnets[1]
  vpc_security_group_ids = [aws_security_group.ec2_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.ec2_profile.name

  user_data = aws_instance.bastion.user_data # reuse same script

  tags = {
    Name = "WebServer"
  }
}

resource "aws_s3_bucket_policy" "config_access" {
  bucket = aws_s3_bucket.log_archiving.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = "s3:PutObject",
        Resource = "${aws_s3_bucket.log_archiving.arn}/*",
        Condition = {
          StringEquals = {
            "AWS:SourceAccount" = data.aws_caller_identity.current.account_id
          }
        }
      },
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = "s3:GetBucketAcl",
        Resource = aws_s3_bucket.log_archiving.arn
      }
    ]
  })
}

data "aws_caller_identity" "current" {}


# 2. CloudWatch Logs + S3 Archive 
resource "aws_cloudwatch_log_group" "ec2_logs" {
  name              = "/ec2/monitoring"
  retention_in_days = 7
}

resource "aws_s3_bucket" "log_archiving" {
  bucket        = "log-archiving-secure-${random_id.bucket_id.hex}"
  force_destroy = true
}

resource "random_id" "bucket_id" {
  byte_length = 4
}

# 3. Security Services: GuardDuty, Config   #

resource "aws_guardduty_detector" "main" {
  enable = true #enable GuardDutyter
}


resource "aws_config_configuration_recorder" "recorder" {
  name     = "config"
  role_arn = aws_iam_role.config_role.arn
  recording_group {
    all_supported = true
  }
}

resource "aws_config_delivery_channel" "channel" {
  name           = "config"
  s3_bucket_name = aws_s3_bucket.log_archiving.bucket

 depends_on = [
    aws_s3_bucket_policy.config_access,
    aws_config_configuration_recorder.recorder
  ]
}

resource "aws_iam_role" "config_role" {
  name               = "config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role_policy_attachment" "config_policy" {
  role       = aws_iam_role.config_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"

}

#Security Hub + SNS for Alerting
resource "aws_securityhub_account" "hub" {
  depends_on = [aws_guardduty_detector.main]
}

resource "aws_sns_topic" "alerts" {
  name = "security-alerts"
}

#Lambda for Auto-remediation
resource "aws_iam_role" "lambda_exec" {
  name = "lambda_exec_role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_lambda_function" "remediate" {
  filename         = "lambda/remediate.zip"
  function_name    = "AutoRemediate"
  role             = aws_iam_role.lambda_exec.arn
  handler          = "index.handler"
  runtime          = "python3.9"
  source_code_hash = filebase64sha256("lambda/remediate.zip")

  environment {
    variables = {
      SNS_TOPIC = aws_sns_topic.alerts.arn
    }
  }
}

