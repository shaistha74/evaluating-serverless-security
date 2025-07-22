locals {
  region         = "us-east-1"
  cidr_block     = "10.1.0.0/16"
  public_subnets = ["10.1.1.0/24", "10.1.2.0/24"]
  azs            = ["us-east-1c", "us-east-1d"]
  project_name   = "CyberSecureInfra"
}

provider "aws" {
  region = local.region
}

data "aws_caller_identity" "current" {}

# VPC and Networking
module "vpc_infrastructure" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "5.1.1"

  name                 = "${local.project_name}-vpc"
  cidr                 = local.cidr_block
  azs                  = local.azs
  public_subnets       = local.public_subnets
  enable_dns_hostnames = true
  
  tags = {
    Project = local.project_name
  }
}

resource "aws_security_group" "bastion_sg" {
  name        = "bastion-sg"
  description = "Access rules for SSH and HTTP"
  vpc_id      = module.vpc_infrastructure.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["90.254.227.254/32"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["90.254.227.254/32"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_route_table" "public_routes" {
  vpc_id = module.vpc_infrastructure.vpc_id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = module.vpc_infrastructure.igw_id
  }
}

# IAM for EC2
resource "aws_iam_role" "instance_iam_role" {
  name = "InstanceAccessRole"

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

resource "aws_iam_role_policy_attachment" "attach_cloudwatch" {
  role       = aws_iam_role.instance_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchAgentServerPolicy"
}

resource "aws_iam_role_policy_attachment" "attach_ssm" {
  role       = aws_iam_role.instance_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_role_policy_attachment" "attach_logs" {
  role       = aws_iam_role.instance_iam_role.name
  policy_arn = "arn:aws:iam::aws:policy/CloudWatchLogsFullAccess"
}

resource "aws_iam_instance_profile" "profile_instance" {
  name = "ec2-instance-access-profile"
  role = aws_iam_role.instance_iam_role.name
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn2-ami-hvm-*-x86_64-gp2"]
  }
}

# Bastion Host EC2
resource "aws_instance" "bastion_host" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = module.vpc_infrastructure.public_subnets[0]
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.profile_instance.name
  key_name               = aws_key_pair.bastion.key_name

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
              systemctl enable amazon-ssm-agent
              systemctl start amazon-ssm-agent
              /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl \\
                -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/bin/config.json -s
EOF

  tags = {
    Name        = "BastionHost"
    Environment = "Production"
  }
}

# Web Server
resource "aws_instance" "web_server" {
  ami                    = data.aws_ami.amazon_linux.id
  instance_type          = "t2.micro"
  subnet_id              = module.vpc_infrastructure.public_subnets[1]
  vpc_security_group_ids = [aws_security_group.bastion_sg.id]
  iam_instance_profile   = aws_iam_instance_profile.profile_instance.name
  user_data              = aws_instance.bastion_host.user_data
  key_name               = aws_key_pair.bastion.key_name

  tags = {
    Name        = "WebServer"
    Environment = "Production"
  }
}

resource "tls_private_key" "bastion_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "bastion" {
  key_name   = "bastion-key"
  public_key = tls_private_key.bastion_key.public_key_openssh
}

# Central Log Bucket
resource "random_id" "s3_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "central_log_bucket" {
  bucket        = "cloud-logs-${random_id.s3_suffix.hex}"
  force_destroy = true
}

# GuardDuty
resource "aws_guardduty_detector" "gd_detector" {
  enable = true
}

# AWS Config
resource "aws_iam_role" "config_service_role" {
  name = "AWSConfigServiceRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "config_service_policy" {
  role       = aws_iam_role.config_service_role.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRoleForOrganizations"
}

resource "aws_config_configuration_recorder" "config_recorder" {
  name     = "ConfigRecorder"
  role_arn = aws_iam_role.config_service_role.arn

  recording_group {
    all_supported = true
  }
}

resource "aws_s3_bucket_policy" "allow_config" {
  bucket = aws_s3_bucket.central_log_bucket.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Effect = "Allow",
        Principal = {
          Service = "config.amazonaws.com"
        },
        Action = ["s3:PutObject"],
        Resource = "${aws_s3_bucket.central_log_bucket.arn}/*",
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
        Resource = aws_s3_bucket.central_log_bucket.arn
      }
    ]
  })
}

resource "aws_config_delivery_channel" "config_channel" {
  name           = "ConfigChannel"
  s3_bucket_name = aws_s3_bucket.central_log_bucket.bucket

  depends_on = [
    aws_iam_role_policy_attachment.config_service_policy,
    aws_s3_bucket.central_log_bucket
  ]
}

# CloudTrail
resource "aws_cloudtrail" "account_trail1" {
  name                          = "AccountActivityTrail"
  s3_bucket_name                = aws_s3_bucket.log_archiving.bucket
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_logging                = true

  depends_on = [aws_s3_bucket_policy.trail_bucket_policy]
}

resource "random_id" "bucket_id" {
  byte_length = 4
}

resource "aws_s3_bucket" "log_archiving" {
  bucket        = "log-archiving-secure-${random_id.bucket_id.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_policy" "trail_bucket_policy" {
  bucket = aws_s3_bucket.log_archiving.id

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Sid       = "AWSCloudTrailAclCheck",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:GetBucketAcl",
        Resource  = aws_s3_bucket.log_archiving.arn
      },
      {
        Sid       = "AWSCloudTrailWrite",
        Effect    = "Allow",
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        },
        Action    = "s3:PutObject",
        Resource  = "${aws_s3_bucket.log_archiving.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/*",
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Security Hub + SNS
resource "aws_securityhub_account" "shub" {
  depends_on = [aws_guardduty_detector.gd_detector]
}

resource "aws_sns_topic" "alerting_topic" {
  name = "security-alert-topic"
}

resource "aws_sns_topic_subscription" "email_alert" {
  topic_arn = aws_sns_topic.alerting_topic.arn
  protocol  = "email"
  endpoint  = "shaika74@gmail.com"
}

# Lambda for auto-remediation
resource "aws_iam_role" "lambda_execution_role" {
  name = "LambdaExecutionSecurityRole"

  assume_role_policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action = "sts:AssumeRole",
        Principal = {
          Service = "lambda.amazonaws.com"
        },
        Effect = "Allow"
      }
    ]
  })
}

resource "aws_iam_policy" "lambda_s3_write_policy" {
  name = "LambdaS3LogWrite"

  policy = jsonencode({
    Version = "2012-10-17",
    Statement = [
      {
        Action   = ["s3:PutObject"],
        Effect   = "Allow",
        Resource = "${aws_s3_bucket.central_log_bucket.arn}/*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_write_attach" {
  role       = aws_iam_role.lambda_execution_role.name
  policy_arn = aws_iam_policy.lambda_s3_write_policy.arn
}

resource "aws_lambda_function" "security_lambda" {
  filename         = "lambda/remediate.zip"
  function_name    = "SecurityEventResponder"
  role             = aws_iam_role.lambda_execution_role.arn
  handler          = "index.handler"
  runtime          = "python3.9"
  source_code_hash = filebase64sha256("lambda/remediate.zip")

  environment {
    variables = {
      SNS_TOPIC  = aws_sns_topic.alerting_topic.arn
      LOG_BUCKET = aws_s3_bucket.central_log_bucket.bucket
    }
  }
}

# EventBridge triggers
resource "aws_cloudwatch_event_rule" "guardduty_alerts" {
  name        = "GDAlertsTrigger"
  description = "Trigger for GuardDuty security alerts"

  event_pattern = jsonencode({
    source = ["aws.guardduty"]
  })
}

resource "aws_cloudwatch_event_rule" "securityhub_alerts" {
  name        = "SHAlertsTrigger"
  description = "Trigger for Security Hub findings"

  event_pattern = jsonencode({
    source = ["aws.securityhub"]
  })
}

resource "aws_cloudwatch_event_target" "gd_lambda_target" {
  rule      = aws_cloudwatch_event_rule.guardduty_alerts.name
  target_id = "GDToLambda"
  arn       = aws_lambda_function.security_lambda.arn
}

resource "aws_cloudwatch_event_target" "sh_lambda_target" {
  rule      = aws_cloudwatch_event_rule.securityhub_alerts.name
  target_id = "SHToLambda"
  arn       = aws_lambda_function.security_lambda.arn
}

resource "aws_lambda_permission" "allow_gd_eventbridge" {
  statement_id  = "AllowGDInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.guardduty_alerts.arn
}

resource "aws_lambda_permission" "allow_sh_eventbridge" {
  statement_id  = "AllowSHInvokeLambda"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.security_lambda.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.securityhub_alerts.arn
}
