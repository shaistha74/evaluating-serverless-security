provider "aws" {
  region = "us-east-1"
}

terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# IAM Role for Lambda
resource "aws_iam_role" "lambda_role" {
  name = "vod-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Service = "lambda.amazonaws.com"
      }
      Action = "sts:AssumeRole"
    }]
  })
}

# Basic execution policy (logs etc.)
resource "aws_iam_policy_attachment" "lambda_basic_execution" {
  name       = "lambda-basic-execution"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

# Extra permissions for Lambdas to access source + attacker buckets
resource "aws_iam_role_policy" "lambda_s3_access" {
  role = aws_iam_role.lambda_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:CopyObject"
        ]
        Resource = [
          "arn:aws:s3:::${var.vod_source_bucket}/*",
          "arn:aws:s3:::${var.attacker_bucket}/*"
        ]
      }
    ]
  })
}

# Attacker-controlled bucket (for data exfiltration test)
resource "aws_s3_bucket" "attacker" {
  bucket = var.attacker_bucket
  force_destroy = true
}

resource "aws_s3_bucket_policy" "attacker_policy" {
  bucket = aws_s3_bucket.attacker.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          AWS = aws_iam_role.lambda_role.arn
        }
        Action = [
          "s3:PutObject",
          "s3:GetObject"
        ]
        Resource = "arn:aws:s3:::${var.attacker_bucket}/*"
      }
    ]
  })
}

# Benign Lambda

resource "aws_lambda_function" "benign" {
  function_name = "vod-benign-lambda"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  filename         = "${path.module}/benign_lambda.zip"
  source_code_hash = filebase64sha256("${path.module}/benign_lambda.zip")
}

resource "aws_lambda_permission" "allow_s3_benign" {
  statement_id  = "AllowExecutionFromS3Benign"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.benign.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.vod_source_bucket}"
}

# Malicious Lambda 1 – Permission Misuse

resource "aws_lambda_function" "malicious_permission" {
  function_name = "vod-malicious-permission"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  filename         = "${path.module}/malicious_permission.zip"
  source_code_hash = filebase64sha256("${path.module}/malicious_permission.zip")
}

resource "aws_lambda_permission" "allow_s3_permission" {
  statement_id  = "AllowExecutionFromS3Permission"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.malicious_permission.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.vod_source_bucket}"
}

# Malicious Lambda 2 – Data Leakage

resource "aws_lambda_function" "malicious_leakage" {
  function_name = "vod-malicious-data-leakage"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  filename         = "${path.module}/malicious_leakage.zip"
  source_code_hash = filebase64sha256("${path.module}/malicious_leakage.zip")

 environment {
    variables = {
      ATTACKER_BUCKET = var.attacker_bucket
    }
  }
}

resource "aws_lambda_permission" "allow_s3_leakage" {
  statement_id  = "AllowExecutionFromS3Leakage"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.malicious_leakage.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.vod_source_bucket}"
}

# Malicious Lambda 3 – Denial of Wallet

resource "aws_lambda_function" "malicious_dow" {
  function_name = "vod-malicious-denial-of-wallet"
  role          = aws_iam_role.lambda_role.arn
  handler       = "index.handler"
  runtime       = "python3.9"

  filename         = "${path.module}/malicious_dow.zip"
  source_code_hash = filebase64sha256("${path.module}/malicious_dow.zip")
}

resource "aws_lambda_permission" "allow_s3_dow" {
  statement_id  = "AllowExecutionFromS3DoW"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.malicious_dow.function_name
  principal     = "s3.amazonaws.com"
  source_arn    = "arn:aws:s3:::${var.vod_source_bucket}"
}

# Notifications (use suffix to avoid overlap)

resource "aws_s3_bucket_notification" "vod_source_trigger" {
  bucket = var.vod_source_bucket

  lambda_function {
    lambda_function_arn = aws_lambda_function.benign.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".benign"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.malicious_permission.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".perm"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.malicious_leakage.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".leak"
  }

  lambda_function {
    lambda_function_arn = aws_lambda_function.malicious_dow.arn
    events              = ["s3:ObjectCreated:*"]
    filter_suffix       = ".dow"
  }
}

# CloudTrail for S3 Data Events

resource "aws_cloudtrail" "vod_trail" {
  name                          = "vod-trail"
  s3_bucket_name                = var.cloudtrail_bucket_name
  include_global_service_events = true
  is_multi_region_trail         = true
  enable_log_file_validation    = true

  depends_on = [aws_s3_bucket_policy.cloudtrail_logs_policy]

  event_selector {
    read_write_type           = "All"
    include_management_events = true

    data_resource {
      type   = "AWS::S3::Object"
      values = [
        "arn:aws:s3:::${var.vod_source_bucket}/*",
        "arn:aws:s3:::${var.attacker_bucket}/*"
      ]
    }
  }
}

# S3 Bucket for CloudTrail Logs

resource "aws_s3_bucket" "cloudtrail_logs" {
  bucket = var.cloudtrail_bucket_name
}

# Optional: Enable encryption + block public access for compliance
resource "aws_s3_bucket_server_side_encryption_configuration" "trail_encryption" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "trail_logs_block" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true

}

resource "aws_s3_bucket_policy" "cloudtrail_logs_policy" {
  bucket = aws_s3_bucket.cloudtrail_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AWSCloudTrailAclCheck"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:GetBucketAcl"
        Resource = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.id}"
      },
      {
        Sid    = "AWSCloudTrailWrite"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.amazonaws.com"
        }
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::${aws_s3_bucket.cloudtrail_logs.id}/AWSLogs/${data.aws_caller_identity.current.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl" = "bucket-owner-full-control"
          }
        }
      }
    ]
  })
}

# Get Account ID (needed for the bucket policy)
data "aws_caller_identity" "current" {}

