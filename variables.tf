# ---------------------------
# Variables
# ---------------------------
variable "vod_source_bucket" {
  description = "Name of the VOD source bucket"
  type        = string
}

variable "attacker_bucket" {
  description = "Name of the attacker-controlled bucket (for data leakage test)"
  type        = string
}

variable "cloudtrail_bucket_name" {
  description = "S3 bucket for storing CloudTrail logs"
  type        = string
}