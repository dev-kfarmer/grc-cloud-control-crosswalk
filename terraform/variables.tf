variable "aws_region" {
  description = "AWS region for lab resources"
  type        = string
  default     = "us-east-1"
}

variable "aws_profile" {
  description = "Named AWS CLI profile to use (matches `aws configure --profile grc-lab`)"
  type        = string
  default     = "grc-lab"
}

variable "iam_user_name" {
  description = "Existing IAM user created via console bootstrap — NOT managed by Terraform, referenced by name only"
  type        = string
  default     = "grc-lab-readonly"
}

variable "bucket_prefix" {
  description = "Prefix for lab S3 bucket names (bucket names are globally unique, so this should be distinctive)"
  type        = string
  default     = "grc-evidence-lab"
}
