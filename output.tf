output "benign_lambda_arn" {
  value = aws_lambda_function.benign.arn
}

output "malicious_permission_lambda_arn" {
  value = aws_lambda_function.malicious_permission.arn
}

output "malicious_leakage_lambda_arn" {
  value = aws_lambda_function.malicious_leakage.arn
}

output "malicious_dow_lambda_arn" {
  value = aws_lambda_function.malicious_dow.arn
}
