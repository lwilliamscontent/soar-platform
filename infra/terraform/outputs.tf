output "findings_queue_url" {
  value = aws_sqs_queue.findings.url
}

output "findings_dlq_url" {
  value = aws_sqs_queue.findings_dlq.url
}

output "splunk_soar_secret_arn" {
  value = aws_secretsmanager_secret.splunk_soar.arn
}

output "virustotal_secret_arn" {
  value = aws_secretsmanager_secret.virustotal.arn
}
