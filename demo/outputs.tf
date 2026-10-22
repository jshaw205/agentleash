output "agent_id" {
  value = aws_bedrockagent_agent.support.agent_id
}

output "scan_command" {
  description = "Run this to scan the demo with agentleash."
  value       = "agentleash scan --region ${var.region}"
}
