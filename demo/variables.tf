variable "region" {
  description = "Region to deploy into. Bedrock Agents and the chosen model must be available there."
  type        = string
  default     = "eu-west-2"
}

variable "foundation_model" {
  description = "Model ID for the agent. You must have enabled access to it in the Bedrock console."
  type        = string
  default     = "anthropic.claude-3-haiku-20240307-v1:0"
}

variable "name_prefix" {
  description = "Prefix for every resource name."
  type        = string
  default     = "agentleash-demo"
}
