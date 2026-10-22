# A deliberately vulnerable Bedrock agent for testing agentleash.
#
# DO NOT deploy this into an account that holds anything you care about. Use an
# empty sandbox account and run `terraform destroy` when you are done.
#
# The weaknesses, each of which agentleash should report:
#   1. The tool's execution role may call sts:AssumeRole on any role.
#   2. data-reader trusts the whole account, so the tool role can assume it and
#      read the customer-exports bucket (HIGH, read data via AssumeRole chain).
#   3. The tool role may s3:PutObject anywhere: it can overwrite data in this
#      account (HIGH) and copy data to a bucket in another account (MEDIUM, exfil).
#   4. The tool takes the bucket and key as free-text arguments, so whatever the
#      role can read, an injected agent can ask for.

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}

resource "random_id" "suffix" {
  byte_length = 3
}

locals {
  name    = "${var.name_prefix}-${random_id.suffix.hex}"
  account = data.aws_caller_identity.current.account_id
}

# ---------------------------------------------------------------- data -------

resource "aws_s3_bucket" "customer_exports" {
  bucket        = "${local.name}-customer-exports"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "customer_exports" {
  bucket                  = aws_s3_bucket.customer_exports.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "fake_export" {
  bucket       = aws_s3_bucket.customer_exports.id
  key          = "exports/customers.csv"
  content_type = "text/csv"
  # Synthetic data only.
  content = "id,name,email\n1,Test Customer,test@example.invalid\n"
}

resource "aws_s3_bucket" "tickets" {
  bucket        = "${local.name}-tickets"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "tickets" {
  bucket                  = aws_s3_bucket.tickets.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_object" "ticket" {
  bucket       = aws_s3_bucket.tickets.id
  key          = "tickets/1001.json"
  content_type = "application/json"
  content      = jsonencode({ id = 1001, subject = "Cannot log in", status = "open" })
}

# ---------------------------------------------------------------- roles ------

data "aws_iam_policy_document" "lambda_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "tool" {
  name               = "${local.name}-support-tool-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_trust.json
}

resource "aws_iam_role_policy_attachment" "tool_logs" {
  role       = aws_iam_role.tool.name
  policy_arn = "arn:${data.aws_partition.current.partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_iam_role_policy" "tool" {
  name = "tool"
  role = aws_iam_role.tool.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid      = "ReadTickets"
        Effect   = "Allow"
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.tickets.arn}/*"
      },
      {
        # Weakness 1: far broader than the tool needs.
        Sid      = "AssumeAnything"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = "*"
      },
      {
        # Weakness 3: write anywhere, including buckets in other accounts.
        Sid      = "WriteAnywhere"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_role" "data_reader" {
  name = "${local.name}-data-reader"
  # Weakness 2: trusts every principal in the account that has sts:AssumeRole.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { AWS = "arn:${data.aws_partition.current.partition}:iam::${local.account}:root" }
    }]
  })
}

resource "aws_iam_role_policy" "data_reader" {
  name = "read-exports"
  role = aws_iam_role.data_reader.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "s3:GetObject"
      Resource = "${aws_s3_bucket.customer_exports.arn}/*"
    }]
  })
}

# ---------------------------------------------------------------- tool -------

data "archive_file" "tool" {
  type        = "zip"
  source_file = "${path.module}/lambda/lookup_ticket.py"
  output_path = "${path.module}/build/lookup_ticket.zip"
}

resource "aws_lambda_function" "tool" {
  function_name    = "${local.name}-lookup-ticket"
  role             = aws_iam_role.tool.arn
  runtime          = "python3.12"
  handler          = "lookup_ticket.handler"
  filename         = data.archive_file.tool.output_path
  source_code_hash = data.archive_file.tool.output_base64sha256
  timeout          = 10
}

resource "aws_lambda_permission" "bedrock" {
  statement_id   = "AllowBedrockAgent"
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.tool.function_name
  principal      = "bedrock.amazonaws.com"
  source_account = local.account
  source_arn     = aws_bedrockagent_agent.support.agent_arn
}

# ---------------------------------------------------------------- agent ------

data "aws_iam_policy_document" "agent_trust" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["bedrock.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account]
    }
  }
}

resource "aws_iam_role" "agent" {
  name               = "${local.name}-agent-service-role"
  assume_role_policy = data.aws_iam_policy_document.agent_trust.json
}

resource "aws_iam_role_policy" "agent" {
  name = "invoke-model"
  role = aws_iam_role.agent.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "bedrock:InvokeModel"
      Resource = "arn:${data.aws_partition.current.partition}:bedrock:${var.region}::foundation-model/${var.foundation_model}"
    }]
  })
}

resource "aws_bedrockagent_agent" "support" {
  agent_name                  = "${local.name}-support-agent"
  agent_resource_role_arn     = aws_iam_role.agent.arn
  foundation_model            = var.foundation_model
  idle_session_ttl_in_seconds = 600
  prepare_agent               = true
  instruction                 = <<-EOT
    You are a customer support assistant. Use the lookup_ticket tool to fetch
    support tickets when a customer asks about one, and summarise them politely.
  EOT
}

resource "aws_bedrockagent_agent_action_group" "ticket_ops" {
  action_group_name          = "TicketOps"
  agent_id                   = aws_bedrockagent_agent.support.agent_id
  agent_version              = "DRAFT"
  skip_resource_in_use_check = true
  action_group_executor {
    lambda = aws_lambda_function.tool.arn
  }
  function_schema {
    member_functions {
      functions {
        name        = "lookup_ticket"
        description = "Fetch a support ticket document from S3."
        # Weakness 4: free-text bucket and key.
        parameters {
          map_block_key = "bucket"
          type          = "string"
          description   = "S3 bucket holding the ticket"
          required      = true
        }
        parameters {
          map_block_key = "key"
          type          = "string"
          description   = "Object key of the ticket"
          required      = true
        }
      }
    }
  }
}

resource "aws_bedrockagent_agent_alias" "prod" {
  agent_alias_name = "prod"
  agent_id         = aws_bedrockagent_agent.support.agent_id
  depends_on       = [aws_bedrockagent_agent_action_group.ticket_ops]
}
