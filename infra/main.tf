terraform {
  required_version = ">= 0.14"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 4.0"
    }
  }
}

provider "aws" {
  region = "us-west-2"
}

resource "aws_s3_bucket" "lambda_bucket" {
  bucket = "cc360-pages-1734034858"
  acl    = "private"
}

resource "aws_iam_role" "lambda_role" {
  name = "transfer-ai-website-dynamo-to-ghl-v2-lambda-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action: "sts:AssumeRole",
        Effect: "Allow",
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy_attachment" "lambda_logs" {
  name       = "transfer-ai-website-dynamo-to-ghl-v2-lambda-logs"
  roles      = [aws_iam_role.lambda_role.name]
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}

resource "aws_lambda_function" "my_lambda" {
  function_name = "transfer-ai-website-dynamo-to-ghl-v2-function"
  role          = aws_iam_role.lambda_role.arn
  handler       = "lambda_function.lambda_handler"
  runtime       = "python3.9"
  s3_bucket     = aws_s3_bucket.lambda_bucket.bucket
  s3_key        = "lambda_function.zip"
  environment {
    variables = {
      REGION_NAME      = "us-west-2"
      DYNAMODB_TABLE   = "AI-temp-website-for-leads"
      GHL_SECRET_NAME  = "GHLAccessKey"
      COMPANY_ID       = "Cbjwl9dRdmiskYlzh8Oo"
    }
  }
}

output "lambda_function_name" {
  value = aws_lambda_function.my_lambda.function_name
}
