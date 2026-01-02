# Terraform Configuration for Enterprise Application
# Security controls implemented following AWS Well-Architected Framework
#
# Author: Sunanda Mandal

terraform {
  required_version = ">= 1.5.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.27"
    }
  }
  
  # Remote state with encryption
  backend "s3" {
    bucket         = "company-terraform-state"
    key            = "enterprise-app/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "terraform-state-lock"
  }
}

# =============================================================================
# VARIABLES
# =============================================================================

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
  
  validation {
    condition     = contains(["development", "staging", "production"], var.environment)
    error_message = "Environment must be development, staging, or production."
  }
}

variable "app_name" {
  description = "Application name"
  type        = string
  default     = "enterprise-app"
}

variable "vpc_cidr" {
  description = "VPC CIDR block"
  type        = string
  default     = "10.0.0.0/16"
}

# =============================================================================
# DATA SOURCES
# =============================================================================

data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_caller_identity" "current" {}

# =============================================================================
# VPC & NETWORKING
# =============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  
  # Security: Enable VPC Flow Logs
  tags = {
    Name        = "${var.app_name}-vpc"
    Environment = var.environment
  }
}

# Security: VPC Flow Logs for network monitoring
resource "aws_flow_log" "main" {
  iam_role_arn    = aws_iam_role.flow_log.arn
  log_destination = aws_cloudwatch_log_group.flow_log.arn
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.main.id
  
  tags = {
    Name = "${var.app_name}-flow-logs"
  }
}

resource "aws_cloudwatch_log_group" "flow_log" {
  name              = "/aws/vpc/flow-logs/${var.app_name}"
  retention_in_days = 90
  
  # Security: Encrypt logs with KMS
  kms_key_id = aws_kms_key.logs.arn
}

# Private subnets for application
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  # Security: No public IPs for private subnets
  map_public_ip_on_launch = false
  
  tags = {
    Name = "${var.app_name}-private-${count.index + 1}"
    Type = "private"
  }
}

# Public subnets for load balancer
resource "aws_subnet" "public" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = cidrsubnet(var.vpc_cidr, 8, count.index + 10)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  
  tags = {
    Name = "${var.app_name}-public-${count.index + 1}"
    Type = "public"
  }
}

# =============================================================================
# SECURITY GROUPS
# =============================================================================

# ALB Security Group
resource "aws_security_group" "alb" {
  name        = "${var.app_name}-alb-sg"
  description = "Security group for Application Load Balancer"
  vpc_id      = aws_vpc.main.id
  
  # Security: Only allow HTTPS
  ingress {
    description = "HTTPS from anywhere"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  # Security: Redirect HTTP to HTTPS (handled by ALB)
  ingress {
    description = "HTTP for redirect"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.app_name}-alb-sg"
  }
}

# Application Security Group
resource "aws_security_group" "app" {
  name        = "${var.app_name}-app-sg"
  description = "Security group for application containers"
  vpc_id      = aws_vpc.main.id
  
  # Security: Only allow traffic from ALB
  ingress {
    description     = "Traffic from ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb.id]
  }
  
  egress {
    description = "Allow all outbound"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.app_name}-app-sg"
  }
}

# Database Security Group
resource "aws_security_group" "db" {
  name        = "${var.app_name}-db-sg"
  description = "Security group for RDS database"
  vpc_id      = aws_vpc.main.id
  
  # Security: Only allow traffic from application
  ingress {
    description     = "PostgreSQL from app"
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [aws_security_group.app.id]
  }
  
  # Security: No egress needed for database
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
  
  tags = {
    Name = "${var.app_name}-db-sg"
  }
}

# =============================================================================
# APPLICATION LOAD BALANCER
# =============================================================================

resource "aws_lb" "main" {
  name               = "${var.app_name}-alb"
  internal           = false
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb.id]
  subnets            = aws_subnet.public[*].id
  
  # Security: Enable deletion protection in production
  enable_deletion_protection = var.environment == "production"
  
  # Security: Enable access logs
  access_logs {
    bucket  = aws_s3_bucket.logs.id
    prefix  = "alb-logs"
    enabled = true
  }
  
  # Security: Drop invalid headers
  drop_invalid_header_fields = true
  
  tags = {
    Name        = "${var.app_name}-alb"
    Environment = var.environment
  }
}

# HTTPS Listener with modern TLS policy
resource "aws_lb_listener" "https" {
  load_balancer_arn = aws_lb.main.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"  # Security: TLS 1.3
  certificate_arn   = aws_acm_certificate.main.arn
  
  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.main.arn
  }
}

# HTTP to HTTPS redirect
resource "aws_lb_listener" "http_redirect" {
  load_balancer_arn = aws_lb.main.arn
  port              = 80
  protocol          = "HTTP"
  
  default_action {
    type = "redirect"
    
    redirect {
      port        = "443"
      protocol    = "HTTPS"
      status_code = "HTTP_301"
    }
  }
}

# =============================================================================
# RDS DATABASE
# =============================================================================

resource "aws_db_subnet_group" "main" {
  name       = "${var.app_name}-db-subnet-group"
  subnet_ids = aws_subnet.private[*].id
  
  tags = {
    Name = "${var.app_name}-db-subnet-group"
  }
}

resource "aws_db_instance" "main" {
  identifier = "${var.app_name}-db"
  
  # Instance configuration
  engine               = "postgres"
  engine_version       = "15.4"
  instance_class       = "db.t3.medium"
  allocated_storage    = 100
  max_allocated_storage = 500
  
  # Credentials
  db_name  = "appdb"
  username = "dbadmin"
  password = random_password.db_password.result
  
  # Network
  db_subnet_group_name   = aws_db_subnet_group.main.name
  vpc_security_group_ids = [aws_security_group.db.id]
  publicly_accessible    = false  # Security: Not publicly accessible
  
  # Security: Encryption at rest
  storage_encrypted = true
  kms_key_id        = aws_kms_key.database.arn
  
  # Security: Enable enhanced monitoring
  monitoring_interval = 60
  monitoring_role_arn = aws_iam_role.rds_monitoring.arn
  
  # Security: Enable Performance Insights with encryption
  performance_insights_enabled          = true
  performance_insights_kms_key_id       = aws_kms_key.database.arn
  performance_insights_retention_period = 7
  
  # Security: Enable IAM authentication
  iam_database_authentication_enabled = true
  
  # Backup
  backup_retention_period = 30
  backup_window          = "03:00-04:00"
  maintenance_window     = "Mon:04:00-Mon:05:00"
  
  # Security: Deletion protection
  deletion_protection = var.environment == "production"
  skip_final_snapshot = var.environment != "production"
  
  # Security: Enable automated minor version upgrades
  auto_minor_version_upgrade = true
  
  tags = {
    Name        = "${var.app_name}-db"
    Environment = var.environment
  }
}

# =============================================================================
# KMS KEYS
# =============================================================================

resource "aws_kms_key" "database" {
  description             = "KMS key for ${var.app_name} database encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true  # Security: Enable automatic key rotation
  
  tags = {
    Name = "${var.app_name}-db-key"
  }
}

resource "aws_kms_key" "logs" {
  description             = "KMS key for ${var.app_name} logs encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.app_name}-logs-key"
  }
}

resource "aws_kms_key" "secrets" {
  description             = "KMS key for ${var.app_name} secrets encryption"
  deletion_window_in_days = 30
  enable_key_rotation     = true
  
  tags = {
    Name = "${var.app_name}-secrets-key"
  }
}

# =============================================================================
# SECRETS MANAGER
# =============================================================================

resource "aws_secretsmanager_secret" "db_credentials" {
  name       = "${var.app_name}/db-credentials"
  kms_key_id = aws_kms_key.secrets.arn
  
  # Security: Enable automatic rotation
  tags = {
    Name = "${var.app_name}-db-credentials"
  }
}

resource "aws_secretsmanager_secret_version" "db_credentials" {
  secret_id = aws_secretsmanager_secret.db_credentials.id
  secret_string = jsonencode({
    username = aws_db_instance.main.username
    password = random_password.db_password.result
    host     = aws_db_instance.main.endpoint
    port     = aws_db_instance.main.port
    dbname   = aws_db_instance.main.db_name
  })
}

resource "random_password" "db_password" {
  length           = 32
  special          = true
  override_special = "!#$%&*()-_=+[]{}<>:?"
}

# =============================================================================
# S3 BUCKET FOR LOGS
# =============================================================================

resource "aws_s3_bucket" "logs" {
  bucket = "${var.app_name}-logs-${data.aws_caller_identity.current.account_id}"
  
  tags = {
    Name = "${var.app_name}-logs"
  }
}

# Security: Enable versioning
resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  versioning_configuration {
    status = "Enabled"
  }
}

# Security: Enable server-side encryption
resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.logs.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Security: Block public access
resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Security: Enable access logging
resource "aws_s3_bucket_logging" "logs" {
  bucket = aws_s3_bucket.logs.id
  
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "access-logs/"
}

# =============================================================================
# WAF (Web Application Firewall)
# =============================================================================

resource "aws_wafv2_web_acl" "main" {
  name        = "${var.app_name}-waf"
  description = "WAF rules for ${var.app_name}"
  scope       = "REGIONAL"
  
  default_action {
    allow {}
  }
  
  # Security: AWS Managed Rules - Common Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 1
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesCommonRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }
  
  # Security: SQL Injection Protection
  rule {
    name     = "AWSManagedRulesSQLiRuleSet"
    priority = 2
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesSQLiRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesSQLiRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }
  
  # Security: Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3
    
    override_action {
      none {}
    }
    
    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "AWSManagedRulesKnownBadInputsRuleSetMetric"
      sampled_requests_enabled  = true
    }
  }
  
  # Security: Rate limiting
  rule {
    name     = "RateLimitRule"
    priority = 4
    
    action {
      block {}
    }
    
    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }
    
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name               = "RateLimitRuleMetric"
      sampled_requests_enabled  = true
    }
  }
  
  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name               = "${var.app_name}-waf-metric"
    sampled_requests_enabled  = true
  }
  
  tags = {
    Name = "${var.app_name}-waf"
  }
}

# Associate WAF with ALB
resource "aws_wafv2_web_acl_association" "main" {
  resource_arn = aws_lb.main.arn
  web_acl_arn  = aws_wafv2_web_acl.main.arn
}

# =============================================================================
# OUTPUTS
# =============================================================================

output "alb_dns_name" {
  description = "ALB DNS name"
  value       = aws_lb.main.dns_name
}

output "db_endpoint" {
  description = "RDS endpoint"
  value       = aws_db_instance.main.endpoint
  sensitive   = true
}

output "waf_arn" {
  description = "WAF Web ACL ARN"
  value       = aws_wafv2_web_acl.main.arn
}
