# Forensiq AWS infrastructure (Terraform)
#
# Provisions the cloud-side resources the Kubernetes manifests assume:
#   - VPC with public + private subnets across 3 AZs
#   - EKS cluster
#   - Managed RDS Postgres
#   - ElastiCache Redis
#   - S3 buckets for backups + raw tool outputs
#   - IAM roles for IRSA (pod-level AWS auth)
#   - ACM cert + Route53 DNS
#
# We use modules from terraform-aws-modules where they're well-maintained
# (VPC, EKS) and write the rest inline.
#
# Usage:
#   terraform init
#   terraform plan -var-file=prod.tfvars
#   terraform apply -var-file=prod.tfvars

terraform {
  required_version = ">= 1.6.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.50"
    }
    kubernetes = {
      source  = "hashicorp/kubernetes"
      version = "~> 2.30"
    }
    helm = {
      source  = "hashicorp/helm"
      version = "~> 2.13"
    }
  }

  # Configure your backend appropriately. Example: S3 backend with state locking via DynamoDB.
  # backend "s3" {
  #   bucket         = "forensiq-tfstate"
  #   key            = "prod/terraform.tfstate"
  #   region         = "us-east-1"
  #   dynamodb_table = "forensiq-tfstate-lock"
  #   encrypt        = true
  # }
}

provider "aws" {
  region = var.region
  default_tags {
    tags = {
      Project     = "forensiq"
      Environment = var.environment
      ManagedBy   = "terraform"
    }
  }
}

# ─── VPC ──────────────────────────────────────────────────────────────

module "vpc" {
  source  = "terraform-aws-modules/vpc/aws"
  version = "~> 5.8"

  name = "forensiq-${var.environment}"
  cidr = "10.40.0.0/16"

  azs             = data.aws_availability_zones.available.names
  private_subnets = ["10.40.1.0/24", "10.40.2.0/24", "10.40.3.0/24"]
  public_subnets  = ["10.40.11.0/24", "10.40.12.0/24", "10.40.13.0/24"]

  enable_nat_gateway     = true
  single_nat_gateway     = var.environment != "prod"   # save $$$ in dev
  enable_dns_hostnames   = true
  enable_dns_support     = true

  # Tags expected by AWS Load Balancer Controller
  public_subnet_tags = {
    "kubernetes.io/role/elb" = "1"
  }
  private_subnet_tags = {
    "kubernetes.io/role/internal-elb" = "1"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
  filter {
    name   = "opt-in-status"
    values = ["opt-in-not-required"]
  }
}

# ─── EKS ──────────────────────────────────────────────────────────────

module "eks" {
  source  = "terraform-aws-modules/eks/aws"
  version = "~> 20.20"

  cluster_name    = "forensiq-${var.environment}"
  cluster_version = "1.30"

  cluster_endpoint_public_access = true
  cluster_endpoint_private_access = true

  vpc_id     = module.vpc.vpc_id
  subnet_ids = module.vpc.private_subnets

  # Encrypt secrets at rest with a customer-managed KMS key
  cluster_encryption_config = {
    provider_key_arn = aws_kms_key.eks.arn
    resources        = ["secrets"]
  }

  # Required for IRSA (IAM Roles for Service Accounts)
  enable_irsa = true

  # Cluster add-ons. Use AWS-managed VPC CNI + kube-proxy + CoreDNS.
  cluster_addons = {
    coredns = {
      most_recent = true
    }
    kube-proxy = {
      most_recent = true
    }
    vpc-cni = {
      most_recent = true
      configuration_values = jsonencode({
        env = {
          ENABLE_PREFIX_DELEGATION = "true"
        }
      })
    }
    aws-ebs-csi-driver = {
      most_recent              = true
      service_account_role_arn = module.ebs_csi_irsa.iam_role_arn
    }
  }

  eks_managed_node_groups = {
    # General-purpose pool for API + worker pods
    general = {
      desired_size = var.environment == "prod" ? 3 : 2
      min_size     = 2
      max_size     = 10
      instance_types = ["m6i.large"]
      capacity_type  = var.environment == "prod" ? "ON_DEMAND" : "SPOT"

      labels = {
        workload = "general"
      }
    }

    # Engine pool — beefier nodes, taints so only engine Jobs land here.
    # Echidna campaigns can spike to several GB of memory.
    engines = {
      desired_size = 1
      min_size     = 0
      max_size     = 8
      instance_types = ["m6i.xlarge"]
      capacity_type  = "SPOT"

      labels = {
        workload = "engine"
      }
      taints = [{
        key    = "workload"
        value  = "engine"
        effect = "NO_SCHEDULE"
      }]
    }
  }
}

resource "aws_kms_key" "eks" {
  description             = "EKS secrets encryption key for ${var.environment}"
  deletion_window_in_days = 30
  enable_key_rotation     = true
}

# IRSA role for EBS CSI (used by PVCs from StatefulSets)
module "ebs_csi_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.40"

  role_name             = "forensiq-${var.environment}-ebs-csi"
  attach_ebs_csi_policy = true
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["kube-system:ebs-csi-controller-sa"]
    }
  }
}

# ─── RDS Postgres ─────────────────────────────────────────────────────

resource "aws_security_group" "rds" {
  name        = "forensiq-${var.environment}-rds"
  description = "Postgres ingress from EKS nodes"
  vpc_id      = module.vpc.vpc_id

  ingress {
    from_port       = 5432
    to_port         = 5432
    protocol        = "tcp"
    security_groups = [module.eks.cluster_primary_security_group_id, module.eks.node_security_group_id]
  }
}

resource "random_password" "rds" {
  length  = 32
  special = false
}

resource "aws_db_subnet_group" "main" {
  name       = "forensiq-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_db_instance" "main" {
  identifier              = "forensiq-${var.environment}"
  engine                  = "postgres"
  engine_version          = "16.4"
  instance_class          = var.rds_instance_class
  allocated_storage       = 50
  max_allocated_storage   = 500
  storage_type            = "gp3"
  storage_encrypted       = true
  kms_key_id              = aws_kms_key.eks.arn   # reuse KMS key
  db_name                 = "forensiq"
  username                = "forensiq"
  password                = random_password.rds.result
  multi_az                = var.environment == "prod"
  publicly_accessible     = false
  vpc_security_group_ids  = [aws_security_group.rds.id]
  db_subnet_group_name    = aws_db_subnet_group.main.name
  backup_retention_period = var.environment == "prod" ? 30 : 7
  backup_window           = "03:00-04:00"
  deletion_protection     = var.environment == "prod"
  skip_final_snapshot     = var.environment != "prod"
  performance_insights_enabled = var.environment == "prod"
}

# ─── ElastiCache Redis ────────────────────────────────────────────────

resource "aws_security_group" "redis" {
  name   = "forensiq-${var.environment}-redis"
  vpc_id = module.vpc.vpc_id
  ingress {
    from_port       = 6379
    to_port         = 6379
    protocol        = "tcp"
    security_groups = [module.eks.cluster_primary_security_group_id, module.eks.node_security_group_id]
  }
}

resource "aws_elasticache_subnet_group" "main" {
  name       = "forensiq-${var.environment}"
  subnet_ids = module.vpc.private_subnets
}

resource "aws_elasticache_replication_group" "main" {
  replication_group_id       = "forensiq-${var.environment}"
  description                = "Forensiq Redis ${var.environment}"
  engine                     = "redis"
  engine_version             = "7.1"
  node_type                  = var.elasticache_node_type
  num_cache_clusters         = var.environment == "prod" ? 2 : 1
  port                       = 6379
  subnet_group_name          = aws_elasticache_subnet_group.main.name
  security_group_ids         = [aws_security_group.redis.id]
  at_rest_encryption_enabled = true
  transit_encryption_enabled = false   # BullMQ doesn't support TLS by default; check before changing
  automatic_failover_enabled = var.environment == "prod"
}

# ─── S3 buckets ───────────────────────────────────────────────────────

resource "aws_s3_bucket" "backups" {
  bucket = "forensiq-${var.environment}-backups-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_versioning" "backups" {
  bucket = aws_s3_bucket.backups.id
  versioning_configuration { status = "Enabled" }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.eks.arn
    }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "backups" {
  bucket = aws_s3_bucket.backups.id
  rule {
    id     = "expire-old-backups"
    status = "Enabled"
    filter {}
    expiration { days = 90 }
    noncurrent_version_expiration { noncurrent_days = 30 }
  }
}

resource "aws_s3_bucket" "raw_outputs" {
  bucket = "forensiq-${var.environment}-raw-${data.aws_caller_identity.current.account_id}"
}

resource "aws_s3_bucket_server_side_encryption_configuration" "raw_outputs" {
  bucket = aws_s3_bucket.raw_outputs.id
  rule {
    apply_server_side_encryption_by_default { sse_algorithm = "AES256" }
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "raw_outputs" {
  bucket = aws_s3_bucket.raw_outputs.id
  rule {
    id     = "transition-old"
    status = "Enabled"
    filter {}
    transition {
      days          = 30
      storage_class = "STANDARD_IA"
    }
    transition {
      days          = 90
      storage_class = "GLACIER"
    }
    expiration { days = 365 }
  }
}

data "aws_caller_identity" "current" {}

# ─── IRSA for the backup CronJob ──────────────────────────────────────

module "backup_irsa" {
  source  = "terraform-aws-modules/iam/aws//modules/iam-role-for-service-accounts-eks"
  version = "~> 5.40"

  role_name = "forensiq-${var.environment}-backup"
  role_policy_arns = {
    s3 = aws_iam_policy.backup_s3.arn
  }
  oidc_providers = {
    main = {
      provider_arn               = module.eks.oidc_provider_arn
      namespace_service_accounts = ["forensiq:forensiq-app"]
    }
  }
}

resource "aws_iam_policy" "backup_s3" {
  name        = "forensiq-${var.environment}-backup"
  description = "Write to backups bucket"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["s3:PutObject", "s3:GetObject", "s3:ListBucket"]
      Resource = [
        aws_s3_bucket.backups.arn,
        "${aws_s3_bucket.backups.arn}/*",
        aws_s3_bucket.raw_outputs.arn,
        "${aws_s3_bucket.raw_outputs.arn}/*",
      ]
    }]
  })
}

# ─── Outputs ──────────────────────────────────────────────────────────

output "cluster_name" { value = module.eks.cluster_name }
output "cluster_endpoint" { value = module.eks.cluster_endpoint }
output "rds_endpoint" { value = aws_db_instance.main.endpoint }
output "redis_endpoint" { value = aws_elasticache_replication_group.main.primary_endpoint_address }
output "backup_bucket" { value = aws_s3_bucket.backups.id }
output "raw_outputs_bucket" { value = aws_s3_bucket.raw_outputs.id }
output "rds_password" {
  value     = random_password.rds.result
  sensitive = true
}
output "backup_irsa_role_arn" { value = module.backup_irsa.iam_role_arn }
