# ❌ Intentionally insecure Terraform config for demo

provider "aws" {
  region = "us-east-1"
}

# ❌ Security group open to world
resource "aws_security_group" "web" {
  name        = "web-sg"
  description = "Web security group"

  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port        = 0
    to_port          = 65535
    protocol         = "tcp"
    ipv6_cidr_blocks = ["::/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ❌ S3 bucket without encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-app-data-bucket"
}

# ❌ RDS without encryption, publicly accessible
resource "aws_db_instance" "main" {
  identifier           = "myapp-db"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"
  allocated_storage    = 20
  username             = "admin"
  password             = "password123"
  publicly_accessible  = true
  storage_encrypted    = false
  skip_final_snapshot  = true
}

# ❌ Logging disabled
resource "aws_s3_bucket_logging" "example" {
  bucket = aws_s3_bucket.data.id
  enable_logging = false
}
