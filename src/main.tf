module "describe_regions_for_ec2" {
    source = "./iam_role"
    name = "describe-regions-for-ec2"
    policy = data.aws_iam_policy_document.allow_describe_regions.json
    identifier = "ec2.amazonaws.com"
}

resource "aws_s3_bucket" "private" {
    bucket = "private-pragmatic-terraform-20210327"

    versioning {
        enabled = true
    }

    server_side_encryption_configuration {
        rule {
            apply_server_side_encryption_by_default {
                sse_algorithm = "AES256"
            }
        }
    }
}

resource "aws_s3_bucket_public_access_block" "private" {
    bucket = aws_s3_bucket.private.id
    block_public_acls = true
    block_public_policy = true
    ignore_public_acls = true
    restrict_public_buckets = true
}

resource "aws_s3_bucket" "public" {
    bucket = "public_pragmatic_terraform-20210327"
    acl = "public-read"

    cors_rule {
        allowed_origins = ["https://example.com"]
        allowed_methods = ["GET"]
        allowed_headers = ["*"]
        max_age_seconds = 3000
    }
}

resource "aws_s3_bucket" "alb_log" {
    bucket = "alb-log-pragmatic-terraform-20210327"

    lifecycle_rule {
        enabled = true

        expiration {
            days = "180"
        }
    }
}

resource "aws_s3_bucket_policy" "alb_log" {
    bucket = aws_s3_bucket.alb_log.id
    policy = data.aws_iam_policy_document.alb_log.json
}

data "aws_iam_policy_document" "alb_log" {
    statement {
        effect = "Allow"
        actions = ["s3:PutObject"]
        resources = [ "arn:aws:s3:::${aws_s3_bucket.alb_log.id}/*" ]

        principals {
            type = "AWS"
            identifiers = [ "582318560864" ]
        }
    }
}

resource "aws_vpc" "example" {
    cidr_block = "10.0.0.0/16"
    enable_dns_support = true
    enable_dns_hostnames = true

    tags = {
        Name = "example"
    }
}

resource "aws_subnet" "public" {
    vpc_id = aws_vpc.example.id
    cidr_block = "10.0.0.0/24"
    map_public_ip_on_launch = true
    availability_zone = "ap-northeast-1a"
}

resource "aws_internet_gateway" "example" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route_table" "public" {
    vpc_id = aws_vpc.example.id
}

resource "aws_route" "public" {
    route_table_id = aws_route_table.public.id
    gateway_id = aws_internet_gateway.example.id
    destination_cidr_block = "0.0.0.0/0"
}

resource "aws_route_table_association" "public" {
    subnet_id = aws_subnet.public.id
    route_table_id = aws_route_table.public.id
}
