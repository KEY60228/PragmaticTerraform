module "describe_regions_for_ec2" {
    source = "./iam_role"
    name = "describe-regions-for-ec2"
    policy = data.aws_iam_policy_document.allow_describe_regions.json
    identifier = "ec2.amazonaws.com"
}