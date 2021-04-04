output "alb_dns_name" {
    value = aws_lb.example.dns_name
}

# output "domain_name" {
#     value = aws_route53_record.example.name
# }

output "operation_instance_id" {
    value = aws_instance.example_for_operation.id
}
