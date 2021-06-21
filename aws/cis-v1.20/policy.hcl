policy "cis-v1.20" {
  description = "AWS CIS V1.20 Policy"
  configuration {
    provider "aws" {
      version = ">= 0.4"
    }
  }

  view "aws_log_metric_filter_and_alarm" {
    description = "AWS Log Metric Filter and Alarm"
    query "aws_log_metric_filter_and_alarm_query" {
      query = <<EOF
        CREATE VIEW aws_log_metric_filter_and_alarm AS
        SELECT aws_cloudtrail_trails.account_id, aws_cloudtrail_trails.region, cloud_watch_logs_log_group_arn, pattern FROM aws_cloudtrail_trails
          JOIN aws_cloudtrail_trail_event_selectors on aws_cloudtrail_trails.id = aws_cloudtrail_trail_event_selectors.trail_id
          JOIN aws_cloudwatchlogs_filters on aws_cloudtrail_trails.cloudwatch_logs_log_group_name = aws_cloudwatchlogs_filters.log_group_name
          JOIN aws_cloudwatch_alarm_metrics on aws_cloudwatchlogs_filters.name = aws_cloudwatch_alarm_metrics.metric_stat_metric_name
          JOIN aws_cloudwatch_alarms on aws_cloudwatch_alarm_metrics.alarm_id = aws_cloudwatch_alarms.id
          JOIN aws_sns_subscriptions ON aws_sns_subscriptions.topic_arn = ANY(aws_cloudwatch_alarms.alarm_actions)
        WHERE is_multi_region_trail=true AND is_logging=true
          AND include_management_events=true AND read_write_type = 'All'
          AND subscription_arn LIKE 'aws:arn:%'
EOF
    }
  }

  policies = [
    file("cis-section-1.hcl")
  ]

}