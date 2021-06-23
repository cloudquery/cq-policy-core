policy "cis-v1.20" {
  description = "AWS CIS V1.20 Policy"
  configuration {
    provider "aws" {
      version = ">= 0.4.11"
    }
  }

  view "aws_log_metric_filter_and_alarm" {
    description = "AWS Log Metric Filter and Alarm"
    query "aws_log_metric_filter_and_alarm_query" {
      query = file("queries/aws-log-view.sql")
    }
  }

  policy "aws-cis-section-1" {
    description = "AWS CIS Section 1"

    query "1.1" {
      description = "AWS CIS 1.1 Avoid the use of 'root' account. Show used in last 30 days (Scored)"
      query =<<EOF
      SELECT account_id, password_last_used, user_name FROM aws_iam_users
      WHERE user_name = '<root_account>' AND password_last_used > (now() - '30 days'::interval)
    EOF
    }

    query "1.2" {
      description = "AWS CIS 1.2 Ensure MFA is enabled for all IAM users that have a console password (Scored)"
      query =<<EOF
      SELECT account_id, password_last_used, user_name, mfa_active FROM aws_iam_users
      WHERE password_enabled AND NOT mfa_active
    EOF
    }

    query "1.3" {
      description = "AWS CIS 1.3 Ensure credentials unused for 90 days or greater are disabled (Scored)"
      query =<<EOF
      SELECT account_id, arn, password_last_used, user_name, access_key_id, last_used FROM aws_iam_users
        JOIN aws_iam_user_access_keys on aws_iam_users.id = aws_iam_user_access_keys.user_id
       WHERE (password_enabled AND password_last_used < (now() - '90 days'::interval) OR
             (last_used < (now() - '90 days'::interval)))
    EOF
    }

    query "1.4" {
      description = "AWS CIS 1.4 Ensure access keys are rotated every 90 days or less"
      query =<<EOF
      SELECT account_id, arn, password_last_used, user_name, access_key_id, last_used, last_rotated FROM aws_iam_users
        JOIN aws_iam_user_access_keys on aws_iam_users.id = aws_iam_user_access_keys.user_id
       WHERE last_rotated < (now() - '90 days'::interval)
    EOF
    }

    query "1.5" {
      description = "AWS CIS 1.5  Ensure IAM password policy requires at least one uppercase letter"
      query =<<EOF
      SELECT account_id, require_uppercase_characters FROM aws_iam_password_policies
       WHERE require_uppercase_characters = FALSE
    EOF
    }

    query "1.6" {
      description = "AWS CIS 1.6  Ensure IAM password policy requires at least one lowercase letter"
      query =<<EOF
      SELECT account_id, require_lowercase_characters FROM aws_iam_password_policies
       WHERE require_lowercase_characters = FALSE
    EOF
    }

    query "1.7" {
      description = "AWS CIS 1.7  Ensure IAM password policy requires at least one symbol"
      query =<<EOF
      SELECT account_id, require_symbols FROM aws_iam_password_policies
       WHERE require_symbols = FALSE
    EOF
    }

    query "1.8" {
      description = "AWS CIS 1.8  Ensure IAM password policy requires at least one number"
      query =<<EOF
      SELECT account_id, require_numbers FROM aws_iam_password_policies
       WHERE require_numbers = FALSE
    EOF
    }

    query "1.9" {
      description = "AWS CIS 1.9 Ensure IAM password policy requires minimum length of 14 or greater"
      query =<<EOF
      SELECT account_id, minimum_password_length FROM aws_iam_password_policies
       WHERE minimum_password_length < 14
    EOF
    }

    query "1.10" {
      description = "AWS CIS 1.10 Ensure IAM password policy prevents password reuse"
      query =<<EOF
      SELECT account_id, password_reuse_prevention FROM aws_iam_password_policies
       WHERE password_reuse_prevention is NULL or password_reuse_prevention > 24
    EOF
    }

    query "1.11" {
      description = "AWS CIS 1.11 Ensure IAM password policy expires passwords within 90 days or less"
      query =<<EOF
      SELECT account_id, max_password_age FROM aws_iam_password_policies
       WHERE max_password_age is NULL or max_password_age < 90
    EOF
    }

    query "1.12" {
      description = "AWS CIS 1.12  Ensure no root account access key exists (Scored)"
      query =<<EOF
      select * from aws_iam_users
          JOIN aws_iam_user_access_keys aiuak on aws_iam_users.id = aiuak.user_id
      WHERE user_name = '<root>'
    EOF
    }

    query "1.13" {
      description = "AWS CIS 1.13 Ensure MFA is enabled for the 'root' account"
      query =<<EOF
      SELECT account_id, arn, password_last_used, user_name, mfa_active FROM aws_iam_users
      WHERE user_name = '<root_account>' AND NOT mfa_active
    EOF
    }

    query "1.14" {
      description = "AWS CIS 1.14 Ensure hardware MFA is enabled for the 'root' account (Scored)"
      query =<<EOF
      SELECT aiu.account_id, arn, password_last_used, aiu.user_name, mfa_active FROM aws_iam_users as aiu
      JOIN aws_iam_virtual_mfa_devices ON aws_iam_virtual_mfa_devices.user_arn = aiu.arn
      WHERE aiu.user_name = '<root_account>' AND aiu.mfa_active
    EOF
    }

    query "1.16" {
      description = "AWS CIS 1.16 Ensure IAM policies are attached only to groups or roles (Scored)"
      query =<<EOF
      SELECT aws_iam_users.account_id, arn, user_name FROM aws_iam_users
      JOIN aws_iam_user_attached_policies aiuap on aws_iam_users.id = aiuap.user_id
    EOF
    }
  }
}