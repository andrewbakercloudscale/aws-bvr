#!/usr/bin/env python3
"""
test_classification.py  --  Unit tests for BVR classification and metrics logic

Run:
    python test_classification.py
    python -m pytest test_classification.py -v
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from aws_value_check import (
    classify,
    urgency,
    is_new_account,
    get_date_range,
    bvr_colour,
    NEW_ACCOUNT_SPEND_THRESHOLD,
)


class TestClassify(unittest.TestCase):

    def test_ec2_is_value(self):
        self.assertEqual(classify("Amazon EC2"), "VALUE")

    def test_lambda_is_value(self):
        self.assertEqual(classify("AWS Lambda"), "VALUE")

    def test_rds_is_value(self):
        self.assertEqual(classify("Amazon RDS"), "VALUE")

    def test_opensearch_is_value(self):
        # OpenSearch is VALUE by default (can be log sink but starts as VALUE)
        self.assertEqual(classify("Amazon OpenSearch Service"), "VALUE")

    def test_s3_is_value(self):
        self.assertEqual(classify("Amazon S3"), "VALUE")

    def test_dynamodb_is_value(self):
        self.assertEqual(classify("Amazon DynamoDB"), "VALUE")

    def test_sagemaker_is_value(self):
        self.assertEqual(classify("Amazon SageMaker"), "VALUE")

    def test_bedrock_is_value(self):
        self.assertEqual(classify("Amazon Bedrock"), "VALUE")

    def test_cloudwatch_is_admin(self):
        self.assertEqual(classify("Amazon CloudWatch"), "ADMIN")

    def test_cloudwatch_alias_is_admin(self):
        self.assertEqual(classify("CloudWatch"), "ADMIN")

    def test_guardduty_is_admin(self):
        self.assertEqual(classify("Amazon GuardDuty"), "ADMIN")

    def test_config_is_admin(self):
        self.assertEqual(classify("AWS Config"), "ADMIN")

    def test_cloudtrail_is_admin(self):
        self.assertEqual(classify("AWS CloudTrail"), "ADMIN")

    def test_tax_is_admin(self):
        self.assertEqual(classify("Tax"), "ADMIN")

    def test_vpc_is_overhead(self):
        self.assertEqual(classify("Amazon VPC"), "OVERHEAD")

    def test_acm_is_overhead(self):
        self.assertEqual(classify("AWS Certificate Manager"), "OVERHEAD")

    def test_route53_is_overhead(self):
        self.assertEqual(classify("Amazon Route 53"), "OVERHEAD")

    def test_directory_service_is_overhead(self):
        self.assertEqual(classify("AWS Directory Service"), "OVERHEAD")

    def test_kms_is_overhead(self):
        self.assertEqual(classify("AWS Key Management Service"), "OVERHEAD")

    def test_secrets_manager_is_overhead(self):
        self.assertEqual(classify("AWS Secrets Manager"), "OVERHEAD")

    def test_elb_is_overhead(self):
        self.assertEqual(classify("Amazon Elastic Load Balancing"), "OVERHEAD")

    def test_ebs_is_waste(self):
        self.assertEqual(classify("Amazon EBS"), "WASTE")

    def test_ec2_snapshots_is_waste(self):
        self.assertEqual(classify("Amazon EC2 Snapshots"), "WASTE")

    def test_ebs_snapshots_alias_is_waste(self):
        self.assertEqual(classify("EBS Snapshots"), "WASTE")

    def test_fuzzy_snapshot_is_waste(self):
        self.assertEqual(classify("Some EC2 Snapshot Service"), "WASTE")

    def test_unknown_service(self):
        self.assertEqual(classify("AWS Some Completely New Service XYZ"), "UNKNOWN")

    def test_fuzzy_ec2_match(self):
        self.assertEqual(classify("EC2-Instances"), "VALUE")

    def test_fuzzy_cloudwatch_match(self):
        result = classify("CloudWatch Events")
        self.assertEqual(result, "ADMIN")

    def test_savings_plans_is_admin(self):
        self.assertEqual(classify("Savings Plans for AWS Compute usage"), "ADMIN")


class TestUrgency(unittest.TestCase):

    def test_cloudwatch_above_threshold_is_urgent(self):
        self.assertEqual(urgency("Amazon CloudWatch", 100, "ADMIN"), "URGENT")

    def test_cloudwatch_below_threshold_is_empty(self):
        self.assertEqual(urgency("Amazon CloudWatch", 30, "ADMIN"), "")

    def test_acm_above_threshold_is_urgent(self):
        self.assertEqual(urgency("AWS Certificate Manager", 200, "OVERHEAD"), "URGENT")

    def test_opensearch_above_500_is_urgent(self):
        self.assertEqual(urgency("Amazon OpenSearch Service", 600, "VALUE"), "URGENT")

    def test_opensearch_below_500_is_empty(self):
        self.assertEqual(urgency("Amazon OpenSearch Service", 400, "VALUE"), "")

    def test_high_admin_spend_is_review(self):
        self.assertEqual(urgency("AWS Some Admin Service", 250, "ADMIN"), "REVIEW")

    def test_high_overhead_spend_is_review(self):
        self.assertEqual(urgency("AWS Some Overhead Service", 600, "OVERHEAD"), "REVIEW")

    def test_low_spend_is_empty(self):
        self.assertEqual(urgency("Amazon EC2", 10, "VALUE"), "")

    def test_waste_always_urgent(self):
        self.assertEqual(urgency("Amazon EBS", 0.50, "WASTE"), "URGENT")

    def test_waste_tiny_spend_still_urgent(self):
        self.assertEqual(urgency("EBS Snapshots", 0.02, "WASTE"), "URGENT")


class TestNewAccountDetection(unittest.TestCase):

    def test_new_account_detected(self):
        costs = {
            "Amazon CloudWatch": 30.0,
            "AWS Config": 20.0,
            "Amazon GuardDuty": 40.0,
            "Amazon VPC": 15.0,
        }
        self.assertTrue(is_new_account(costs, 1))

    def test_new_account_not_triggered_with_value_spend(self):
        costs = {
            "Amazon EC2": 200.0,
            "Amazon CloudWatch": 30.0,
        }
        self.assertFalse(is_new_account(costs, 1))

    def test_new_account_not_triggered_above_threshold(self):
        costs = {
            "Amazon CloudWatch": 80.0,
            "AWS Config": 50.0,
            "Amazon GuardDuty": 80.0,
        }
        self.assertFalse(is_new_account(costs, 1))

    def test_new_account_boundary_at_threshold(self):
        # Exactly at threshold should NOT trigger new account
        costs = {"Amazon CloudWatch": NEW_ACCOUNT_SPEND_THRESHOLD}
        self.assertFalse(is_new_account(costs, 1))

    def test_multi_month_averages_correctly(self):
        # $300 over 3 months = $100/mo average, below $150 threshold with no value spend
        costs = {
            "Amazon CloudWatch": 150.0,
            "AWS Config": 90.0,
            "Amazon GuardDuty": 60.0,
        }
        self.assertTrue(is_new_account(costs, 3))


class TestBvrColour(unittest.TestCase):

    def test_healthy_is_green(self):
        self.assertEqual(bvr_colour(0.75), "green")

    def test_exactly_sixty_is_green(self):
        self.assertEqual(bvr_colour(0.60), "green")

    def test_warning_is_yellow(self):
        self.assertEqual(bvr_colour(0.50), "yellow")

    def test_exactly_35_is_yellow(self):
        self.assertEqual(bvr_colour(0.35), "yellow")

    def test_critical_is_red(self):
        self.assertEqual(bvr_colour(0.10), "red")

    def test_zero_is_red(self):
        self.assertEqual(bvr_colour(0.0), "red")


class TestDateRange(unittest.TestCase):

    def test_returns_two_strings(self):
        start, end = get_date_range(3)
        self.assertIsInstance(start, str)
        self.assertIsInstance(end, str)

    def test_end_is_first_of_month(self):
        _, end = get_date_range(1)
        self.assertTrue(end.endswith("-01"))

    def test_start_before_end(self):
        start, end = get_date_range(3)
        self.assertLess(start, end)

    def test_six_month_range(self):
        start, end = get_date_range(6)
        from datetime import date
        from dateutil.relativedelta import relativedelta
        s = date.fromisoformat(start)
        e = date.fromisoformat(end)
        diff = relativedelta(e, s)
        self.assertEqual(diff.months + diff.years * 12, 6)


class TestBvrCalculation(unittest.TestCase):
    """Integration-style tests against a synthetic cost dict."""

    def setUp(self):
        self.healthy_costs = {
            "Amazon EC2": 1000.0,
            "AWS Lambda": 500.0,
            "Amazon RDS": 300.0,
            "Amazon CloudWatch": 40.0,
            "Amazon VPC": 30.0,
        }
        # OpenSearch classifies as VALUE (customer-facing by default), so a
        # truly "broken" account uses ACM Private CA + Directory Service + Route53
        # overhead dwarfing a tiny EC2 footprint — matching the blog post example.
        self.broken_costs = {
            "Amazon EC2": 100.0,
            "AWS Certificate Manager": 3800.0,
            "Amazon Route 53": 1500.0,
            "AWS Directory Service": 800.0,
            "Amazon CloudWatch": 300.0,
            "Amazon VPC": 500.0,
        }

    def _bvr(self, costs):
        total = sum(costs.values())
        value = sum(v for s, v in costs.items() if classify(s) == "VALUE")
        return value / total if total > 0 else 0.0

    def test_healthy_account_bvr_above_60(self):
        self.assertGreater(self._bvr(self.healthy_costs), 0.60)

    def test_broken_account_bvr_below_35(self):
        self.assertLess(self._bvr(self.broken_costs), 0.35)

    def test_zero_spend_bvr_is_zero(self):
        self.assertEqual(self._bvr({}), 0.0)

    def test_all_value_bvr_is_one(self):
        costs = {"Amazon EC2": 1000.0, "Amazon RDS": 500.0}
        self.assertAlmostEqual(self._bvr(costs), 1.0)

    def test_all_admin_bvr_is_zero(self):
        costs = {"Amazon CloudWatch": 100.0, "AWS Config": 50.0}
        self.assertAlmostEqual(self._bvr(costs), 0.0)


if __name__ == "__main__":
    unittest.main(verbosity=2)
