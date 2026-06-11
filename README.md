# aws-bvr

AWS Business Value Ratio — cost posture auditor for AWS product accounts.

Classifies every service in your AWS bill as **Value-generating**, **Enablement**, **Governance**, or **Waste**, computes two diagnostic ratios, and flags services that exceed review thresholds with specific remediation guidance.

## The metrics

**Business Value Ratio (BVR)**

```
BVR = Product Spend / (Total Spend - Tax - Credits - Support)
```

| BVR | Assessment |
|-----|------------|
| 60% and above | Healthy — most spend is directed at the product |
| 35% to 60% | Warning — enablement and governance costs are elevated |
| Below 35% | Critical — the account costs more to run than the business it serves |

**Governance Load Ratio (GLR)**

```
GLR = (Governance Spend + Enablement Spend) / Product Spend
```

A healthy product account carries a GLR below 0.25. Above 0.75 the account is infrastructure-heavy relative to its product footprint.

Read in combination: BVR below 35% with GLR above 0.75 is the provisioning standards problem signature.

## Scripts

| Script | Purpose |
|--------|---------|
| `aws_value_check.py` | Single-account audit with rich terminal output |
| `aws_ou_bvr_scan.py` | Scan all accounts in an AWS Organizations OU |
| `run_account_scan.py` | Run against named AWS profiles, write Markdown reports |
| `test_classification.py` | Unit tests for classification and metrics logic |

## Requirements

```bash
pip install boto3 rich python-dateutil
```

One IAM permission is required: `ce:GetCostAndUsage` (available via `AWSBillingReadOnlyAccess`).

## Single-account usage

```bash
# Last 3 months, default profile
python aws_value_check.py

# Last 6 months with CSV export
python aws_value_check.py --months 6 --csv results.csv

# Named AWS profile
python aws_value_check.py --profile prod-readonly

# Force new account detection mode
python aws_value_check.py --new-account

# Plain text output (no rich formatting)
python aws_value_check.py --no-rich
```

## Multi-profile Markdown reports

```bash
# Scan default profile, write Markdown to ./scan-results/
python run_account_scan.py

# Scan multiple named profiles
python run_account_scan.py --profiles dev staging prod

# Custom output directory and look-back period
python run_account_scan.py --profiles prod --months 6 --out-dir ./q2-audit
```

## OU-wide scan

```bash
pip install boto3 rich python-dateutil jinja2

# Scan all accounts in an OU
python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx

# 6 months, custom output directory
python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --months 6 --out-dir ./q2-audit

# Non-default audit role name
python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --role-name ReadOnlyAuditRole

# Scan only immediate OU children, not nested child OUs
python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --no-recursive
```

### IAM setup for OU scan

The scanning identity needs:
- `organizations:ListAccountsForParent`
- `organizations:ListChildren`
- `organizations:DescribeAccount`
- `sts:AssumeRole`

Each member account needs a role named `BVRAuditRole` (or as passed to `--role-name`) with this trust policy (substitute your scanning role ARN):

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "AWS": "arn:aws:iam::MANAGEMENT_ACCOUNT_ID:role/YOUR_SCANNING_ROLE"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

Permission policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": "ce:GetCostAndUsage",
      "Resource": "*"
    }
  ]
}
```

## Running tests

```bash
python test_classification.py

# Or with pytest
pip install pytest
pytest test_classification.py -v
```

## Service taxonomy

Services are classified by workload purpose, not by AWS service name alone. The same service in two accounts can correctly classify in two different categories.

**Value-generating (PRODUCT):** EC2, ECS, EKS, Lambda, RDS, Aurora, DynamoDB, SageMaker, Bedrock, S3, OpenSearch (when customer-facing), API Gateway, Kinesis, and all services where removing them degrades a customer outcome.

**Enablement (OVERHEAD):** VPC, Route 53, Certificate Manager, load balancers, KMS, Secrets Manager, IAM, Directory Service, WAF — necessary plumbing that breaks delivery but not customer function when removed.

**Governance (ADMIN):** CloudWatch, Config, GuardDuty, CloudTrail, Security Hub — observability, audit, and compliance controls. Removing these reduces safety and compliance posture.

**Waste (WASTE):** Services or resources that accumulate cost without active use and have no architectural justification. Currently covers EBS snapshots (`Amazon EBS`, `Amazon EC2 Snapshots`, `EBS Snapshots`, and any service name containing "snapshot"). Waste items are always flagged URGENT regardless of spend amount — even a few cents indicates unmanaged accumulation. Remediation advice includes the snapshot audit command and Data Lifecycle Manager setup.

Unlike the other three categories, Waste is not a matter of classification debate — it represents spend that should be eliminated, not optimised or right-sized.

## New account detection

Accounts with monthly average spend below $150 and no value-generating workload trigger the new account path. The report surfaces a specific finding: all current spend is standards overhead and production workloads should not be deployed until that baseline is reviewed.

## When a low BVR is correct

This framework applies to product accounts. Shared observability accounts, central security accounts, disaster recovery environments, and pre-launch accounts will legitimately score low on BVR. Assess those account types against their own purpose-appropriate benchmarks.

## API cost

Each audit run makes 2–5 Cost Explorer API calls at $0.01 each. Total audit cost is negligible.

---

*Based on the Business Value Ratio framework described in [Your AWS Account Has a Cost Posture Problem](https://andrewbaker.ninja).*
