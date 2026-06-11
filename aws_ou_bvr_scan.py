#!/usr/bin/env python3
"""
aws_ou_bvr_scan.py  --  OU-level AWS Business Value Cost Scanner
=================================================================
Enumerates all accounts in an AWS Organizations OU, assumes a
read-only role in each, computes BVR and GLR, writes per-account
CSV detail files, and produces a ranked HTML summary report.

Requirements:
    pip install boto3 rich python-dateutil jinja2

IAM permissions required (management account or delegated admin):
    organizations:ListAccountsForParent
    organizations:ListChildren
    organizations:DescribeAccount
    sts:AssumeRole  (to assume the audit role in each member account)

Each member account must have a role matching --role-name that trusts
the scanning identity. The role requires only ce:GetCostAndUsage.

Usage:
    python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx
    python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --months 3
    python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --role-name BVRAuditRole
    python aws_ou_bvr_scan.py --ou-id ou-xxxx-xxxxxxxx --out-dir ./bvr-reports
"""

import argparse
import csv
import json
import os
import sys
from datetime import date, datetime
from dateutil.relativedelta import relativedelta
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

# ---------------------------------------------------------------------------
# Import classification and fetch logic from aws_value_check.py if present,
# otherwise embed the minimum required subset inline.
# ---------------------------------------------------------------------------

try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from aws_value_check import (
        classify, fetch_costs, get_date_range,
        VALUE_GENERATING, OVERHEAD, ADMINISTRATIVE,
        NEW_ACCOUNT_SPEND_THRESHOLD, REVIEW_ADVICE, WARNING_THRESHOLDS,
        urgency
    )
    IMPORTED = True
except ImportError:
    IMPORTED = False

# If aws_value_check.py is not present, embed the minimum classification subset.
if not IMPORTED:
    NEW_ACCOUNT_SPEND_THRESHOLD = 150.0

    VALUE_GENERATING = {
        "Amazon EC2", "Amazon EC2 - Other", "EC2 - Other", "EC2-Instances", "EC2-Other",
        "Amazon Elastic Container Service", "Amazon Elastic Kubernetes Service",
        "AWS Lambda", "Amazon RDS", "Amazon Aurora", "Amazon DynamoDB",
        "Amazon ElastiCache", "Amazon Redshift", "Amazon EMR", "Amazon SageMaker",
        "Amazon Bedrock", "Amazon Rekognition", "Amazon Comprehend", "Amazon Translate",
        "Amazon Transcribe", "Amazon Polly", "Amazon Lex", "Amazon Personalize",
        "Amazon Forecast", "Amazon Kendra", "Amazon S3", "Amazon S3 Glacier",
        "Amazon OpenSearch Service", "Amazon API Gateway", "Amazon AppSync",
        "Amazon SQS", "Amazon SNS", "Amazon Kinesis", "Amazon MSK",
        "Amazon EventBridge", "Amazon Connect", "Amazon Pinpoint", "Amazon WorkSpaces",
        "AWS Elastic Beanstalk", "Amazon Lightsail", "AWS Amplify", "AWS App Runner",
        "Amazon ECS", "Amazon EKS", "Amazon ECR", "AWS Batch", "Amazon MQ",
        "Amazon DocumentDB", "Amazon Neptune", "Amazon Timestream", "Amazon QLDB",
        "Amazon Managed Blockchain", "AWS Glue", "Amazon Athena", "Amazon QuickSight",
        "AWS Lake Formation", "Amazon DataZone",
    }

    OVERHEAD = {
        "Amazon VPC", "VPC", "AWS Transit Gateway", "Amazon CloudFront",
        "Amazon Route 53", "Route 53", "AWS Direct Connect",
        "Amazon Elastic Load Balancing", "Elastic Load Balancing",
        "AWS Global Accelerator", "AWS PrivateLink",
        "AWS Certificate Manager", "Certificate Manager",
        "AWS Secrets Manager", "Secrets Manager",
        "AWS Key Management Service", "Key Management Service",
        "AWS Identity and Access Management", "AWS IAM Identity Center",
        "Amazon Cognito", "AWS Directory Service", "Directory Service",
        "AWS WAF", "AWS Shield", "Amazon Inspector", "AWS Firewall Manager",
        "AWS Network Firewall", "Amazon Macie", "AWS Security Hub",
        "Amazon Backup", "AWS Elastic Disaster Recovery", "AWS DataSync",
        "AWS Transfer Family", "AWS Storage Gateway", "AWS Systems Manager",
        "Systems Manager", "AWS CodeDeploy", "AWS CodePipeline", "AWS CodeBuild",
        "AWS CodeCommit", "AWS CodeArtifact", "Amazon EFS", "AWS Fargate",
    }

    ADMINISTRATIVE = {
        "Amazon CloudWatch", "CloudWatch", "AWS CloudTrail", "AWS Config", "Config",
        "Amazon GuardDuty", "GuardDuty", "AWS Security Hub", "Amazon Detective",
        "Amazon Inspector", "Amazon Inspector2", "AWS Trusted Advisor",
        "AWS Cost Explorer", "AWS Budgets", "AWS Control Tower", "AWS Organizations",
        "AWS Service Catalog", "AWS Audit Manager", "AWS License Manager",
        "AWS Resource Access Manager", "AWS Compute Optimizer",
        "AWS Health Dashboard", "AWS Personal Health Dashboard", "AWS Support",
        "AWS Artifact", "Amazon Managed Grafana",
        "Amazon Managed Service for Prometheus", "AWS X-Ray", "AWS Chatbot",
        "Amazon DevOps Guru", "AWS Fault Injection Simulator", "AWS Resilience Hub",
        "AWS Migration Hub", "AWS Application Migration Service",
        "AWS Database Migration Service", "AWS Well-Architected Tool",
        "AWS Service Quotas", "Tax", "AWS Tax",
        "Savings Plans for AWS Compute usage", "Savings Plans Upfront Fee",
    }

    EXCLUDE_FROM_DENOMINATOR = {"Tax", "AWS Tax", "AWS Support"}

    WARNING_THRESHOLDS = {
        "Amazon CloudWatch": 50, "CloudWatch": 50,
        "AWS Config": 30, "Config": 30,
        "Amazon GuardDuty": 100, "GuardDuty": 100,
        "Amazon OpenSearch Service": 500,
        "AWS Directory Service": 200, "Directory Service": 200,
        "Amazon Route 53": 200, "Route 53": 200,
        "AWS Certificate Manager": 100, "Certificate Manager": 100,
        "AWS Secrets Manager": 50, "Secrets Manager": 50,
    }

    def classify(service_name):
        if service_name in VALUE_GENERATING:
            return "PRODUCT"
        if service_name in OVERHEAD:
            return "ENABLEMENT"
        if service_name in ADMINISTRATIVE:
            return "GOVERNANCE"
        sl = service_name.lower()
        if any(k in sl for k in ("ec2", "rds", "lambda", "sagemaker", "bedrock",
                                  "ecs", "eks", "opensearch", "elasticache",
                                  "redshift", "emr", "aurora", "dynamodb",
                                  "kinesis", "msk")):
            return "PRODUCT"
        if any(k in sl for k in ("cloudwatch", "config", "guardduty", "cloudtrail",
                                  "audit", "inspector", "macie", "detective")):
            return "GOVERNANCE"
        if any(k in sl for k in ("vpc", "route 53", "certificate", "directory",
                                  "secrets", "kms", "iam", "cognito", "waf",
                                  "shield", "firewall", "backup", "load balanc",
                                  "transit gateway", "cloudfront")):
            return "ENABLEMENT"
        return "UNKNOWN"

    def get_date_range(months_back):
        today = date.today()
        end = today.replace(day=1)
        start = end - relativedelta(months=months_back)
        return start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")

    def fetch_costs(ce_client, start, end):
        costs = {}
        paginator_token = None
        while True:
            kwargs = dict(
                TimePeriod={"Start": start, "End": end},
                Granularity="MONTHLY",
                Metrics=["BlendedCost"],
                GroupBy=[{"Type": "DIMENSION", "Key": "SERVICE"}],
            )
            if paginator_token:
                kwargs["NextPageToken"] = paginator_token
            response = ce_client.get_cost_and_usage(**kwargs)
            for result in response.get("ResultsByTime", []):
                for group in result.get("Groups", []):
                    service = group["Keys"][0]
                    amount = float(group["Metrics"]["BlendedCost"]["Amount"])
                    costs[service] = costs.get(service, 0.0) + amount
            paginator_token = response.get("NextPageToken")
            if not paginator_token:
                break
        return costs

    def urgency(service, cost, category):
        threshold = WARNING_THRESHOLDS.get(service)
        if threshold and cost >= threshold:
            return "URGENT"
        if category == "GOVERNANCE" and cost >= 200:
            return "REVIEW"
        if category == "ENABLEMENT" and cost >= 500:
            return "REVIEW"
        return ""

EXCLUDE_FROM_DENOMINATOR = {"Tax", "AWS Tax", "AWS Support", "Savings Plans for AWS Compute usage"}

# ---------------------------------------------------------------------------
# Metrics computation
# ---------------------------------------------------------------------------

def compute_metrics(costs, months):
    total_raw = sum(costs.values())
    excluded = sum(v for s, v in costs.items() if s in EXCLUDE_FROM_DENOMINATOR)
    total_adj = total_raw - excluded

    breakdown = {
        "PRODUCT":    sum(v for s, v in costs.items() if classify(s) == "PRODUCT"),
        "ENABLEMENT": sum(v for s, v in costs.items() if classify(s) == "ENABLEMENT"),
        "GOVERNANCE": sum(v for s, v in costs.items() if classify(s) == "GOVERNANCE"),
        "UNKNOWN":    sum(v for s, v in costs.items() if classify(s) == "UNKNOWN"),
    }

    bvr = breakdown["PRODUCT"] / total_adj if total_adj > 0 else 0.0
    glr_num = breakdown["GOVERNANCE"] + breakdown["ENABLEMENT"]
    glr = glr_num / breakdown["PRODUCT"] if breakdown["PRODUCT"] > 0 else float("inf")
    monthly_avg = total_raw / max(months, 1)
    is_new = monthly_avg < NEW_ACCOUNT_SPEND_THRESHOLD and breakdown["PRODUCT"] < 1.0

    urgent_services = [
        s for s, v in costs.items()
        if urgency(s, v, classify(s)) == "URGENT"
    ]

    return {
        "total_raw":    total_raw,
        "total_adj":    total_adj,
        "monthly_avg":  monthly_avg,
        "breakdown":    breakdown,
        "bvr":          bvr,
        "glr":          glr,
        "is_new":       is_new,
        "urgent":       urgent_services,
        "costs":        costs,
    }


def bvr_status(bvr, is_new):
    if is_new:
        return "NEW"
    if bvr >= 0.60:
        return "HEALTHY"
    if bvr >= 0.35:
        return "WARNING"
    return "CRITICAL"


def glr_status(glr):
    if glr == float("inf"):
        return "NO_PRODUCT"
    if glr < 0.25:
        return "HEALTHY"
    if glr < 0.75:
        return "REVIEW"
    return "HEAVY"


# ---------------------------------------------------------------------------
# Organizations enumeration
# ---------------------------------------------------------------------------

def list_accounts_in_ou(org_client, ou_id, recursive=True):
    accounts = []

    paginator = org_client.get_paginator("list_accounts_for_parent")
    for page in paginator.paginate(ParentId=ou_id):
        for acct in page.get("Accounts", []):
            if acct["Status"] == "ACTIVE":
                accounts.append({
                    "id":    acct["Id"],
                    "name":  acct["Name"],
                    "email": acct.get("Email", ""),
                })

    if recursive:
        child_paginator = org_client.get_paginator("list_children")
        for page in child_paginator.paginate(ParentId=ou_id, ChildType="ORGANIZATIONAL_UNIT"):
            for child_ou in page.get("Children", []):
                accounts.extend(list_accounts_in_ou(org_client, child_ou["Id"], recursive=True))

    return accounts


# ---------------------------------------------------------------------------
# Per-account scanning
# ---------------------------------------------------------------------------

def assume_role(account_id, role_name, session_name="BVRScan"):
    sts = boto3.client("sts")
    role_arn = f"arn:aws:iam::{account_id}:role/{role_name}"
    try:
        resp = sts.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
        creds = resp["Credentials"]
        return boto3.Session(
            aws_access_key_id=creds["AccessKeyId"],
            aws_secret_access_key=creds["SecretAccessKey"],
            aws_session_token=creds["SessionToken"],
        )
    except ClientError:
        return None


def scan_account(account, role_name, start, end, months, out_dir):
    account_id   = account["id"]
    account_name = account["name"]
    safe_name    = account_name.replace(" ", "_").replace("/", "_")
    detail_file  = out_dir / f"{account_id}_{safe_name}.csv"

    session = assume_role(account_id, role_name)
    if session is None:
        return {
            "id":     account_id,
            "name":   account_name,
            "error":  "role_assumption_failed",
            "detail": str(detail_file),
        }

    ce = session.client("ce", region_name="us-east-1")
    try:
        costs = fetch_costs(ce, start, end)
    except ClientError as e:
        return {
            "id":     account_id,
            "name":   account_name,
            "error":  str(e.response["Error"]["Code"]),
            "detail": str(detail_file),
        }

    metrics = compute_metrics(costs, months)

    with open(detail_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Account_ID", "Account_Name", "Service", "Category",
                         "Cost_USD", "Share_Pct", "Flag"])
        total = metrics["total_raw"]
        for svc, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
            if cost < 0.01:
                continue
            cat  = classify(svc)
            flag = urgency(svc, cost, cat)
            share = cost / total * 100 if total > 0 else 0
            writer.writerow([account_id, account_name, svc, cat,
                             f"{cost:.2f}", f"{share:.2f}", flag])

    return {
        "id":          account_id,
        "name":        account_name,
        "error":       None,
        "detail":      str(detail_file),
        "detail_file": detail_file.name,
        **metrics,
    }


# ---------------------------------------------------------------------------
# HTML summary report
# ---------------------------------------------------------------------------

STATUS_COLOUR = {
    "HEALTHY":    "#2d7a2d",
    "WARNING":    "#b8860b",
    "CRITICAL":   "#cc2200",
    "NEW":        "#5566aa",
    "NO_PRODUCT": "#888888",
    "REVIEW":     "#b8860b",
    "HEAVY":      "#cc2200",
}

def render_html(results, failed, ou_id, months, start, end, out_path):
    generated = datetime.utcnow().strftime("%Y-%m-%d %H:%M UTC")

    product_rows   = [r for r in results if not r.get("is_new") and r.get("error") is None]
    new_rows       = [r for r in results if r.get("is_new") and r.get("error") is None]
    sorted_product = sorted(product_rows, key=lambda r: r["bvr"])

    def pct(v):
        return f"{v:.1%}"

    def usd(v):
        return f"${v:,.0f}"

    def glr_fmt(v):
        return "N/A" if v == float("inf") else f"{v:.2f}"

    def status_badge(label, colour):
        return (f'<span style="background:{colour};color:#fff;'
                f'padding:2px 8px;border-radius:3px;font-size:0.85em;'
                f'font-weight:bold">{label}</span>')

    rows_html = ""
    for r in sorted_product:
        bs  = bvr_status(r["bvr"], r["is_new"])
        gs  = glr_status(r["glr"])
        bc  = STATUS_COLOUR.get(bs, "#888")
        gc  = STATUS_COLOUR.get(gs, "#888")
        urg = ", ".join(r["urgent"]) if r["urgent"] else ""
        rows_html += f"""
        <tr>
          <td><a href="{r['detail_file']}">{r['name']}</a></td>
          <td style="font-family:monospace">{r['id']}</td>
          <td style="text-align:right">{usd(r['monthly_avg'])}</td>
          <td style="text-align:right">{usd(r['breakdown']['PRODUCT'])}</td>
          <td style="text-align:right">{usd(r['breakdown']['ENABLEMENT'])}</td>
          <td style="text-align:right">{usd(r['breakdown']['GOVERNANCE'])}</td>
          <td style="text-align:center">{status_badge(pct(r['bvr']), bc)}</td>
          <td style="text-align:center">{status_badge(glr_fmt(r['glr']), gc)}</td>
          <td style="font-size:0.8em;color:#c00">{urg}</td>
        </tr>"""

    new_rows_html = ""
    for r in new_rows:
        new_rows_html += f"""
        <tr style="color:#5566aa">
          <td><a href="{r['detail_file']}">{r['name']}</a></td>
          <td style="font-family:monospace">{r['id']}</td>
          <td style="text-align:right">{usd(r['monthly_avg'])}</td>
          <td colspan="6" style="color:#5566aa">New account: no product workload detected</td>
        </tr>"""

    failed_rows_html = ""
    for f in failed:
        failed_rows_html += f"""
        <tr style="color:#888">
          <td>{f['name']}</td>
          <td style="font-family:monospace">{f['id']}</td>
          <td colspan="7">{f['error']}</td>
        </tr>"""

    total_spend    = sum(r["total_raw"]           for r in product_rows)
    total_product  = sum(r["breakdown"]["PRODUCT"] for r in product_rows)
    org_bvr        = total_product / total_spend if total_spend > 0 else 0
    critical_count = sum(1 for r in product_rows if bvr_status(r["bvr"], False) == "CRITICAL")
    warning_count  = sum(1 for r in product_rows if bvr_status(r["bvr"], False) == "WARNING")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AWS BVR OU Summary: {ou_id}</title>
<style>
  body  {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
           margin: 40px; color: #222; background: #fafafa; }}
  h1    {{ font-size: 1.4em; margin-bottom: 4px; }}
  h2    {{ font-size: 1.1em; margin-top: 32px; border-bottom: 1px solid #ddd;
           padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.9em; margin-top: 12px; }}
  th    {{ background: #222; color: #fff; padding: 8px 10px; text-align: left; }}
  td    {{ padding: 7px 10px; border-bottom: 1px solid #e0e0e0; vertical-align: top; }}
  tr:hover td {{ background: #f0f4ff; }}
  .summary-box {{ display: inline-block; background: #fff; border: 1px solid #ddd;
                  border-radius: 6px; padding: 16px 24px; margin: 8px 8px 8px 0;
                  min-width: 140px; }}
  .summary-box .val {{ font-size: 1.6em; font-weight: bold; }}
  .summary-box .lbl {{ font-size: 0.8em; color: #666; margin-top: 2px; }}
  a {{ color: #1a5fb4; }}
</style>
</head>
<body>
<h1>AWS Business Value Ratio: OU Summary Report</h1>
<p style="color:#666;font-size:0.85em">
  OU: <strong>{ou_id}</strong> &nbsp;|&nbsp;
  Period: {start} to {end} ({months} months) &nbsp;|&nbsp;
  Generated: {generated}
</p>

<div>
  <div class="summary-box">
    <div class="val">{len(product_rows)}</div>
    <div class="lbl">Product accounts scanned</div>
  </div>
  <div class="summary-box">
    <div class="val" style="color:{STATUS_COLOUR['CRITICAL']}">{critical_count}</div>
    <div class="lbl">Critical (BVR &lt; 35%)</div>
  </div>
  <div class="summary-box">
    <div class="val" style="color:{STATUS_COLOUR['WARNING']}">{warning_count}</div>
    <div class="lbl">Warning (BVR 35-60%)</div>
  </div>
  <div class="summary-box">
    <div class="val">{pct(org_bvr)}</div>
    <div class="lbl">Aggregate OU BVR</div>
  </div>
  <div class="summary-box">
    <div class="val">{usd(total_spend)}</div>
    <div class="lbl">Total OU spend ({months}m)</div>
  </div>
</div>

<h2>Product accounts: ranked by BVR, worst first</h2>
<table>
  <tr>
    <th>Account name</th>
    <th>Account ID</th>
    <th>Avg monthly spend</th>
    <th>Product spend</th>
    <th>Enablement spend</th>
    <th>Governance spend</th>
    <th>BVR</th>
    <th>GLR</th>
    <th>Urgent services</th>
  </tr>
  {rows_html}
</table>

<h2>New accounts: no product workload detected</h2>
<table>
  <tr>
    <th>Account name</th><th>Account ID</th><th>Avg monthly spend</th>
    <th colspan="6">Status</th>
  </tr>
  {new_rows_html if new_rows_html else '<tr><td colspan="9" style="color:#888">None</td></tr>'}
</table>

<h2>Failed scans</h2>
<table>
  <tr>
    <th>Account name</th><th>Account ID</th><th colspan="7">Error</th>
  </tr>
  {failed_rows_html if failed_rows_html else '<tr><td colspan="9" style="color:#888">None</td></tr>'}
</table>

<p style="font-size:0.75em;color:#aaa;margin-top:40px">
  Generated by aws_ou_bvr_scan.py &mdash; BVR and GLR are heuristic indicators.
  Account names link to per-account CSV detail files in the same directory.
</p>
</body>
</html>"""

    with open(out_path, "w") as f:
        f.write(html)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AWS OU Business Value Cost Scanner")
    parser.add_argument("--ou-id",    required=True,               help="OU ID to scan (ou-xxxx-xxxxxxxx)")
    parser.add_argument("--months",   type=int,   default=3,       help="Months to analyse (default: 3)")
    parser.add_argument("--role-name",            default="BVRAuditRole",
                                                                    help="IAM role name to assume in each account")
    parser.add_argument("--out-dir",              default="./bvr-reports",
                                                                    help="Output directory for reports")
    parser.add_argument("--profile",              default=None,    help="AWS profile for the management account")
    parser.add_argument("--recursive", action="store_true", default=True,
                                                                    help="Recurse into child OUs (default: true)")
    parser.add_argument("--no-recursive", dest="recursive", action="store_false")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    session    = boto3.Session(**session_kwargs)
    org_client = session.client("organizations")

    print(f"Enumerating accounts under {args.ou_id} ...")
    try:
        accounts = list_accounts_in_ou(org_client, args.ou_id, args.recursive)
    except ClientError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(accounts)} active accounts. Scanning ...")
    start, end = get_date_range(args.months)

    results = []
    failed  = []

    for i, account in enumerate(accounts, 1):
        print(f"  [{i:>3}/{len(accounts)}] {account['name']} ({account['id']}) ... ", end="", flush=True)
        result = scan_account(account, args.role_name, start, end, args.months, out_dir)
        if result.get("error"):
            print(f"FAILED ({result['error']})")
            failed.append(result)
        else:
            bs = bvr_status(result["bvr"], result.get("is_new", False))
            print(f"BVR={result['bvr']:.1%}  GLR={result['glr']:.2f}  [{bs}]")
            results.append(result)

    summary_path = out_dir / "bvr_summary.html"
    render_html(results, failed, args.ou_id, args.months, start, end, summary_path)

    print(f"\nSummary report: {summary_path}")
    print(f"Per-account CSVs: {out_dir}/")

    critical = [r for r in results if bvr_status(r["bvr"], r.get("is_new")) == "CRITICAL"]
    if critical:
        print(f"\nCRITICAL accounts ({len(critical)}):")
        for r in sorted(critical, key=lambda x: x["bvr"]):
            print(f"  {r['name']:<40} BVR={r['bvr']:.1%}  GLR={r['glr']:.2f}  "
                  f"spend={r['monthly_avg']:,.0f}/mo")


if __name__ == "__main__":
    main()
