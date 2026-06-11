#!/usr/bin/env python3
"""
aws_value_check.py  --  AWS Business Value Cost Auditor
========================================================
Classifies every service in your AWS bill as Value-Generating,
Overhead, or Administrative, computes a Business Value Ratio (BVR),
and flags services that warrant urgent attention.

Requirements:
    pip install boto3 rich python-dateutil

IAM permission required:
    ce:GetCostAndUsage  (Cost Explorer read access)

Usage:
    python aws_value_check.py                    # last 3 months
    python aws_value_check.py --months 6         # last 6 months
    python aws_value_check.py --csv out.csv      # also write CSV
    python aws_value_check.py --profile myprof   # named AWS profile
    python aws_value_check.py --new-account      # force new account mode
"""

import argparse
import csv
import sys
from datetime import date
from dateutil.relativedelta import relativedelta

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich import box
    RICH = True
except ImportError:
    RICH = False

# ---------------------------------------------------------------------------
# Service classification taxonomy
# ---------------------------------------------------------------------------

VALUE_GENERATING = {
    "Amazon EC2", "Amazon EC2 - Other", "EC2 - Other", "EC2-Instances", "EC2-Other",
    "Amazon Elastic Compute Cloud - Compute", "Amazon Elastic Compute Cloud",
    "Amazon Elastic Container Service", "Amazon Elastic Kubernetes Service",
    "AWS Lambda", "Amazon RDS", "Amazon Aurora",
    "Amazon Relational Database Service",
    "Amazon DynamoDB", "Amazon ElastiCache", "Amazon Redshift", "Amazon EMR",
    "Amazon SageMaker", "Amazon Bedrock",
    "Amazon Rekognition", "Amazon Comprehend", "Amazon Translate",
    "Amazon Transcribe", "Amazon Polly", "Amazon Lex", "Amazon Personalize",
    "Amazon Forecast", "Amazon Kendra",
    "Amazon S3", "Amazon Simple Storage Service", "Amazon S3 Glacier",
    "Amazon OpenSearch Service", "Amazon API Gateway", "Amazon AppSync",
    "Amazon SQS", "Amazon Simple Queue Service",
    "Amazon SNS", "Amazon Simple Notification Service",
    "Amazon Kinesis", "Amazon MSK",
    "Amazon EventBridge", "Amazon Connect", "Amazon Pinpoint", "Amazon WorkSpaces",
    "AWS Elastic Beanstalk", "Amazon Lightsail", "AWS Amplify", "AWS App Runner",
    "Amazon ECS", "Amazon EKS", "Amazon ECR", "AWS Batch", "Amazon MQ",
    "Amazon DocumentDB", "Amazon Neptune", "Amazon Timestream", "Amazon QLDB",
    "Amazon Managed Blockchain", "AWS Glue", "Amazon Athena", "Amazon QuickSight",
    "AWS Lake Formation", "Amazon DataZone",
    "Amazon Registrar",
}

OVERHEAD = {
    "Amazon VPC", "Amazon Virtual Private Cloud", "VPC",
    "AWS Transit Gateway", "Amazon CloudFront",
    "Amazon Route 53", "Route 53",
    "AWS Direct Connect",
    "Amazon Elastic Load Balancing", "Elastic Load Balancing",
    "AWS Global Accelerator", "AWS PrivateLink",
    "AWS Certificate Manager", "Certificate Manager",
    "AWS Secrets Manager", "Secrets Manager",
    "AWS Key Management Service", "Key Management Service",
    "AWS Identity and Access Management", "AWS IAM Identity Center",
    "Amazon Cognito", "AWS Directory Service", "Directory Service",
    "AWS WAF", "AWS Shield", "Amazon Inspector", "AWS Firewall Manager",
    "AWS Network Firewall", "Amazon Macie", "AWS Security Hub",
    "Amazon Backup", "AWS Disaster Recovery Service",
    "AWS Elastic Disaster Recovery", "AWS DataSync", "AWS Transfer Family",
    "AWS Snow Family", "AWS Storage Gateway", "Amazon WorkMail",
    "Amazon WorkDocs", "Amazon Chime", "AWS Systems Manager", "Systems Manager",
    "AWS OpsWorks", "AWS CodeDeploy", "AWS CodePipeline", "AWS CodeBuild",
    "AWS CodeCommit", "AWS CodeArtifact", "Amazon ECR Public",
    "AWS App Mesh", "AWS Service Mesh", "Amazon EFS", "AWS Fargate",
}

ADMINISTRATIVE = {
    "Amazon CloudWatch", "CloudWatch", "AmazonCloudWatch",
    "AWS CloudTrail", "AWS Config", "Config",
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
    "AWS Database Migration Service", "AWS Schema Conversion Tool",
    "AWS Well-Architected Tool", "AWS Service Quotas", "AWS Resource Groups",
    "AWS Tag Editor", "Tax", "AWS Tax",
    "Savings Plans for AWS Compute usage", "Savings Plans Upfront Fee",
    "AWS Reserved Instance",
}

# Services that are nearly always orphaned or accumulated waste in product accounts.
# EBS snapshots show up under "Amazon EBS" in Cost Explorer when billed separately,
# or as part of "EC2 - Other" / "Amazon EC2" at the usage-type level.
WASTE = {
    "Amazon EBS",
    "Amazon EC2 Snapshots",
    "EBS Snapshots",
}

WARNING_THRESHOLDS = {
    "Amazon CloudWatch": 50, "CloudWatch": 50,
    "AWS Config": 30, "Config": 30,
    "Amazon GuardDuty": 100, "GuardDuty": 100,
    "AWS CloudTrail": 50,
    "Amazon OpenSearch Service": 500,
    "AWS Directory Service": 200, "Directory Service": 200,
    "Amazon Route 53": 200, "Route 53": 200,
    "AWS Certificate Manager": 100, "Certificate Manager": 100,
    "AWS Secrets Manager": 50, "Secrets Manager": 50,
    "Amazon EBS": 20, "Amazon EC2 Snapshots": 20, "EBS Snapshots": 20,
}

REVIEW_ADVICE = {
    "Amazon OpenSearch Service": (
        "Confirm this cluster is serving a customer-facing feature rather than "
        "internal log analysis. If it is a log sink, replace with S3 plus Athena "
        "for ad hoc queries or OpenSearch Serverless to eliminate provisioned node "
        "costs. A shared cluster serving a single team rarely needs production-tier "
        "node counts."
    ),
    "Amazon CloudWatch": (
        "CloudWatch costs compound across log ingestion, retention, and custom "
        "metrics. Set retention policies on all log groups (30 days for operational, "
        "90 days for security-relevant logs), reduce custom metric resolution where "
        "1-minute granularity is not needed, and route high-volume application logs "
        "to S3 via Firehose."
    ),
    "CloudWatch": (
        "Set retention policies on all log groups, reduce custom metric resolution, "
        "and route high-volume application logs to S3 via Firehose."
    ),
    "AWS Config": (
        "Config charges per configuration item recorded. Disable rules not actively "
        "monitored, exclude ephemeral resources such as Lambda versions and ECS tasks, "
        "and use Config aggregation rather than per-account rules where possible."
    ),
    "Config": (
        "Disable rules not actively reviewed and exclude ephemeral resource types "
        "to reduce configuration item volume."
    ),
    "AWS Certificate Manager": (
        "Public ACM certificates are free. Material cost here almost certainly means "
        "ACM Private CA at USD 400 per month per CA regardless of usage. Audit active "
        "private CAs, consolidate under a single CA hierarchy, and confirm all "
        "consumers genuinely require private PKI."
    ),
    "Certificate Manager": (
        "Material ACM cost almost always means Private CA at USD 400 per month per CA. "
        "Audit active private CAs and consolidate where possible."
    ),
    "Amazon Route 53": (
        "Route 53 charges per hosted zone and per query. Audit for stale or redundant "
        "zones, disable health checks on non-critical endpoints, and move high-volume "
        "internal resolution to a private hosted zone with Route 53 Resolver."
    ),
    "Route 53": (
        "Audit hosted zones for stale entries, disable health checks on non-critical "
        "endpoints, and use private hosted zones for internal resolution."
    ),
    "AWS Directory Service": (
        "Managed Microsoft AD bills per domain controller at approximately USD 0.16 "
        "per DC-hour across a minimum of two DCs per directory. Confirm all directories "
        "are actively used; orphaned directories from legacy migrations are common and "
        "cost roughly USD 230 per month each."
    ),
    "Directory Service": (
        "Audit active directories. Orphaned Managed AD instances from old migrations "
        "cost roughly USD 230 per month each and are frequently overlooked."
    ),
    "Amazon GuardDuty": (
        "GuardDuty costs scale with CloudTrail, VPC Flow Log, and DNS log volume. "
        "Confirm findings are being triaged and actioned. Disable add ons such as "
        "Malware Protection or EKS Runtime Monitoring if there is no response playbook "
        "for those finding types."
    ),
    "GuardDuty": (
        "Confirm findings are being actioned and disable protection types not covered "
        "by an active response playbook."
    ),
    "AWS Secrets Manager": (
        "Secrets Manager charges per secret per month plus per API call. Audit for "
        "unused secrets and use SSM Parameter Store for non-sensitive configuration "
        "to eliminate per-secret monthly charges."
    ),
    "Secrets Manager": (
        "Audit for unused secrets and use SSM Parameter Store for non-sensitive "
        "configuration to eliminate per-secret monthly charges."
    ),
    "Amazon EBS": (
        "EBS snapshot storage accumulates indefinitely unless a lifecycle policy is "
        "applied. Audit for snapshots older than 90 days with no active AMI dependency, "
        "delete orphaned volumes (state: available), and enable Data Lifecycle Manager "
        "to enforce automated retention on all future snapshots."
    ),
    "Amazon EC2 Snapshots": (
        "Snapshot costs grow silently — AWS does not expire them by default. "
        "Run `aws ec2 describe-snapshots --owner-ids self` to list all snapshots, "
        "identify those with no AMI or active restore dependency, and delete them. "
        "Use Data Lifecycle Manager policies to cap retention going forward."
    ),
    "EBS Snapshots": (
        "Snapshot costs grow silently — AWS does not expire them by default. "
        "Audit with `aws ec2 describe-snapshots --owner-ids self`, delete orphaned "
        "snapshots, and enforce retention via Data Lifecycle Manager."
    ),
}

NEW_ACCOUNT_SPEND_THRESHOLD = 150.0


# ---------------------------------------------------------------------------
# Classification and helpers
# ---------------------------------------------------------------------------

def classify(service_name: str) -> str:
    if service_name in WASTE:
        return "WASTE"
    if service_name in VALUE_GENERATING:
        return "VALUE"
    if service_name in OVERHEAD:
        return "OVERHEAD"
    if service_name in ADMINISTRATIVE:
        return "ADMIN"
    sl = service_name.lower()
    if any(k in sl for k in ("snapshot",)):
        return "WASTE"
    if any(k in sl for k in ("ec2", "rds", "lambda", "sagemaker", "bedrock",
                              "ecs", "eks", "opensearch", "elasticache",
                              "redshift", "emr", "aurora", "dynamodb",
                              "kinesis", "s3 glacier", "msk")):
        return "VALUE"
    if any(k in sl for k in ("cloudwatch", "config", "guardduty", "cloudtrail",
                              "audit", "security hub", "inspector", "macie",
                              "detective", "trusted advisor", "health")):
        return "ADMIN"
    if any(k in sl for k in ("vpc", "route 53", "certificate", "directory",
                              "secrets", "kms", "iam", "cognito", "waf",
                              "shield", "firewall", "backup", "load balanc",
                              "transit gateway", "cloudfront", "direct connect")):
        return "OVERHEAD"
    return "UNKNOWN"


def get_date_range(months_back: int) -> tuple:
    today = date.today()
    end = today.replace(day=1)
    start = end - relativedelta(months=months_back)
    return start.strftime("%Y-%m-%d"), end.strftime("%Y-%m-%d")


def fetch_costs(ce_client, start: str, end: str) -> dict:
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


def bvr_colour(ratio: float) -> str:
    if ratio >= 0.60:
        return "green"
    if ratio >= 0.35:
        return "yellow"
    return "red"


def urgency(service: str, cost: float, category: str) -> str:
    if category == "WASTE" and cost >= 0.01:
        return "URGENT"
    threshold = WARNING_THRESHOLDS.get(service)
    if threshold and cost >= threshold:
        return "URGENT"
    if category == "ADMIN" and cost >= 200:
        return "REVIEW"
    if category == "OVERHEAD" and cost >= 500:
        return "REVIEW"
    return ""


def is_new_account(costs: dict, months: int) -> bool:
    total = sum(costs.values())
    monthly_avg = total / max(months, 1)
    value_spend = sum(v for s, v in costs.items() if classify(s) == "VALUE")
    return monthly_avg < NEW_ACCOUNT_SPEND_THRESHOLD and value_spend < 1.0


# ---------------------------------------------------------------------------
# Plain text output
# ---------------------------------------------------------------------------

def separator():
    print("-" * 90)


def print_plain(costs: dict, months: int):
    total = sum(costs.values())
    breakdown = {
        "VALUE":   sum(v for s, v in costs.items() if classify(s) == "VALUE"),
        "OVERHEAD": sum(v for s, v in costs.items() if classify(s) == "OVERHEAD"),
        "ADMIN":   sum(v for s, v in costs.items() if classify(s) == "ADMIN"),
        "WASTE":   sum(v for s, v in costs.items() if classify(s) == "WASTE"),
        "UNKNOWN": sum(v for s, v in costs.items() if classify(s) == "UNKNOWN"),
    }
    bvr = breakdown["VALUE"] / total if total > 0 else 0.0

    print("\n" + "=" * 90)
    print("  AWS BUSINESS VALUE COST AUDIT")
    print(f"  Period: {months} months    Total spend: ${total:,.2f}")
    print("=" * 90)
    print(f"\n  Business Value Ratio (BVR): {bvr:.1%}")
    print(f"  Value-generating:  ${breakdown['VALUE']:>10,.2f}  ({breakdown['VALUE']/total:.1%})")
    print(f"  Overhead:          ${breakdown['OVERHEAD']:>10,.2f}  ({breakdown['OVERHEAD']/total:.1%})")
    print(f"  Administrative:    ${breakdown['ADMIN']:>10,.2f}  ({breakdown['ADMIN']/total:.1%})")
    if breakdown["WASTE"]:
        print(f"  Waste:             ${breakdown['WASTE']:>10,.2f}  ({breakdown['WASTE']/total:.1%})")
    if breakdown["UNKNOWN"]:
        print(f"  Unclassified:      ${breakdown['UNKNOWN']:>10,.2f}  ({breakdown['UNKNOWN']/total:.1%})")

    if bvr < 0.35:
        print("\n  [CRITICAL] BVR below 35%. Account costs more to run than the business it serves.")
    elif bvr < 0.60:
        print("\n  [WARNING] BVR below 60%. Overhead and administrative costs are elevated.")
    else:
        print("\n  [OK] BVR is healthy.")

    print("\n")
    separator()
    print(f"  {'SERVICE':<45} {'CATEGORY':<12} {'COST':>12}  {'SHARE':>6}  {'FLAG'}")
    separator()

    urgent_services = []
    for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
        if cost < 0.01:
            continue
        cat = classify(service)
        flag = urgency(service, cost, cat)
        share = cost / total * 100
        print(f"  {service:<45} {cat:<12} ${cost:>11,.2f}  {share:>5.1f}%  {flag}")
        if flag == "URGENT":
            urgent_services.append(service)

    separator()

    if urgent_services:
        print("\n  URGENT REVIEW ITEMS\n")
        for svc in urgent_services:
            advice = REVIEW_ADVICE.get(svc)
            if advice:
                print(f"  [{svc}]\n  {advice}\n")
    print()


def print_new_account_plain(costs: dict, months: int):
    total = sum(costs.values())
    monthly_avg = total / max(months, 1)
    print("\n" + "=" * 70)
    print("  NEW ACCOUNT DETECTED")
    print("=" * 70)
    print(f"\n  Total spend ({months}m): ${total:,.2f}   Monthly average: ${monthly_avg:,.2f}")
    print("  Value-generating workload: $0.00\n")
    print("  All current spend is provisioning standards overhead.")
    print("  Do not deploy production workloads until this baseline is")
    print("  reviewed and rationalised.\n")
    print("  Recommended action: review the account vending template against")
    print("  this service list before onboarding application teams.\n")
    print("  Current services:")
    separator()
    for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
        if cost < 0.01:
            continue
        cat = classify(service)
        print(f"  {service:<45} {cat:<12} ${cost:>10,.2f}")
    separator()
    print()


# ---------------------------------------------------------------------------
# Rich output
# ---------------------------------------------------------------------------

def print_rich(costs: dict, months: int, start: str, end: str):
    console = Console()
    total = sum(costs.values())
    breakdown = {
        "VALUE":   sum(v for s, v in costs.items() if classify(s) == "VALUE"),
        "OVERHEAD": sum(v for s, v in costs.items() if classify(s) == "OVERHEAD"),
        "ADMIN":   sum(v for s, v in costs.items() if classify(s) == "ADMIN"),
        "WASTE":   sum(v for s, v in costs.items() if classify(s) == "WASTE"),
        "UNKNOWN": sum(v for s, v in costs.items() if classify(s) == "UNKNOWN"),
    }
    bvr = breakdown["VALUE"] / total if total > 0 else 0.0
    colour = bvr_colour(bvr)

    summary_lines = [
        f"[bold]Period:[/bold] {start} to {end}   [bold]Months analysed:[/bold] {months}",
        f"[bold]Total AWS spend:[/bold] [yellow]${total:,.2f}[/yellow]",
        "",
        f"[bold]Business Value Ratio (BVR):[/bold] [{colour} bold]{bvr:.1%}[/{colour} bold]",
        "",
        f"  Value-generating:  [green]${breakdown['VALUE']:>12,.2f}[/green]  ({breakdown['VALUE']/total:.1%})",
        f"  Overhead:          [yellow]${breakdown['OVERHEAD']:>12,.2f}[/yellow]  ({breakdown['OVERHEAD']/total:.1%})",
        f"  Administrative:    [cyan]${breakdown['ADMIN']:>12,.2f}[/cyan]  ({breakdown['ADMIN']/total:.1%})",
    ]
    if breakdown["WASTE"]:
        summary_lines.append(
            f"  Waste:             [red]${breakdown['WASTE']:>12,.2f}[/red]  ({breakdown['WASTE']/total:.1%})"
        )
    if breakdown["UNKNOWN"]:
        summary_lines.append(
            f"  Unclassified:      [dim]${breakdown['UNKNOWN']:>12,.2f}[/dim]  ({breakdown['UNKNOWN']/total:.1%})"
        )
    if bvr < 0.35:
        summary_lines += ["", "[red bold]CRITICAL: BVR below 35%. Account costs more to run than the business it serves.[/red bold]"]
    elif bvr < 0.60:
        summary_lines += ["", "[yellow bold]WARNING: BVR below 60%. Overhead and administrative costs are elevated.[/yellow bold]"]
    else:
        summary_lines += ["", "[green bold]HEALTHY: BVR is above 60%.[/green bold]"]

    console.print(Panel("\n".join(summary_lines), title="[bold]AWS Business Value Cost Audit[/bold]", expand=True))

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white")
    table.add_column("Service", style="white", min_width=40)
    table.add_column("Category", justify="left", min_width=10)
    table.add_column("Cost (USD)", justify="right", min_width=12)
    table.add_column("Share", justify="right", min_width=7)
    table.add_column("Flag", justify="center", min_width=8)

    cat_style = {"VALUE": "green", "OVERHEAD": "yellow", "ADMIN": "cyan", "WASTE": "red", "UNKNOWN": "dim"}
    urgent_services = []

    for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
        if cost < 0.01:
            continue
        cat = classify(service)
        flag = urgency(service, cost, cat)
        share = cost / total * 100
        style = cat_style.get(cat, "white")
        flag_display = "[red bold]URGENT[/red bold]" if flag == "URGENT" else (
                       "[yellow]REVIEW[/yellow]" if flag == "REVIEW" else "")
        table.add_row(service, f"[{style}]{cat}[/{style}]", f"${cost:,.2f}", f"{share:.1f}%", flag_display)
        if flag == "URGENT":
            urgent_services.append(service)

    console.print(table)

    if urgent_services:
        console.print("\n[bold red]URGENT REVIEW ITEMS[/bold red]\n")
        for svc in urgent_services:
            advice = REVIEW_ADVICE.get(svc)
            if advice:
                console.print(Panel(advice, title=f"[red bold]{svc}[/red bold]", expand=False))


def print_new_account_rich(costs: dict, months: int):
    console = Console()
    total = sum(costs.values())
    monthly_avg = total / max(months, 1)

    summary = "\n".join([
        f"[bold]Total spend ({months}m):[/bold] [yellow]${total:,.2f}[/yellow]   "
        f"[bold]Monthly average:[/bold] [yellow]${monthly_avg:,.2f}[/yellow]",
        "[bold]Value-generating workload:[/bold] [red]$0.00[/red]",
        "",
        "[yellow]All current spend is provisioning standards overhead.[/yellow]",
        "Do not deploy production workloads until this baseline is reviewed and rationalised.",
        "",
        "[bold]Recommended action:[/bold] review the account vending template against",
        "this service list before onboarding application teams.",
    ])
    console.print(Panel(summary, title="[bold red]NEW ACCOUNT DETECTED[/bold red]", expand=True))

    table = Table(box=box.SIMPLE_HEAVY, show_header=True, header_style="bold white")
    table.add_column("Service", min_width=40)
    table.add_column("Category", min_width=10)
    table.add_column("Cost (USD)", justify="right", min_width=12)

    cat_style = {"VALUE": "green", "OVERHEAD": "yellow", "ADMIN": "cyan", "WASTE": "red", "UNKNOWN": "dim"}
    for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
        if cost < 0.01:
            continue
        cat = classify(service)
        style = cat_style.get(cat, "white")
        table.add_row(service, f"[{style}]{cat}[/{style}]", f"${cost:,.2f}")

    console.print(table)


# ---------------------------------------------------------------------------
# CSV export
# ---------------------------------------------------------------------------

def write_csv(costs: dict, path: str, total: float):
    with open(path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Service", "Category", "Cost_USD", "Share_Pct", "Flag"])
        for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
            if cost < 0.01:
                continue
            cat = classify(service)
            flag = urgency(service, cost, cat)
            share = cost / total * 100
            writer.writerow([service, cat, f"{cost:.2f}", f"{share:.2f}", flag])
    print(f"CSV written to {path}")


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="AWS Business Value Cost Auditor")
    parser.add_argument("--months",      type=int, default=3,    help="Months to analyse (default: 3)")
    parser.add_argument("--csv",         type=str, default=None, help="Optional CSV output path")
    parser.add_argument("--profile",     type=str, default=None, help="AWS profile name")
    parser.add_argument("--no-rich",     action="store_true",    help="Force plain text output")
    parser.add_argument("--new-account", action="store_true",    help="Force new account detection mode")
    args = parser.parse_args()

    session_kwargs = {}
    if args.profile:
        session_kwargs["profile_name"] = args.profile

    try:
        session = boto3.Session(**session_kwargs)
        ce = session.client("ce", region_name="us-east-1")
    except Exception as e:
        print(f"ERROR: Could not create AWS session: {e}", file=sys.stderr)
        sys.exit(1)

    start, end = get_date_range(args.months)
    print(f"Fetching Cost Explorer data ({start} to {end}) ...")

    try:
        costs = fetch_costs(ce, start, end)
    except NoCredentialsError:
        print("ERROR: No AWS credentials found. Configure via environment variables, "
              "~/.aws/credentials, or an IAM role.", file=sys.stderr)
        sys.exit(1)
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "OptInRequired":
            print("ERROR: Cost Explorer is not enabled. Enable it at "
                  "https://console.aws.amazon.com/cost-management/home", file=sys.stderr)
        else:
            print(f"ERROR: AWS API error: {e}", file=sys.stderr)
        sys.exit(1)

    if not costs:
        print("No cost data returned for the requested period.")
        sys.exit(0)

    total = sum(costs.values())

    if args.csv:
        write_csv(costs, args.csv, total)

    use_rich = RICH and not args.no_rich

    if args.new_account or is_new_account(costs, args.months):
        if use_rich:
            print_new_account_rich(costs, args.months)
        else:
            print_new_account_plain(costs, args.months)
        sys.exit(0)

    if use_rich:
        print_rich(costs, args.months, start, end)
    else:
        print_plain(costs, args.months)


if __name__ == "__main__":
    main()
