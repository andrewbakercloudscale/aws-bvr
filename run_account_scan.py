#!/usr/bin/env python3
"""
run_account_scan.py  --  Run BVR audit against one or more named AWS profiles
and write a Markdown report per account into ./scan-results/

Usage:
    python run_account_scan.py                         # default profile only
    python run_account_scan.py --profiles dev prod     # named profiles
    python run_account_scan.py --months 3              # look-back period
    python run_account_scan.py --out-dir ./results     # custom output dir
"""

import argparse
import sys
import os
from datetime import datetime, timezone
from pathlib import Path

import boto3
from botocore.exceptions import ClientError, NoCredentialsError

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from aws_value_check import (
    classify, fetch_costs, get_date_range, urgency,
    REVIEW_ADVICE, NEW_ACCOUNT_SPEND_THRESHOLD,
)


# ---------------------------------------------------------------------------
# Markdown rendering
# ---------------------------------------------------------------------------

def bvr_badge(bvr: float, is_new: bool) -> str:
    if is_new:
        return "NEW ACCOUNT"
    if bvr >= 0.60:
        return f"HEALTHY ({bvr:.1%})"
    if bvr >= 0.35:
        return f"WARNING ({bvr:.1%})"
    return f"CRITICAL ({bvr:.1%})"


def glr_fmt(glr: float) -> str:
    if glr == float("inf"):
        return "N/A (no product spend)"
    return f"{glr:.2f}"


def render_markdown(account_id: str, account_name: str, costs: dict,
                    months: int, start: str, end: str) -> str:
    total = sum(costs.values())
    if total == 0:
        return f"# {account_name}\n\nNo cost data found for period {start} to {end}.\n"

    EXCLUDE = {"Tax", "AWS Tax", "AWS Support", "Savings Plans for AWS Compute usage"}
    total_adj = total - sum(v for s, v in costs.items() if s in EXCLUDE)

    breakdown = {
        "VALUE":    sum(v for s, v in costs.items() if classify(s) == "VALUE"),
        "OVERHEAD": sum(v for s, v in costs.items() if classify(s) == "OVERHEAD"),
        "ADMIN":    sum(v for s, v in costs.items() if classify(s) == "ADMIN"),
        "WASTE":    sum(v for s, v in costs.items() if classify(s) == "WASTE"),
        "UNKNOWN":  sum(v for s, v in costs.items() if classify(s) == "UNKNOWN"),
    }

    bvr = breakdown["VALUE"] / total_adj if total_adj > 0 else 0.0
    glr_num = breakdown["OVERHEAD"] + breakdown["ADMIN"]
    glr = glr_num / breakdown["VALUE"] if breakdown["VALUE"] > 0 else float("inf")
    monthly_avg = total / months
    is_new = monthly_avg < NEW_ACCOUNT_SPEND_THRESHOLD and breakdown["VALUE"] < 1.0

    lines = []
    lines.append(f"# BVR Audit: {account_name}")
    lines.append("")
    lines.append(f"**Account ID:** `{account_id}`  ")
    lines.append(f"**Period:** {start} to {end} ({months} months)  ")
    lines.append(f"**Generated:** {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}  ")
    lines.append("")

    if is_new:
        lines.append("## Status: NEW ACCOUNT")
        lines.append("")
        lines.append("> All current spend is provisioning standards overhead.")
        lines.append("> Do not deploy production workloads until this baseline is reviewed.")
        lines.append("")
    else:
        badge = bvr_badge(bvr, is_new)
        lines.append(f"## Status: {badge}")
        lines.append("")

    lines.append("## Summary")
    lines.append("")
    lines.append(f"| Metric | Value |")
    lines.append(f"|--------|-------|")
    lines.append(f"| Total spend ({months}m) | ${total:,.2f} |")
    lines.append(f"| Monthly average | ${monthly_avg:,.2f} |")
    lines.append(f"| Business Value Ratio (BVR) | {bvr:.1%} |")
    lines.append(f"| Governance Load Ratio (GLR) | {glr_fmt(glr)} |")
    lines.append(f"| Value-generating spend | ${breakdown['VALUE']:,.2f} ({breakdown['VALUE']/total:.1%}) |")
    lines.append(f"| Enablement spend | ${breakdown['OVERHEAD']:,.2f} ({breakdown['OVERHEAD']/total:.1%}) |")
    lines.append(f"| Governance spend | ${breakdown['ADMIN']:,.2f} ({breakdown['ADMIN']/total:.1%}) |")
    if breakdown["WASTE"]:
        lines.append(f"| **Waste** | **${breakdown['WASTE']:,.2f}** ({breakdown['WASTE']/total:.1%}) |")
    if breakdown["UNKNOWN"]:
        lines.append(f"| Unclassified | ${breakdown['UNKNOWN']:,.2f} ({breakdown['UNKNOWN']/total:.1%}) |")
    lines.append("")

    if not is_new:
        if bvr < 0.35:
            lines.append("> **CRITICAL:** BVR below 35%. The account costs more to run than the business it serves.")
            lines.append("> Review spend composition before attempting further cost optimisation.")
        elif bvr < 0.60:
            lines.append("> **WARNING:** BVR below 60%. Enablement and governance costs are elevated relative to product spend.")
        else:
            lines.append("> **HEALTHY:** BVR is above 60%. Most spend is directed at value-generating workloads.")
        lines.append("")

        if glr != float("inf"):
            if glr > 0.75:
                lines.append(f"> **GLR {glr:.2f}:** Infrastructure-heavy relative to product footprint. Review enablement and governance spend.")
            elif glr > 0.25:
                lines.append(f"> **GLR {glr:.2f}:** Governance and enablement spend warrants review.")
            else:
                lines.append(f"> **GLR {glr:.2f}:** Governance and enablement costs are proportionate.")
        lines.append("")

    lines.append("## Service Breakdown")
    lines.append("")
    lines.append("| Service | Category | Cost (USD) | Share | Flag |")
    lines.append("|---------|----------|-----------|-------|------|")

    urgent_services = []
    for service, cost in sorted(costs.items(), key=lambda x: x[1], reverse=True):
        if cost < 0.01:
            continue
        cat = classify(service)
        flag = urgency(service, cost, cat)
        share = cost / total * 100
        flag_str = flag if flag else ""
        lines.append(f"| {service} | {cat} | ${cost:,.2f} | {share:.1f}% | {flag_str} |")
        if flag == "URGENT":
            urgent_services.append(service)

    lines.append("")

    if urgent_services:
        lines.append("## Urgent Review Items")
        lines.append("")
        for svc in urgent_services:
            advice = REVIEW_ADVICE.get(svc)
            if advice:
                lines.append(f"### {svc}")
                lines.append("")
                lines.append(advice)
                lines.append("")

    lines.append("---")
    lines.append("*Generated by [aws-bvr](https://github.com/andrewbakercloudscale/aws-bvr)*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def scan_profile(profile: str, months: int, start: str, end: str, out_dir: Path):
    label = profile if profile else "default"
    print(f"  Scanning profile: {label} ... ", end="", flush=True)

    try:
        kwargs = {"profile_name": profile} if profile else {}
        session = boto3.Session(**kwargs)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        account_id = identity["Account"]
        account_name = label
        ce = session.client("ce", region_name="us-east-1")
        costs = fetch_costs(ce, start, end)
    except NoCredentialsError:
        print("FAILED (no credentials)")
        return
    except ClientError as e:
        print(f"FAILED ({e.response['Error']['Code']})")
        return

    md = render_markdown(account_id, account_name, costs, months, start, end)
    safe = label.replace("/", "_").replace(" ", "_")
    out_path = out_dir / f"{account_id}_{safe}.md"
    out_path.write_text(md)
    total = sum(costs.values())
    print(f"OK  ${total:,.2f} -> {out_path.name}")


def main():
    parser = argparse.ArgumentParser(description="Run BVR audit against AWS profiles, write Markdown reports")
    parser.add_argument("--profiles", nargs="*", default=[None],
                        help="Named AWS profiles to scan (default: uses default credential chain)")
    parser.add_argument("--months",  type=int, default=3, help="Months to analyse (default: 3)")
    parser.add_argument("--out-dir", default="./scan-results", help="Output directory (default: ./scan-results)")
    args = parser.parse_args()

    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    start, end = get_date_range(args.months)
    print(f"Period: {start} to {end}")

    for profile in args.profiles:
        scan_profile(profile, args.months, start, end, out_dir)

    print(f"\nReports written to {out_dir}/")


if __name__ == "__main__":
    main()
