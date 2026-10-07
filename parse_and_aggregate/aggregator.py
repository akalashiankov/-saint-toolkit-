#!/usr/bin/env python3
"""
aggregator.py - SAINT's result parser & aggregator

Walks output/nmap, output/zap, output/burp, output/manual_poc for
normalized findings JSON (see findings_schema.md), combines them, dedupes,
assigns OWASP Top 10 categories via keyword matching, and renders the final
report in Markdown, HTML, and JSON.

Usage:
    python3 aggregator.py --target-name example-lab-app
"""

import argparse
import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

import yaml
from jinja2 import Template

ROOT_DIR = Path(__file__).resolve().parent.parent
OUTPUT_DIR = ROOT_DIR / "output"
REPORT_CONFIG_FILE = ROOT_DIR / "config" / "report_config.yaml"
TEMPLATE_FILE = Path(__file__).resolve().parent / "templates" / "report_template.md"
FINAL_REPORT_DIR = OUTPUT_DIR / "final_report"

# Very small keyword -> OWASP Top 10 (2021) mapping. This is intentionally
# simple and meant to be extended -- it's a starting point, not a complete
# classifier. Anything that doesn't match stays uncategorized rather than
# being force-fit into the wrong bucket.
OWASP_KEYWORD_MAP = {
    "A01:2021-Broken Access Control": ["access control", "idor", "forced browsing", "path traversal", "authorization bypass"],
    "A02:2021-Cryptographic Failures": ["tls", "ssl", "weak cipher", "cleartext", "certificate", "encryption"],
    "A03:2021-Injection": ["sql injection", "xss", "cross-site scripting", "command injection", "ldap injection", "injection"],
    "A04:2021-Insecure Design": ["insecure design", "business logic"],
    "A05:2021-Security Misconfiguration": ["misconfiguration", "default credential", "directory listing", "verbose error", "debug mode", "banner"],
    "A06:2021-Vulnerable and Outdated Components": ["outdated", "vulnerable component", "known vulnerable", "end of life", "unpatched"],
    "A07:2021-Identification and Authentication Failures": ["authentication", "session fixation", "weak password", "credential stuffing", "brute force"],
    "A08:2021-Software and Data Integrity Failures": ["deserialization", "integrity", "supply chain"],
    "A09:2021-Security Logging and Monitoring Failures": ["logging", "monitoring"],
    "A10:2021-Server-Side Request Forgery": ["ssrf", "server-side request forgery"],
}


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def guess_owasp_category(title, description):
    text = f"{title} {description}".lower()
    for category, keywords in OWASP_KEYWORD_MAP.items():
        for kw in keywords:
            if kw in text:
                return category
    return None


def collect_findings(target_name):
    """Glob every normalized findings JSON under output/*/ for this target."""
    findings = []
    seen_ids = set()

    for subdir in ["nmap", "zap", "burp", "manual_poc"]:
        dir_path = OUTPUT_DIR / subdir
        if not dir_path.exists():
            continue
        for json_file in dir_path.glob("*.json"):
            if json_file.name.endswith("_template.json"):
                continue  # skip the manual_poc template itself
            try:
                with open(json_file) as f:
                    data = json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                print(f"WARNING: could not read {json_file}: {e}")
                continue

            if data.get("target_name") != target_name:
                continue

            for finding in data.get("findings", []):
                dedup_key = (finding.get("source"), finding.get("id"))
                if dedup_key in seen_ids:
                    continue
                seen_ids.add(dedup_key)

                if not finding.get("owasp_category"):
                    finding["owasp_category"] = guess_owasp_category(
                        finding.get("title", ""), finding.get("description", "")
                    )

                findings.append(finding)

    return findings


def group_by_severity(findings, severity_order):
    grouped = defaultdict(list)
    for f in findings:
        grouped[f.get("severity", "Informational")].append(f)
    # Return in the configured order, dropping empty buckets
    return [(sev, grouped[sev]) for sev in severity_order if grouped[sev]]


def group_by_owasp(findings, owasp_order):
    grouped = defaultdict(list)
    uncategorized = []
    for f in findings:
        cat = f.get("owasp_category")
        if cat:
            grouped[cat].append(f)
        else:
            uncategorized.append(f)
    result = [(cat, grouped[cat]) for cat in owasp_order if grouped[cat]]
    if uncategorized:
        result.append(("Uncategorized", uncategorized))
    return result


def summary_counts(findings, severity_order):
    counts = {sev: 0 for sev in severity_order}
    for f in findings:
        sev = f.get("severity", "Informational")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def render_markdown(context):
    template_text = TEMPLATE_FILE.read_text()
    template = Template(template_text)
    return template.render(**context)


def markdown_to_html(md_text, title):
    # Minimal, dependency-light md->html wrapper. For nicer output, swap in
    # the `markdown` package if it's available in your environment.
    try:
        import markdown as md_lib
        body = md_lib.markdown(md_text, extensions=["tables", "fenced_code"])
    except ImportError:
        # Fallback: wrap as <pre> so the HTML report still works without the
        # markdown package installed.
        import html
        body = f"<pre>{html.escape(md_text)}</pre>"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif; max-width: 900px; margin: 40px auto; padding: 0 20px; line-height: 1.5; color: #1a1a1a; }}
  h1, h2, h3 {{ border-bottom: 1px solid #ddd; padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 16px 0; }}
  th, td {{ border: 1px solid #ccc; padding: 8px; text-align: left; vertical-align: top; }}
  th {{ background: #f4f4f4; }}
  code, pre {{ background: #f4f4f4; padding: 2px 4px; border-radius: 4px; }}
  .sev-Critical {{ color: #8b0000; font-weight: bold; }}
  .sev-High {{ color: #c0392b; font-weight: bold; }}
  .sev-Medium {{ color: #d68910; font-weight: bold; }}
  .sev-Low {{ color: #2874a6; }}
  .sev-Informational {{ color: #566573; }}
</style>
</head>
<body>
{body}
</body>
</html>"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-name", required=True)
    args = parser.parse_args()

    report_cfg = load_yaml(REPORT_CONFIG_FILE)["report"]
    severity_order = report_cfg["severity_order"]
    owasp_order = report_cfg["owasp_top10_2021"]

    findings = collect_findings(args.target_name)

    if not findings:
        print(f"No normalized findings found for target '{args.target_name}'.")
        print("Run the individual scan scripts first (nmap_scan.sh, zap_scan.py, burp_export.sh)")
        print("or fill in output/manual_poc/<target>_manual_poc.json.")
        return

    by_severity = group_by_severity(findings, severity_order)
    by_owasp = group_by_owasp(findings, owasp_order)
    counts = summary_counts(findings, severity_order)

    context = {
        "report_title": report_cfg["title"],
        "target_name": args.target_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "total_findings": len(findings),
        "counts": counts,
        "by_severity": by_severity,
        "by_owasp": by_owasp,
        "all_findings": findings,
    }

    FINAL_REPORT_DIR.mkdir(parents=True, exist_ok=True)

    # Markdown
    md_out = render_markdown(context)
    md_path = FINAL_REPORT_DIR / f"{args.target_name}_report.md"
    md_path.write_text(md_out)

    # HTML
    html_out = markdown_to_html(md_out, context["report_title"])
    html_path = FINAL_REPORT_DIR / f"{args.target_name}_report.html"
    html_path.write_text(html_out)

    # JSON
    json_path = FINAL_REPORT_DIR / f"{args.target_name}_findings.json"
    with open(json_path, "w") as f:
        json.dump({
            "target_name": args.target_name,
            "generated_at": context["generated_at"],
            "total_findings": len(findings),
            "counts": counts,
            "findings": findings,
        }, f, indent=2)

    print(f"Aggregated {len(findings)} finding(s) for '{args.target_name}'.")
    print("Severity breakdown:", {k: v for k, v in counts.items() if v})
    print(f"\nWrote:\n  {md_path}\n  {html_path}\n  {json_path}")


if __name__ == "__main__":
    main()
