#!/usr/bin/env python3
"""
normalize_burp.py

Converts a Burp Suite "issues" XML export into SAINT's common finding
schema. This only parses a file you exported yourself from Burp -- it does
not drive Burp or launch any scan.

Burp's standard issue export XML looks roughly like:

<issues>
  <issue>
    <serialNumber>...</serialNumber>
    <type>...</type>
    <name>SQL injection</name>
    <host ip="1.2.3.4">https://example.com</host>
    <path>/search</path>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueBackground>...</issueBackground>
    <remediationBackground>...</remediationBackground>
    ...
  </issue>
  ...
</issues>

Field names can vary slightly by Burp version; this parser reads the common
ones defensively and leaves anything it can't find blank rather than
crashing.
"""

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def text_or_none(el, tag):
    child = el.find(tag)
    return child.text.strip() if child is not None and child.text else None


def parse_burp_xml(xml_path, target_name):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings = []

    for idx, issue in enumerate(root.findall("issue")):
        name = text_or_none(issue, "name") or "Unnamed Burp finding"
        severity = text_or_none(issue, "severity") or "Informational"
        confidence = text_or_none(issue, "confidence") or "Unknown"
        host_el = issue.find("host")
        host = host_el.text.strip() if host_el is not None and host_el.text else "unknown"
        path = text_or_none(issue, "path") or ""
        background = text_or_none(issue, "issueBackground") or text_or_none(issue, "description") or ""
        remediation = text_or_none(issue, "remediationBackground") or ""

        findings.append({
            "id": f"burp-{idx}-{host}-{path}".replace(" ", "_"),
            "source": "burp",
            "target_name": target_name,
            "host": f"{host}{path}",
            "title": name,
            "description": background,
            "severity": severity if severity in ("Critical", "High", "Medium", "Low", "Informational") else "Informational",
            "owasp_category": None,
            "evidence": {
                "confidence": confidence,
                "remediation": remediation,
                "path": path,
            },
            "confirmed": confidence.lower() in ("certain", "firm", "high"),
            "scanner_raw_ref": xml_path,
        })

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", required=True, help="Path to Burp issues XML export")
    parser.add_argument("--target-name", required=True)
    parser.add_argument("--out", required=True)
    args = parser.parse_args()

    findings = parse_burp_xml(args.xml, args.target_name)

    output = {
        "source": "burp",
        "target_name": args.target_name,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "finding_count": len(findings),
        "findings": findings,
    }

    with open(args.out, "w") as f:
        json.dump(output, f, indent=2)

    print(f"Normalized {len(findings)} finding(s) from {args.xml} -> {args.out}")


if __name__ == "__main__":
    main()
