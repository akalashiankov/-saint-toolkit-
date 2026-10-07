#!/usr/bin/env python3
"""
normalize_nmap.py

Converts raw Nmap XML output into SAINT's common finding schema (see
parse_and_aggregate/findings_schema.md) so the aggregator can merge it with
ZAP, Burp, and manual-PoC results.

Nmap results are informational by nature (open ports/services), not
vulnerabilities on their own -- they're recorded as "Informational" severity
findings describing exposed services, which the aggregator / report can
later cross-reference against ZAP and manual findings.
"""

import argparse
import json
import xml.etree.ElementTree as ET
from datetime import datetime, timezone


def parse_nmap_xml(xml_path, target_name):
    tree = ET.parse(xml_path)
    root = tree.getroot()

    findings = []

    for host in root.findall("host"):
        address_el = host.find("address")
        ip = address_el.get("addr") if address_el is not None else "unknown"

        hostnames = [h.get("name") for h in host.findall("hostnames/hostname")]

        ports_el = host.find("ports")
        if ports_el is None:
            continue

        for port in ports_el.findall("port"):
            state_el = port.find("state")
            state = state_el.get("state") if state_el is not None else "unknown"

            if state != "open":
                continue

            port_id = port.get("portid")
            protocol = port.get("protocol")

            service_el = port.find("service")
            service_name = service_el.get("name") if service_el is not None else "unknown"
            product = service_el.get("product") if service_el is not None else None
            version = service_el.get("version") if service_el is not None else None

            service_desc = service_name
            if product:
                service_desc += f" ({product}{' ' + version if version else ''})"

            findings.append({
                "id": f"nmap-{ip}-{protocol}-{port_id}",
                "source": "nmap",
                "target_name": target_name,
                "host": ip,
                "hostnames": hostnames,
                "title": f"Open port: {port_id}/{protocol} - {service_desc}",
                "description": (
                    f"Nmap identified an open {protocol} port ({port_id}) running "
                    f"{service_desc} on {ip}."
                ),
                "severity": "Informational",
                "owasp_category": None,
                "evidence": {
                    "port": port_id,
                    "protocol": protocol,
                    "service": service_name,
                    "product": product,
                    "version": version,
                },
                "confirmed": True,
                "scanner_raw_ref": xml_path,
            })

    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--xml", required=True, help="Path to nmap XML output")
    parser.add_argument("--target-name", required=True, help="Target name from targets.yaml")
    parser.add_argument("--out", required=True, help="Path to write normalized JSON")
    args = parser.parse_args()

    findings = parse_nmap_xml(args.xml, args.target_name)

    output = {
        "source": "nmap",
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
