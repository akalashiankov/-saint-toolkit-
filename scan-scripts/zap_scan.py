#!/usr/bin/env python3
"""
zap_scan.py - SAINT's OWASP ZAP automation module

Scans ONLY targets listed in config/targets.yaml. Active scanning only runs
if the target's profile is listed in zap_config.yaml's
active_scan_allowed_profiles AND the target's profile in targets.yaml is
"full". Everything else gets spider + passive scan only.

Requires a ZAP daemon already running, e.g.:
    zap.sh -daemon -port 8080 -config api.key=$ZAP_API_KEY -config api.disablekey=false

Usage:
    export ZAP_API_KEY=your-zap-api-key
    python3 zap_scan.py --target-name example-lab-app

Output:
    output/zap/<target-name>_zap_report.json
    output/zap/<target-name>_zap_report.html
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

import yaml

try:
    from zapv2 import ZAPv2
except ImportError:
    print("ERROR: python-owasp-zap-v2.4 is not installed. Run: pip install python-owasp-zap-v2.4 --break-system-packages")
    sys.exit(1)

ROOT_DIR = Path(__file__).resolve().parent.parent
TARGETS_FILE = ROOT_DIR / "config" / "targets.yaml"
ZAP_CONFIG_FILE = ROOT_DIR / "config" / "zap_config.yaml"
OUTPUT_DIR = ROOT_DIR / "output" / "zap"


def load_yaml(path):
    with open(path) as f:
        return yaml.safe_load(f)


def get_target(targets_cfg, target_name):
    for t in targets_cfg["targets"]:
        if t["name"] == target_name:
            return t
    return None


def wait_for_spider(zap, scan_id, max_minutes):
    deadline = time.time() + max_minutes * 60
    while int(zap.spider.status(scan_id)) < 100:
        if time.time() > deadline:
            print(f"WARNING: spider exceeded {max_minutes} min budget, moving on.")
            break
        print(f"  Spider progress: {zap.spider.status(scan_id)}%")
        time.sleep(5)


def wait_for_passive_scan(zap, max_minutes):
    deadline = time.time() + max_minutes * 60
    while int(zap.pscan.records_to_scan) > 0:
        if time.time() > deadline:
            print(f"WARNING: passive scan exceeded {max_minutes} min budget, moving on.")
            break
        print(f"  Records left to passively scan: {zap.pscan.records_to_scan}")
        time.sleep(5)


def wait_for_active_scan(zap, scan_id, max_minutes):
    deadline = time.time() + max_minutes * 60
    while int(zap.ascan.status(scan_id)) < 100:
        if time.time() > deadline:
            print(f"WARNING: active scan exceeded {max_minutes} min budget, moving on.")
            break
        print(f"  Active scan progress: {zap.ascan.status(scan_id)}%")
        time.sleep(10)


def normalize_alerts(raw_alerts, target_name):
    """Map ZAP alert dicts onto SAINT's common finding schema."""
    risk_map = {
        "High": "High",
        "Medium": "Medium",
        "Low": "Low",
        "Informational": "Informational",
    }
    findings = []
    for a in raw_alerts:
        findings.append({
            "id": f"zap-{a.get('pluginId', 'unknown')}-{a.get('id', a.get('alertRef', 'na'))}",
            "source": "zap",
            "target_name": target_name,
            "host": a.get("url", ""),
            "title": a.get("alert") or a.get("name", "Unnamed ZAP alert"),
            "description": a.get("description", ""),
            "severity": risk_map.get(a.get("risk", "Informational"), "Informational"),
            "owasp_category": None,   # left for the aggregator's OWASP mapping step
            "evidence": {
                "url": a.get("url"),
                "param": a.get("param"),
                "attack": a.get("attack"),
                "evidence": a.get("evidence"),
                "cweid": a.get("cweid"),
                "wascid": a.get("wascid"),
                "solution": a.get("solution"),
            },
            "confirmed": a.get("confidence") in ("High", "Confirmed"),
            "scanner_raw_ref": "zap_alerts",
        })
    return findings


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target-name", required=True)
    args = parser.parse_args()

    targets_cfg = load_yaml(TARGETS_FILE)
    zap_cfg = load_yaml(ZAP_CONFIG_FILE)["zap"]

    target = get_target(targets_cfg, args.target_name)
    if target is None:
        print(f"ERROR: No target named '{args.target_name}' found in {TARGETS_FILE}.")
        print("Add it there first -- that file is SAINT's authorization record.")
        sys.exit(1)

    base_url = target["base_url"]
    profile = target["profile"]

    api_key = os.environ.get(zap_cfg["api_key_env_var"])
    if not api_key:
        print(f"ERROR: Set the {zap_cfg['api_key_env_var']} environment variable with your ZAP API key.")
        sys.exit(1)

    zap = ZAPv2(apikey=api_key, proxies={
        "http": f"{zap_cfg['api_url']}:{zap_cfg['api_port']}",
        "https": f"{zap_cfg['api_url']}:{zap_cfg['api_port']}",
    })

    print(f"Target:  {args.target_name} ({base_url})")
    print(f"Profile: {profile}")

    print("\n[1/3] Spidering...")
    scan_id = zap.spider.scan(base_url, maxchildren=None)
    wait_for_spider(zap, scan_id, zap_cfg["spider"]["max_duration_minutes"])
    print("Spider complete.")

    print("\n[2/3] Waiting for passive scan to finish...")
    wait_for_passive_scan(zap, zap_cfg["passive_scan"]["max_wait_minutes"])
    print("Passive scan complete.")

    active_allowed_profiles = zap_cfg["active_scan"]["enabled_by_target_profile"]
    if active_allowed_profiles and profile == "full":
        print("\n[3/3] Profile is 'full' -- running active scan (authorized targets only)...")
        ascan_id = zap.ascan.scan(base_url)
        wait_for_active_scan(zap, ascan_id, zap_cfg["active_scan"]["max_duration_minutes"])
        print("Active scan complete.")
    else:
        print("\n[3/3] Skipping active scan (profile is not 'full'). Spider + passive results only.")

    print("\nCollecting alerts...")
    raw_alerts = zap.core.alerts(baseurl=base_url)
    findings = normalize_alerts(raw_alerts, args.target_name)

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    json_out = OUTPUT_DIR / f"{args.target_name}_zap_report.json"
    html_out = OUTPUT_DIR / f"{args.target_name}_zap_report.html"

    output = {
        "source": "zap",
        "target_name": args.target_name,
        "base_url": base_url,
        "profile": profile,
        "finding_count": len(findings),
        "findings": findings,
    }
    with open(json_out, "w") as f:
        json.dump(output, f, indent=2)

    # ZAP can also generate its own HTML report directly from the API
    try:
        html_report = zap.core.htmlreport()
        with open(html_out, "w") as f:
            f.write(html_report)
    except Exception as e:
        print(f"WARNING: could not generate ZAP's built-in HTML report: {e}")

    print(f"\nWrote:\n  {json_out}\n  {html_out}")
    print(f"Total findings: {len(findings)}")


if __name__ == "__main__":
    main()
