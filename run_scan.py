import argparse
import sys
import yaml
import time
import socket
from zapv2 import ZAPv2
from report_generator import generate_pdf_report

def load_target(target_name, config_path="config/targets.yaml"):
    try:
        with open(config_path, 'r') as f:
            config = yaml.safe_load(f)
        for target in config.get('targets', []):
            if target.get('name') == target_name:
                return target
    except Exception as e:
        print(f"[-] Error loading target configuration: {e}")
    return None

def wait_for_zap(host='127.0.0.1', port=8080, timeout=60):
    print(f"[*] Waiting for ZAP API to become available on {host}:{port}...")
    start_time = time.time()
    while time.time() - start_time < timeout:
        try:
            with socket.create_connection((host, port), timeout=2):
                print("[+] ZAP API is up and responding!")
                return True
        except (socket.timeout, ConnectionRefusedError):
            time.sleep(2)
    print("[-] Timeout waiting for ZAP API daemon.")
    return False

def main():
    parser = argparse.ArgumentParser(description="SAINT Security Assessment Toolkit")
    parser.add_argument("--target-name", required=True, help="Name of the target defined in targets.yaml")
    args = parser.parse_args()

    target = load_target(args.target_name)
    if not target:
        raise ValueError(f"Target '{args.target_name}' not found in configuration.")

    print(f"[*] Initializing assessment for target: {target['name']} ({target['base_url']}) [Type: {target.get('type', 'webapp').upper()}]")
    
    if not wait_for_zap():
        sys.exit(1)

    zap = ZAPv2(proxies={'http': 'http://127.0.0.1:8080', 'https': 'http://127.0.0.1:8080'})
    
    target_type = target.get('type', 'webapp')
    openapi_spec = target.get('openapi_spec', '')

    if target_type == 'api' and openapi_spec:
        print(f"[*] Importing OpenAPI/Swagger specification from: {openapi_spec}")
        try:
            zap.openapi.import_url(openapi_spec)
            time.sleep(3)
        except Exception as e:
            print(f"[-] Warning: Failed to import OpenAPI spec directly via URL ({e}). Falling back to standard URL load.")
            zap.urlopen(target['base_url'])
    else:
        print("[*] Accessing target URL via ZAP...")
        try:
            zap.urlopen(target['base_url'])
        except Exception as e:
            print(f"[-] Warning during urlopen: {e}")
    
    time.sleep(3)

    print("[*] Retrieving security alerts and generating professional PDF report...")
    try:
        alerts = zap.core.alerts()
    except Exception:
        alerts = []

    generate_pdf_report(
        target_name=target['name'],
        target_url=target['base_url'],
        auth_ref=target.get('authorization_ref', 'N/A'),
        authorized_by=target.get('authorized_by', 'N/A'),
        alerts=alerts
    )
    print("[*] Scan pipeline completed successfully. Report saved to reports/")

if __name__ == "__main__":
    main()
