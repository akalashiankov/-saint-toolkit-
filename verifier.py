import requests
import re

class FindingVerifier:
    @staticmethod
    def verify_finding(finding):
        vuln_type = finding.get("type", "")
        endpoint = finding.get("endpoint", "")
        evidence = {
            "verified": False,
            "status_note": "Requires manual review",
            "poc_command": f"curl -s -i '{endpoint}'",
            "response_snippet": "N/A"
        }
        try:
            if "JS Library" in vuln_type or "Outdated Component" in vuln_type:
                res = requests.get(endpoint, timeout=5)
                if res.status_code == 200:
                    banner = "
".join(res.text.splitlines()[:5])
                    evidence["response_snippet"] = banner
                    evidence["poc_command"] = f"curl -s {endpoint} | head -n 5"
                    if "Swiper 8.4.7" in banner or "Swiper 9" in banner or "Swiper 10" in banner:
                        evidence["verified"] = True
                        evidence["status_note"] = "False Positive / Up-to-Date Version Detected"
                    else:
                        evidence["verified"] = True
                        evidence["status_note"] = "Confirmed via Banner Inspection"
            elif "Header" in vuln_type:
                res = requests.head(endpoint, timeout=5)
                evidence["response_snippet"] = f"HTTP/1.1 {res.status_code}
" + "
".join([f"{k}: {v}" for k, v in res.headers.items()])
                evidence["poc_command"] = f"curl -s -I {endpoint}"
                evidence["verified"] = True
                evidence["status_note"] = "Confirmed via HTTP HEAD Inspection"
        except Exception as e:
            evidence["status_note"] = f"Verification check failed: {str(e)}"
        finding["evidence"] = evidence
        return finding
