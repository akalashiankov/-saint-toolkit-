# SAINT

**S**ecurity **A**ssessment & **I**ntegrated **N**etwork **T**oolkit

SAINT is a pipeline that runs Nmap and OWASP ZAP against an explicitly
authorized target, imports manually-exported Burp Suite findings, folds in
manually-verified proof-of-concept results, and produces a single
deduplicated, severity-ranked, OWASP-Top-10-mapped report in Markdown, HTML,
and JSON.

```
targets.yaml (authorization record)
        │
        ▼
   scan.sh (orchestrator)
        │
   ┌────┼────────────┐
   ▼                 ▼
 Nmap              ZAP
(recon)        (web vuln scan)
   │                 │
   └────────┬────────┘
            ▼
   [manual] Burp import
   [manual] PoC confirmation
            │
            ▼
      aggregator.py
            │
            ▼
   output/final_report/
     report.md / report.html / findings.json
```

## Design principle: authorized targets only

SAINT will not scan an arbitrary hostname. Every target must be added to
`config/targets.yaml` first, with a `profile` (`light` or `full`) and an
`authorization_ref`. That file *is* the authorization record. A `full`
profile scan (which enables ZAP active scanning) is refused outright if
`authorization_ref` is left as a placeholder.

Exploitation (e.g. via Metasploit) is intentionally **not automated**.
Proof-of-concept validation is a manual, human-in-the-loop step you run
yourself in an isolated lab; results get recorded in
`output/manual_poc/<target>_manual_poc.json` (copy
`manual_poc_template.json` to start) and are picked up automatically by the
aggregator. This keeps the pipeline squarely in "scanning and reporting"
territory while still telling the full assessment story: recon → automated
scan → manual confirmation → report.

## Setup

```bash
# System tools
sudo apt install nmap

# ZAP: install separately (https://www.zaproxy.org/download/) and run as a daemon:
zap.sh -daemon -port 8080 -config api.key=$ZAP_API_KEY -config api.disablekey=false

# Python deps
pip install -r requirements.txt --break-system-packages

# yq (used by nmap_scan.sh / scan.sh to read targets.yaml)
sudo snap install yq      # or see https://github.com/mikefarah/yq#install
```

## Configure a target

Edit `config/targets.yaml`:

```yaml
targets:
  - name: my-lab-app
    host: 10.10.10.5
    base_url: https://10.10.10.5
    profile: light          # or "full" once you've filled in authorization_ref
    authorized_by: "Jane Doe, lab owner"
    authorization_ref: "HTB lab assignment #3"
```

## Run

```bash
export ZAP_API_KEY=your-zap-api-key

# Full pipeline: nmap -> zap -> aggregate
./scan.sh --target-name my-lab-app

# Just aggregate (e.g. after manually running Burp or filling in a PoC file)
python3 parse_and_aggregate/aggregator.py --target-name my-lab-app
```

### Optional: import Burp findings

```bash
./scan-scripts/burp_export.sh --target-name my-lab-app --input ~/Downloads/burp_issues.xml
```

### Optional: record a manually-confirmed PoC

```bash
cp output/manual_poc/manual_poc_template.json output/manual_poc/my-lab-app_manual_poc.json
# edit it by hand with what you tested, how, and the result
```

Then re-run the aggregator (or `scan.sh` again) to fold it into the report.

## Output

```
output/
├── nmap/<target>_scan.xml, <target>_scan.json
├── zap/<target>_zap_report.json, <target>_zap_report.html
├── burp/<target>_burp_raw.xml, <target>_burp_findings.json
├── manual_poc/<target>_manual_poc.json
└── final_report/
    ├── <target>_report.md
    ├── <target>_report.html
    └── <target>_findings.json
```

## Project structure

```
webapp-scan-automation/
├── README.md
├── scan.sh                      # master launcher
├── requirements.txt
├── scan-scripts/
│   ├── nmap_scan.sh
│   ├── zap_scan.py
│   └── burp_export.sh           # importer, not a live Burp driver
├── parse_and_aggregate/
│   ├── aggregator.py
│   ├── normalize_nmap.py
│   ├── normalize_burp.py
│   ├── findings_schema.md
│   └── templates/
│       └── report_template.md
├── output/
│   ├── nmap/ zap/ burp/ manual_poc/ final_report/
├── config/
│   ├── targets.yaml              # the authorization record
│   ├── zap_config.yaml
│   └── report_config.yaml
└── .gitignore
```

## Status / roadmap

- [x] Nmap scan + XML→JSON normalization
- [x] ZAP spider / passive / gated active scan + normalization
- [x] Burp export import + normalization
- [x] Manual PoC findings template
- [x] Aggregator: dedupe, severity grouping, OWASP Top 10 mapping, Markdown/HTML/JSON report
- [ ] CI integration (deliberately not wired to run active scans automatically — see Design principle above)
- [ ] Additional normalizers (e.g. Nikto, testssl.sh, trivy)
- [ ] Richer OWASP category classifier (current version is keyword-based)
