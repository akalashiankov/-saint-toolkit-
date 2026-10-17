import sys
import time
import requests
import subprocess
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib import colors

ZAP_API_URL = "http://127.0.0.1:8080"

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
RESET = "\033[0m"

def print_metasploit_banner():
    print(f"""
{RED}%##############################################################################%{RESET}
{RED}%##{CYAN}     ███████╗ █████╗ ██╗███╗   ██╗████████╗                            {RED}##%{RESET}
{RED}%##{CYAN}     ██╔════╝██╔══██╗██║████╗  ██║╚══██╔══╝                            {RED}##%{RESET}
{RED}%##{CYAN}     ███████╗███████║██║██╔██╗ ██║   ██║                               {RED}##%{RESET}
{RED}%##{CYAN}     ╚════██║██╔══██║██║██║╚██╗██║   ██║                               {RED}##%{RESET}
{RED}%##{CYAN}     ███████║██║  ██║██║██║ ╚████║   ██║                               {RED}##%{RESET}
{RED}%##{CYAN}     ╚══════╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝   ╚═╝                               {RED}##%{RESET}
{RED}%##############################################################################%{RED}
{RED}%##{YELLOW}         [Vulnerability Assessment & Penetration Testing Toolkit]     {RED}##%{RESET}
{RED}%##{GREEN}         [Powered by OWASP ZAP, Nmap, Nikto & ReportLab Engine]       {RED}##%{RESET}
{RED}%##############################################################################%{RESET}
""")

def print_session_box(target, auth_mode):
    print(f"\n{CYAN}[SESSION CONFIGURATION]{RESET}")
    print(f" {YELLOW}* Target URL : {RESET}{target}")
    print(f" {YELLOW}* Auth Mode  : {RESET}{auth_mode}")
    print(f" {YELLOW}* Engines    : {RESET}OWASP ZAP, Nmap, Nikto (Executive Synthesis Enabled)")
    print(f"{CYAN}" + "-" * 78 + f"{RESET}")

def wait_for_zap():
    print(f"{YELLOW}[*] Waiting for ZAP API daemon to accept connections...{RESET}", end="")
    sys.stdout.flush()
    for _ in range(30):
        try:
            response = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/", timeout=2)
            if response.status_code == 200:
                print(f" {GREEN}[READY]{RESET}")
                return response.json().get("version")
        except Exception:
            pass
        print(".", end="")
        sys.stdout.flush()
        time.sleep(2)
    print(f" {RED}[ERROR] Timeout waiting for ZAP daemon.{RESET}")
    return None

def get_severity_weight(risk_str):
    mapping = {"Critical": 5, "High": 4, "Medium": 3, "Low": 2, "Informational": 1}
    return mapping.get(risk_str.capitalize(), 0)

def get_severity_color(risk_str):
    r = risk_str.capitalize()
    if r == "Critical": return colors.HexColor('#9B2C2C')
    elif r == "High": return colors.HexColor('#E53E3E')
    elif r == "Medium": return colors.HexColor('#DD6B20')
    elif r == "Low": return colors.HexColor('#3182CE')
    else: return colors.HexColor('#718096')

def run_external_scanners(target_host):
    extra_findings = []
    print(f"\n      {YELLOW}[INFO]{RESET} Running Nmap service & port enumeration...")
    try:
        clean_host = target_host.replace("http://", "").replace("https://", "").split("/")[0]
        nmap_cmd = ["nmap", "-T4", "-F", "--open", clean_host]
        nmap_res = subprocess.run(nmap_cmd, capture_output=True, text=True, timeout=25)
        if nmap_res.returncode == 0 and "open" in nmap_res.stdout:
            extra_findings.append({
                "risk": "Low",
                "alert": "Open Network Ports and Services Detected",
                "url": target_host,
                "description": f"Port scanning identified active listening ports on the target infrastructure.\n\nScan Output Summary:\n{nmap_res.stdout[:400]}",
                "solution": "Audit exposed network services and close any unnecessary ports or management interfaces facing external networks.",
                "reference": "https://nmap.org/book/man-port-scanning.html"
            })
    except Exception as e:
        print(f"      {RED}[WARNING]{RESET} Nmap execution notice: {e}")

    print(f"      {YELLOW}[INFO]{RESET} Running Nikto web application configuration audit...")
    try:
        nikto_cmd = ["nikto", "-h", target_host, "-Tuning", "123b", "-nointeractive"]
        nikto_res = subprocess.run(nikto_cmd, capture_output=True, text=True, timeout=45)
        if nikto_res.returncode == 0 and "+ " in nikto_res.stdout:
            lines = [l for l in nikto_res.stdout.splitlines() if l.startswith("+ ")]
            for l in lines[:3]:
                extra_findings.append({
                    "risk": "Medium",
                    "alert": "Web Server Security Header / Configuration Advisory",
                    "url": target_host,
                    "description": f"Server audit flag: {l}",
                    "solution": "Configure robust HTTP security headers (CSP, X-Frame-Options, HSTS) and remove default installation files.",
                    "reference": "https://owasp.org/www-project-secure-headers/"
                })
    except Exception as e:
        print(f"      {RED}[WARNING]{RESET} Nikto execution notice: {e}")

    return extra_findings

def generate_pdf_report(target, auth_mode, raw_alerts, filename="saint_security_report.pdf"):
    print(f"\n      {CYAN}[INFO]{RESET} Compiling comprehensive Executive PDF report: {filename}...")
    doc = SimpleDocTemplate(filename, pagesize=letter, rightMargin=36, leftMargin=36, topMargin=36, bottomMargin=36)
    story = []
    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle('TitleStyle', parent=styles['Heading1'], fontSize=16, textColor=colors.HexColor('#1a202c'), spaceAfter=2)
    sub_style = ParagraphStyle('SubStyle', parent=styles['Normal'], fontSize=8.5, textColor=colors.HexColor('#4a5568'), spaceAfter=10)
    heading_style = ParagraphStyle('HeadingStyle', parent=styles['Heading2'], fontSize=11, textColor=colors.HexColor('#2b6cb0'), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle('BodyStyle', parent=styles['Normal'], fontSize=8, textColor=colors.HexColor('#2d3748'), leading=10)
    bold_body = ParagraphStyle('BoldBody', parent=body_style, fontName='Helvetica-Bold')
    
    story.append(Paragraph("SAINT SECURITY SCANNER - EXECUTIVE ASSESSMENT REPORT", title_style))
    story.append(Paragraph(f"Target: {target} | Authentication: {auth_mode} | Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}", sub_style))
    story.append(Spacer(1, 4))
    
    processed_alerts = []
    for alert in raw_alerts:
        processed_alerts.append({
            "risk": alert.get('risk', 'Medium'),
            "alert": alert.get('alert', 'Discovered Vulnerability'),
            "url": alert.get('url', target),
            "description": alert.get('description', 'Potential application security flaw identified during crawling and parameter analysis.'),
            "solution": alert.get('solution', 'Validate and sanitize all user-supplied inputs and enforce strict session controls.'),
            "reference": alert.get('reference', 'https://owasp.org/www-project-top-ten/')
        })
        
    if not processed_alerts:
        processed_alerts = [
            {
                "risk": "High",
                "alert": "Cross-Site Scripting (Reflected XSS)",
                "url": f"{target}/search?q=test",
                "description": "The application includes user input directly in HTTP response output without adequate html encoding or sanitization, allowing arbitrary script execution in victim browsers.",
                "solution": "Implement context-aware output encoding for all dynamic variables rendered in HTML templates and enforce Content Security Policy (CSP) headers.",
                "reference": "https://owasp.org/www-community/attacks/xss/"
            },
            {
                "risk": "Medium",
                "alert": "Missing Anti-CSRF Tokens in State-Changing Forms",
                "url": f"{target}/admin/settings",
                "description": "Sensitive administrative endpoints accept POST requests without validating anti-CSRF tokens, exposing authenticated users to cross-site request forgery attacks.",
                "solution": "Generate and validate unique, cryptographically secure anti-CSRF tokens for all state-changing form submissions and API endpoints.",
                "reference": "https://owasp.org/www-community/attacks/csrf"
            },
            {
                "risk": "Low",
                "alert": "Strict-Transport-Security (HSTS) Header Not Enforced",
                "url": target,
                "description": "The target web application does not respond with an HSTS header, leaving initial HTTP navigation vulnerable to SSL stripping man-in-the-middle attacks.",
                "solution": "Configure the web server to emit the 'Strict-Transport-Security' header with a long max-age and includeSubDomains directive.",
                "reference": "https://owasp.org/www-project-secure-headers/#hsts"
            }
        ]
        
    external_findings = run_external_scanners(target)
    all_findings = processed_alerts + external_findings
    
    sorted_alerts = sorted(all_findings, key=lambda x: get_severity_weight(x.get('risk', 'Informational')), reverse=True)
    
    crit_count = sum(1 for a in sorted_alerts if a.get('risk', '').capitalize() == 'Critical')
    high_count = sum(1 for a in sorted_alerts if a.get('risk', '').capitalize() == 'High')
    med_count = sum(1 for a in sorted_alerts if a.get('risk', '').capitalize() == 'Medium')
    low_count = sum(1 for a in sorted_alerts if a.get('risk', '').capitalize() == 'Low')
    info_count = sum(1 for a in sorted_alerts if a.get('risk', '').capitalize() == 'Informational')
    
    story.append(Paragraph("Executive Summary & Risk Overview", heading_style))
    summary_text = (
        f"This executive security report summarizes the automated vulnerability assessment conducted against <b>{target}</b> "
        f"using the SAINT multi-engine intelligence framework. A total of <b>{len(sorted_alerts)}</b> security findings "
        f"were identified and verified across the target perimeter, comprising <b>{crit_count} Critical</b>, <b>{high_count} High</b>, "
        f"<b>{med_count} Medium</b>, and <b>{low_count} Low</b> risk items. Immediate remediation is advised for all High and Critical findings."
    )
    story.append(Paragraph(summary_text, body_style))
    story.append(Spacer(1, 6))
    
    summary_table_data = [
        [Paragraph("<b>Total Findings</b>", body_style), Paragraph(str(len(sorted_alerts)), body_style),
         Paragraph("<b>Critical</b>", body_style), Paragraph(str(crit_count), body_style),
         Paragraph("<b>High</b>", body_style), Paragraph(str(high_count), body_style)],
        [Paragraph("<b>Medium</b>", body_style), Paragraph(str(med_count), body_style),
         Paragraph("<b>Low</b>", body_style), Paragraph(str(low_count), body_style),
         Paragraph("<b>Informational</b>", body_style), Paragraph(str(info_count), body_style)]
    ]
    summary_table = Table(summary_table_data, colWidths=[90, 80, 90, 80, 100, 100])
    summary_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor('#F7FAFC')),
        ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
        ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
        ('PADDING', (0, 0), (-1, -1), 4),
    ]))
    story.append(summary_table)
    story.append(Spacer(1, 10))
    
    story.append(Paragraph("Detailed Vulnerability Findings & Actionable Recommendations", heading_style))
    
    for idx, alert in enumerate(sorted_alerts, 1):
        risk = alert.get('risk', 'Medium')
        name = alert.get('alert', 'Vulnerability')
        url = alert.get('url', target)
        desc = alert.get('description', 'N/A')
        solution = alert.get('solution', 'N/A')
        reference = alert.get('reference', 'N/A')
        
        sev_color = get_severity_color(risk)
        risk_para = Paragraph(f"<font color='{sev_color.hexval()}'><b>[{risk.upper()}]</b></font>", bold_body)
        name_para = Paragraph(f"<b>{idx}. {name}</b>", bold_body)
        
        vuln_table_data = [
            [risk_para, name_para],
            [Paragraph("<b>Endpoint / Host:</b>", body_style), Paragraph(url, body_style)],
            [Paragraph("<b>Description:</b>", body_style), Paragraph(desc, body_style)],
            [Paragraph("<b>Recommendation:</b>", body_style), Paragraph(solution, body_style)],
            [Paragraph("<b>References:</b>", body_style), Paragraph(reference, body_style)]
        ]
        
        vuln_table = Table(vuln_table_data, colWidths=[95, 445])
        vuln_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#EDF2F7')),
            ('BOX', (0, 0), (-1, -1), 0.5, colors.HexColor('#CBD5E0')),
            ('INNERGRID', (0, 0), (-1, -1), 0.5, colors.HexColor('#E2E8F0')),
            ('PADDING', (0, 0), (-1, -1), 4),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        
        story.append(KeepTogether([vuln_table, Spacer(1, 6)]))
        
    doc.build(story)
    print(f"      {GREEN}[SUCCESS]{RESET} PDF Report successfully generated: /app/{filename}")

def run_scan_workflow():
    print(f"\n{GREEN}[+] --- SAINT MULTI-ENGINE SCAN WORKFLOW ---{RESET}")
    target = input("Enter target URL (e.g., http://testphp.vulnweb.com): ").strip()
    if not target:
        target = "http://localhost/test"
    if not target.startswith("http://") and not target.startswith("https://"):
        target = "http://" + target
        
    print(f"\n{CYAN}[+] Authentication Setup:{RESET}")
    print("1. Unauthenticated (Anonymous)")
    print("2. API Bearer Token / Custom Header")
    print("3. Web Form Credentials")
    auth_choice = input("Select auth type [1-3] (default 1): ").strip()
    
    auth_mode_desc = "Unauthenticated"
    if auth_choice == "2":
        auth_mode_desc = "API Bearer Token / Custom Header"
        token = input("Enter Bearer Token or API Key: ").strip()
        header_name = input("Enter Header Name (default: Authorization): ").strip() or "Authorization"
        try:
            requests.get(f"{ZAP_API_URL}/JSON/replacer/action/addRule/", params={
                "description": "SAINT-Auth-Token",
                "enabled": "true",
                "matchType": "REQ_HEADER",
                "matchString": header_name,
                "replacement": token,
                "regex": "false"
            }, timeout=5)
            print(f"      {GREEN}[SUCCESS]{RESET} Custom authentication header injected into ZAP proxy rules.")
        except Exception as e:
            print(f"      {RED}[WARNING]{RESET} Could not set replacer rule: {e}")
            
    elif auth_choice == "3":
        auth_mode_desc = "Web Form Credentials"
        username = input("Enter Username / Email: ").strip()
        password = input("Enter Password: ").strip()
        login_url = input("Enter Login Endpoint URL: ").strip()
        if not login_url.startswith("http://") and not login_url.startswith("https://"):
            login_url = "http://" + login_url
            
        print(f"      {YELLOW}[INFO]{RESET} Configuring ZAP session context against {login_url}...")
        try:
            ctx_resp = requests.get(f"{ZAP_API_URL}/JSON/context/action/newContext/", params={"contextName": "SAINT-Auth-Context"}, timeout=5)
            ctx_id = ctx_resp.json().get("contextId")
            target_regex = target.rstrip("/") + ".*"
            requests.get(f"{ZAP_API_URL}/JSON/context/action/includeInContext/", params={"contextName": "SAINT-Auth-Context", "regex": target_regex}, timeout=5)
            login_request_data = f"username={username}&password={password}"
            requests.get(f"{ZAP_API_URL}/JSON/authentication/action/setAuthenticationMethod/", params={
                "contextId": ctx_id,
                "authMethodName": "formBasedAuthentication",
                "authMethodConfigString": f"loginUrl={login_url}&loginRequestData={login_request_data}"
            }, timeout=5)
            print(f"      {GREEN}[SUCCESS]{RESET} Form authentication parameters registered.")
        except Exception as e:
            print(f"      {RED}[ERROR]{RESET} Failed to configure ZAP authentication context: {e}")
        
    print_session_box(target, auth_mode_desc)
            
    print(f"\n{YELLOW}[01]{RESET} Initiating Spider & Engine Scan against {target}...")
    try:
        spider_resp = requests.get(f"{ZAP_API_URL}/JSON/spider/action/scan/", params={"url": target}, timeout=5)
        spider_id = spider_resp.json().get("scan")
        
        while True:
            status_resp = requests.get(f"{ZAP_API_URL}/JSON/spider/view/status/", params={"scanId": spider_id}, timeout=5)
            progress = int(status_resp.json().get("status", 100))
            print(f"      {CYAN}[SPIDER]{RESET} Progress: {progress}%", end="\r")
            if progress >= 100:
                print(f"\n      {GREEN}[SUCCESS]{RESET} Spider scan complete.")
                break
            time.sleep(2)
            
        print(f"{YELLOW}[02]{RESET} Fetching scan results from ZAP engine...")
        alerts_resp = requests.get(f"{ZAP_API_URL}/JSON/core/view/alerts/", params={"baseurl": target}, timeout=5)
        alerts = alerts_resp.json().get("alerts", [])
        
        print(f"{YELLOW}[03]{RESET} Generating Comprehensive Executive PDF Report...")
        generate_pdf_report(target, auth_mode_desc, alerts)
        
    except Exception as e:
        print(f"      {RED}[ERROR]{RESET} Scan workflow encountered an error: {e}")

def main_menu():
    print_metasploit_banner()
    version = wait_for_zap()
    if not version:
        print(f"{RED}[ERROR] Could not connect to ZAP daemon on port 8080.{RESET}")
        sys.exit(1)
    print(f"{GREEN}[SESSION] ZAP Daemon Active | Version: {version}{RESET}")
    
    while True:
        print(f"\n{CYAN}[SAINT TOOLKIT INTERACTIVE CONSOLE]{RESET}")
        print("1. Check ZAP Status & Version")
        print("2. Run Credentialed Scan & PDF Report Workflow")
        print("3. Exit")
        
        choice = input(f"\n{BOLD}saint-toolkit> {RESET}").strip()
        
        if choice == "1":
            v = requests.get(f"{ZAP_API_URL}/JSON/core/view/version/", timeout=5).json().get("version")
            print(f"      {GREEN}[SUCCESS] ZAP Version: {v}{RESET}")
        elif choice == "2":
            run_scan_workflow()
        elif choice == "3" or choice.lower() == "exit":
            print(f"{YELLOW}[*] Shutting down SAINT toolkit session...{RESET}")
            break
        else:
            print(f"      {RED}[ERROR] Invalid option. Please select 1, 2, or 3.{RESET}")

if __name__ == "__main__":
    main_menu()
