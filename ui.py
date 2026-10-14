import sys
import time

def print_banner():
    print(r"""
   ___ _  __ ____  _          _               _ _    _ _   
  / _ \ |/ // ___|| |__   ___| | _____  _ __ (_) | _(_) |_ 
 | | | ' /'| |    | '_ \ / _ \ |/ / _ \ '_ \| | |/ / | __|
 | |_| . \| |___ | | | |  __/   < (_) | | | | |   <| | |_ 
  \___/_|\_\\____||_| |_|\___|_|\_\___/|_| |_|_|_|\_\_|\__|
""")

def print_session_box(target, mode, req_sec):
    print(f"[SESSION] Target: {target} | Mode: {mode} | Rate: {req_sec}")

def run_step(step_num, title, func):
    print(f" 0{step_num} [RUNNING] {title}...")
    try:
        res = func()
        print(f"      [SUCCESS] Done.")
        return res
    except Exception as e:
        print(f"      [ERROR] {e}")
        raise

def print_finding(risk, alert, cweid, endpoint, evidence, param):
    print(f"  [{risk}] {alert} ({cweid}) -> {endpoint} | Param: {param} | Evidence: {evidence}")
