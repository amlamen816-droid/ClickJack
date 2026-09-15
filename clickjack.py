 #!/usr/bin/env python3
"""ClickJack - Clickjacking PoC Generator | Student: Amal Al-Ghafari"""
import argparse, configparser, html, json, logging, re, ssl, sys
import urllib.error, urllib.request
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

VERSION = "1.0.0"

class ClickJackError(Exception):
    pass

def validate_url(value):
    if not value or not value.strip():
        raise ClickJackError("Invalid input: URL is required.")
    value = value.strip()
    if "://" not in value: value = "https://" + value
    p = urlsplit(value)
    if p.scheme.lower() not in ("http", "https") or not p.hostname:
        raise ClickJackError("Invalid URL: HTTP/HTTPS hostname is required.")
    if p.username or p.password:
        raise ClickJackError("Invalid URL: embedded credentials are not allowed.")
    return urlunsplit((p.scheme.lower(), p.netloc, p.path or "/", p.query, ""))

def load_config(path):
    s = {"timeout":10, "user_agent":"ClickJack/1.0 (Academic Security Tool)",
         "verify_tls":True, "output":"clickjack_report.json"}
    if not path: return s
    p = Path(path)
    if not p.exists(): raise ClickJackError(f"Configuration file not found: {p}")
    c = configparser.ConfigParser()
    try:
        c.read(p, encoding="utf-8")
        sec = c["clickjack"] if "clickjack" in c else {}
        if "timeout" in sec:
            s["timeout"] = float(sec["timeout"])
            if s["timeout"] <= 0: raise ValueError("timeout must be greater than zero")
        if "user_agent" in sec: s["user_agent"] = sec["user_agent"]
        if "verify_tls" in sec: s["verify_tls"] = sec["verify_tls"].lower() in ("1","true","yes","on")
        if "output" in sec: s["output"] = sec["output"]
    except (ValueError, configparser.Error) as e:
        raise ClickJackError(f"Invalid configuration file: {e}")
    return s

def scan_target(url, settings):
    req = urllib.request.Request(url, headers={
        "User-Agent": settings["user_agent"],
        "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"}, method="GET")
    ctx = ssl.create_default_context() if settings["verify_tls"] else ssl._create_unverified_context()
    try:
        with urllib.request.urlopen(req, timeout=settings["timeout"], context=ctx) as r:
            return {"target":url, "final_url":r.geturl(), "status_code":r.status,
                    "headers":{k.lower():v for k,v in r.headers.items()}}
    except urllib.error.HTTPError as e:
        return {"target":url, "final_url":e.geturl(), "status_code":e.code,
                "headers":{k.lower():v for k,v in e.headers.items()}}
    except urllib.error.URLError as e: raise ClickJackError(f"Connection failed: {e.reason}")
    except TimeoutError: raise ClickJackError("Connection timed out.")
    except ssl.SSLError as e: raise ClickJackError(f"TLS/SSL error: {e}")
    except OSError as e: raise ClickJackError(f"Network or system error: {e}")

def frame_ancestors(csp):
    m = re.search(r"(?:^|;)\s*frame-ancestors\s+([^;]+)", csp, re.I)
    return m.group(1).strip() if m else ""

def analyze_headers(headers):
    xfo = headers.get("x-frame-options","").strip()
    csp = headers.get("content-security-policy","").strip()
    fa = frame_ancestors(csp)
    xu, au = xfo.upper(), fa.upper()
    base = {"x_frame_options":xfo or "(missing)",
            "content_security_policy":csp or "(missing)",
            "frame_ancestors":fa or "(missing)"}
    if xu == "DENY" or "'NONE'" in au:
        return {**base,"status":"PROTECTED","risk":"LOW","score":100,
                "reason":"Explicit anti-framing protection was detected.",
                "recommendation":"Keep the current anti-framing policy and include it in security regression testing."}
    if xu == "SAMEORIGIN" or "'SELF'" in au:
        return {**base,"status":"PROTECTED","risk":"LOW","score":90,
"reason":"The response restricts framing to an allowed origin policy.",
                "recommendation":"Keep the policy and verify that the allowed origin is intentional."}
    if xfo or fa:
        return {**base,"status":"PARTIALLY PROTECTED","risk":"LOW/MEDIUM","score":75,
                "reason":"A framing-related security control was detected, but its policy requires contextual review.",
                "recommendation":"Review X-Frame-Options and CSP frame-ancestors for consistency."}
    return {**base,"status":"POTENTIALLY VULNERABLE","risk":"MEDIUM/HIGH","score":20,
            "reason":"No effective anti-framing protection was detected in the response headers.",
            "recommendation":"Consider an appropriate CSP frame-ancestors policy and/or X-Frame-Options."}

def print_result(scan, a):
    print("="*55); print("             CLICKJACK SECURITY TOOL"); print("="*55)
    print(f"Target: {scan['target']}"); print(f"Final URL: {scan['final_url']}")
    print(f"HTTP Status: {scan['status_code']}"); print("-"*55)
    print(f"X-Frame-Options: {a['x_frame_options']}")
    print(f"Content-Security-Policy: {a['content_security_policy']}")
    print(f"frame-ancestors: {a['frame_ancestors']}"); print("-"*55)
    print(f"STATUS: {a['status']}"); print(f"RISK: {a['risk']}")
    print(f"CLICKJACKING PROTECTION ASSESSMENT SCORE: {a['score']}/100")
    print(f"Reason: {a['reason']}"); print(f"Recommendation: {a['recommendation']}")
    print("="*55)

def save_report(path, scan, a):
    p = Path(path)
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({"tool":"ClickJack","version":VERSION,"scan":scan,"assessment":a},
                                indent=2), encoding="utf-8")
    except PermissionError: raise ClickJackError(f"Permission denied: cannot write report '{p}'.")
    except OSError as e: raise ClickJackError(f"Could not write report: {e}")
    print(f"JSON report: {p}")

def generate_poc(url, output):
    p = Path(output)
    safe_url = html.escape(url, quote=True)
    content = """<!doctype html>
<html><head><meta charset="utf-8"><title>ClickJack Educational PoC</title></head>
<body>
<h1>ClickJack Educational PoC</h1>
<p><strong>Authorized testing only.</strong> This demonstrates framing only.</p>
<iframe src="TARGET" title="Authorized framing demonstration"
style="width:100%;height:600px"></iframe>
</body></html>""".replace("TARGET", safe_url)
    try:
        p.parent.mkdir(parents=True, exist_ok=True); p.write_text(content, encoding="utf-8")
    except PermissionError: raise ClickJackError(f"Permission denied: cannot create PoC '{p}'.")
    except OSError as e: raise ClickJackError(f"Could not create PoC: {e}")
    print(f"Educational PoC created: {p}")

def show_report(path):
    p = Path(path)
    if not p.exists(): raise ClickJackError(f"Report file not found: {p}")
    try: data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError,json.JSONDecodeError) as e: raise ClickJackError(f"Invalid or unreadable report: {e}")
    a = data.get("assessment",{})
    print("="*55); print("             CLICKJACK REPORT"); print("="*55)
    print(f"Target: {data.get('scan',{}).get('target','(unknown)')}")
    print(f"Status: {a.get('status','(unknown)')}"); print(f"Risk: {a.get('risk','(unknown)')}")
    print(f"Score: {a.get('score','(unknown)')}/100"); print("="*55)

def build_parser():
    p = argparse.ArgumentParser(prog="clickjack",
        description="Defensive clickjacking protection analyzer and safe educational PoC generator.")
    p.add_argument("--version", action="version", version=f"ClickJack {VERSION}")
    p.add_argument("--config", help="Path to INI configuration file.")
    p.add_argument("--log-level", choices=["DEBUG","INFO","WARNING","ERROR","CRITICAL"], default="INFO")
    sp = p.add_subparsers(dest="command", required=True)
    s = sp.add_parser("scan", help="Scan and analyze clickjacking protection.")
    s.add_argument("--url", required=True); s.add_argument("--report", choices=["json","none"], default="json")
    q = sp.add_parser("poc", help="Generate a safe educational framing PoC.")
    q.add_argument("--url", required=True); q.add_argument("--output", default="clickjacking_poc.html")
    r = sp.add_parser("report", help="Display a saved JSON report.")
    r.add_argument("--input", required=True)
    return p

def main(argv=None):
    a = build_parser().parse_args(argv)
    logging.basicConfig(level=getattr(logging,a.log_level), format="%(levelname)s: %(message)s")
    try:
        if a.command == "report": show_report(a.input); return 0
        settings = load_config(a.config); url = validate_url(a.url)
        if a.command == "poc": generate_poc(url,a.output); return 0
        scan = scan_target(url,settings); assessment = analyze_headers(scan["headers"])
        print_result(scan,assessment)
        if a.report == "json": save_report(settings["output"],scan,assessment)
        return 0
    except ClickJackError as e:
        print(f"ERROR: {e}", file=sys.stderr); return 2

if __name__ == "__main__":
    raise SystemExit(main())