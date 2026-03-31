#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════╗
║          WebSecScout — by HexaCyberLab                  ║
║   Intelligent Website Security Testing Guide Generator   ║
╚══════════════════════════════════════════════════════════╝
Author  : Md. Jony Hassain | HexaCyberLab
GitHub  : https://github.com/jonyhossan110
License : MIT
"""

import sys
import os
import json
import socket
import ssl
import urllib.request
import urllib.error
import urllib.parse
import http.client
import datetime
import re
import time
import argparse

# ─── Optional imports (graceful fallback) ────────────────────────────────────
try:
    import dns.resolver
    DNS_OK = True
except ImportError:
    DNS_OK = False

try:
    import whois as whois_lib
    WHOIS_OK = True
except ImportError:
    WHOIS_OK = False

try:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import cm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        HRFlowable, KeepTogether
    )
    from reportlab.lib.enums import TA_LEFT, TA_CENTER, TA_RIGHT
    PDF_OK = True
except ImportError:
    PDF_OK = False

# ─── Color codes for terminal ────────────────────────────────────────────────
R  = "\033[91m"   # red
G  = "\033[92m"   # green
Y  = "\033[93m"   # yellow
B  = "\033[94m"   # blue
M  = "\033[95m"   # magenta
C  = "\033[96m"   # cyan
W  = "\033[97m"   # white
DIM= "\033[2m"
RST= "\033[0m"

BANNER = f"""
{C}╔══════════════════════════════════════════════════════════════╗
║  {W}██╗    ██╗███████╗██████╗ ███████╗███████╗ ██████╗{C}          ║
║  {W}██║    ██║██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝{C}          ║
║  {W}██║ █╗ ██║█████╗  ██████╔╝███████╗█████╗  ██║     {C}          ║
║  {W}██║███╗██║██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║     {C}          ║
║  {W}╚███╔███╔╝███████╗██████╔╝███████║███████╗╚██████╗{C}          ║
║  {W} ╚══╝╚══╝ ╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝{C}          ║
║                                                              ║
║  {M}███████╗███████╗ ██████╗███████╗ ██████╗ ██╗   ██╗████████╗{C}  ║
║  {M}██╔════╝██╔════╝██╔════╝██╔════╝██╔═══██╗██║   ██║╚══██╔══╝{C}  ║
║  {M}███████╗█████╗  ██║     ███████╗██║   ██║██║   ██║   ██║   {C}  ║
║  {M}╚════██║██╔══╝  ██║     ╚════██║██║   ██║██║   ██║   ██║   {C}  ║
║  {M}███████║███████╗╚██████╗███████║╚██████╔╝╚██████╔╝   ██║   {C}  ║
║  {M}╚══════╝╚══════╝ ╚═════╝╚══════╝ ╚═════╝  ╚═════╝   ╚═╝   {C}  ║
║                                                              ║
║    {Y}Intelligent Website Security Testing Guide Generator{C}        ║
║    {DIM}by Md. Jony Hassain | HexaCyberLab{C}                          ║
╚══════════════════════════════════════════════════════════════╝{RST}
"""

# ══════════════════════════════════════════════════════════════════════════════
#  SCANNER MODULES
# ══════════════════════════════════════════════════════════════════════════════

def log(msg, color=W, prefix="•"):
    print(f"  {color}{prefix} {msg}{RST}")

def section(title):
    print(f"\n{C}  ─── {title} {'─'*(50-len(title))}{RST}")

def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

def get_domain(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    return parsed.netloc or parsed.path

def make_request(url, timeout=10, method="GET"):
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "Mozilla/5.0 (WebSecScout/1.0; HexaCyberLab)"}
        )
        resp = urllib.request.urlopen(req, timeout=timeout)
        return resp, resp.read()
    except urllib.error.HTTPError as e:
        return e, b""
    except Exception:
        return None, b""

# ─── 1. Basic Connectivity & Meta ─────────────────────────────────────────────
def scan_basic(url, domain):
    section("Basic Connectivity & Meta")
    result = {"module": "basic", "data": {}}
    
    resp, body = make_request(url)
    if resp:
        code = resp.status if hasattr(resp, 'status') else resp.code
        log(f"HTTP Status     : {code}", G if code == 200 else Y)
        result["data"]["http_status"] = code
        result["data"]["reachable"] = True
    else:
        log("Site unreachable or blocked", R, "✗")
        result["data"]["reachable"] = False
        return result

    # Server header
    server = resp.headers.get("Server", "Not disclosed")
    log(f"Server Header   : {server}", Y if server != "Not disclosed" else G)
    result["data"]["server"] = server

    # X-Powered-By
    xpb = resp.headers.get("X-Powered-By", None)
    if xpb:
        log(f"X-Powered-By    : {xpb}", R)
        result["data"]["x_powered_by"] = xpb
    else:
        log("X-Powered-By    : Hidden ✓", G)
        result["data"]["x_powered_by"] = None

    # Content-Type
    ct = resp.headers.get("Content-Type", "unknown")
    log(f"Content-Type    : {ct}", W)
    result["data"]["content_type"] = ct

    # Page size
    log(f"Response Size   : {len(body)} bytes", W)
    result["data"]["page_size"] = len(body)

    # Detect CMS from body
    body_str = body.decode("utf-8", errors="ignore").lower()
    cms = detect_cms(body_str, resp.headers)
    result["data"]["cms"] = cms
    if cms:
        log(f"CMS Detected    : {cms}", Y)
    else:
        log("CMS             : Not detected / Custom", W)

    return result

def detect_cms(body, headers):
    checks = {
        "WordPress"  : ["wp-content", "wp-includes", "wordpress"],
        "Joomla"     : ["joomla", "/components/com_", "mosConfig"],
        "Drupal"     : ["drupal", "sites/default/files"],
        "Shopify"    : ["cdn.shopify.com", "shopify"],
        "Magento"    : ["mage/cookies.js", "magento"],
        "Laravel"    : ["laravel_session", "laravel"],
        "Django"     : ["csrfmiddlewaretoken", "django"],
        "React/Next" : ["__next_data__", "_next/static"],
        "Vue/Nuxt"   : ["__nuxt", "nuxt"],
        "Wix"        : ["wix.com", "_wix_"],
        "Squarespace": ["squarespace.com", "static.squarespace"],
    }
    for cms_name, patterns in checks.items():
        if any(p in body for p in patterns):
            return cms_name
    xpb = headers.get("X-Powered-By", "").lower()
    if "php" in xpb:
        return f"PHP ({xpb})"
    return None

# ─── 2. SSL/TLS Analysis ──────────────────────────────────────────────────────
def scan_ssl(domain):
    section("SSL / TLS Certificate Analysis")
    result = {"module": "ssl", "data": {}}

    try:
        ctx = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.socket(), server_hostname=domain)
        conn.settimeout(8)
        conn.connect((domain, 443))
        cert = conn.getpeercert()
        conn.close()

        # Expiry
        exp_str = cert.get("notAfter", "")
        exp_dt = datetime.datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
        days_left = (exp_dt - datetime.datetime.utcnow()).days
        log(f"SSL Valid       : ✓ Yes", G)
        log(f"Expires         : {exp_str} ({days_left} days left)",
            G if days_left > 30 else R)
        result["data"]["ssl_valid"] = True
        result["data"]["expires"] = exp_str
        result["data"]["days_left"] = days_left

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org = issuer.get("organizationName", "Unknown")
        log(f"Issuer          : {org}", W)
        result["data"]["issuer"] = org

        # Subject
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        log(f"Common Name     : {cn}", W)
        result["data"]["cn"] = cn

        # Wildcard
        if cn.startswith("*"):
            log("Wildcard Cert   : Yes", Y)
            result["data"]["wildcard"] = True
        else:
            result["data"]["wildcard"] = False

        # TLS version
        tls_ver = conn.version() if hasattr(conn, 'version') else "TLS"
        result["data"]["tls_version"] = tls_ver

    except ssl.SSLError as e:
        log(f"SSL Error       : {e}", R, "✗")
        result["data"]["ssl_valid"] = False
        result["data"]["error"] = str(e)
    except Exception as e:
        log(f"SSL Check Failed: {e}", Y)
        result["data"]["ssl_valid"] = None
        result["data"]["error"] = str(e)

    return result

# ─── 3. Security Headers ──────────────────────────────────────────────────────
def scan_headers(url):
    section("HTTP Security Headers")
    result = {"module": "headers", "data": {}}

    resp, _ = make_request(url)
    if not resp:
        log("Could not fetch headers", R, "✗")
        return result

    important_headers = {
        "Strict-Transport-Security": {
            "alias": "HSTS",
            "importance": "CRITICAL",
            "missing_risk": "Allows downgrade attacks / HTTP sniffing"
        },
        "Content-Security-Policy": {
            "alias": "CSP",
            "importance": "HIGH",
            "missing_risk": "XSS attacks possible, no script source restrictions"
        },
        "X-Frame-Options": {
            "alias": "Clickjacking Protection",
            "importance": "HIGH",
            "missing_risk": "Clickjacking / UI redressing attacks"
        },
        "X-Content-Type-Options": {
            "alias": "MIME Sniffing Protection",
            "importance": "MEDIUM",
            "missing_risk": "MIME-type confusion attacks"
        },
        "Referrer-Policy": {
            "alias": "Referrer Policy",
            "importance": "MEDIUM",
            "missing_risk": "Sensitive URL data leaked in Referer header"
        },
        "Permissions-Policy": {
            "alias": "Feature Policy",
            "importance": "MEDIUM",
            "missing_risk": "Browser features (camera, mic) could be abused"
        },
        "X-XSS-Protection": {
            "alias": "XSS Filter",
            "importance": "LOW",
            "missing_risk": "Legacy browser XSS filter disabled"
        },
        "Cache-Control": {
            "alias": "Cache Control",
            "importance": "MEDIUM",
            "missing_risk": "Sensitive data may be cached"
        },
        "Access-Control-Allow-Origin": {
            "alias": "CORS Policy",
            "importance": "HIGH",
            "missing_risk": "Check if wildcard (*) is used — CORS misconfiguration risk"
        },
    }

    header_results = {}
    for header, info in important_headers.items():
        val = resp.headers.get(header, None)
        if val:
            # Flag dangerous values
            if header == "Access-Control-Allow-Origin" and val.strip() == "*":
                log(f"[{info['importance']}] {header}: {val} ⚠ WILDCARD!", R)
                header_results[header] = {"value": val, "status": "RISKY", **info}
            else:
                log(f"[{info['importance']}] {header}: Present ✓", G)
                header_results[header] = {"value": val, "status": "PRESENT", **info}
        else:
            color = R if info["importance"] in ("CRITICAL", "HIGH") else Y
            log(f"[{info['importance']}] {header}: MISSING ✗ → {info['missing_risk']}", color)
            header_results[header] = {"value": None, "status": "MISSING", **info}

    result["data"] = header_results
    return result

# ─── 4. DNS & Infrastructure ──────────────────────────────────────────────────
def scan_dns(domain):
    section("DNS & Infrastructure Analysis")
    result = {"module": "dns", "data": {}}

    # IP resolution
    try:
        ip = socket.gethostbyname(domain)
        log(f"Resolved IP     : {ip}", G)
        result["data"]["ip"] = ip
    except:
        log("DNS resolution failed", R, "✗")
        result["data"]["ip"] = None
        return result

    # DNS records via python-dns
    if DNS_OK:
        for rtype in ["A", "MX", "TXT", "NS", "AAAA"]:
            try:
                answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                vals = [str(r) for r in answers]
                log(f"{rtype:5} Records    : {', '.join(vals[:3])}", W)
                result["data"][f"dns_{rtype}"] = vals
            except:
                result["data"][f"dns_{rtype}"] = []
    else:
        log("DNS module not available (install dnspython)", Y)

    # WHOIS
    if WHOIS_OK:
        try:
            w = whois_lib.whois(domain)
            reg = str(w.registrar) if w.registrar else "Unknown"
            created = str(w.creation_date[0] if isinstance(w.creation_date, list)
                          else w.creation_date) if w.creation_date else "Unknown"
            exp = str(w.expiration_date[0] if isinstance(w.expiration_date, list)
                      else w.expiration_date) if w.expiration_date else "Unknown"
            log(f"Registrar       : {reg}", W)
            log(f"Domain Created  : {created}", W)
            log(f"Domain Expires  : {exp}", W)
            result["data"]["registrar"] = reg
            result["data"]["created"] = created
            result["data"]["expires_domain"] = exp
        except:
            log("WHOIS lookup failed", Y)
    else:
        log("WHOIS module not available (install python-whois)", Y)

    return result

# ─── 5. Common Sensitive Paths ────────────────────────────────────────────────
def scan_paths(base_url, cms=None):
    section("Sensitive Files & Directory Discovery")
    result = {"module": "paths", "data": {"found": [], "cms_specific": []}}

    general_paths = [
        ("/robots.txt",         "Robots.txt — reveals hidden paths"),
        ("/.git/HEAD",          "Git repo exposed!"),
        ("/.env",               ".env file — credentials leak risk"),
        ("/sitemap.xml",        "Sitemap — full URL listing"),
        ("/admin",              "Admin panel"),
        ("/login",              "Login page"),
        ("/wp-login.php",       "WordPress login"),
        ("/phpmyadmin",         "phpMyAdmin"),
        ("/backup",             "Backup directory"),
        ("/config.php",         "PHP config file"),
        ("/web.config",         "IIS config file"),
        ("/.htaccess",          "Apache config file"),
        ("/server-status",      "Apache server-status"),
        ("/info.php",           "PHP info page"),
        ("/test.php",           "Test PHP file"),
        ("/readme.html",        "WordPress readme (version leak)"),
        ("/changelog.txt",      "Changelog (version info)"),
        ("/composer.json",      "Composer dependencies exposed"),
        ("/package.json",       "Node package.json exposed"),
    ]

    cms_paths = {
        "WordPress": [
            ("/wp-json/wp/v2/users", "WordPress REST API — user enumeration"),
            ("/wp-content/debug.log","WordPress debug log"),
            ("/wp-config.php.bak",  "WordPress config backup"),
            ("/xmlrpc.php",         "WordPress XML-RPC — brute force vector"),
        ],
        "Joomla": [
            ("/administrator",      "Joomla admin panel"),
            ("/configuration.php",  "Joomla config"),
        ],
        "Laravel": [
            ("/.env",               "Laravel .env — DB credentials"),
            ("/storage/logs/laravel.log", "Laravel log file"),
        ],
    }

    paths_to_check = list(general_paths)
    if cms and cms in cms_paths:
        paths_to_check += cms_paths[cms]

    log(f"Checking {len(paths_to_check)} paths...", C)

    for path, desc in paths_to_check:
        url = base_url.rstrip("/") + path
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (WebSecScout/1.0)"}
            )
            resp = urllib.request.urlopen(req, timeout=6)
            code = resp.status
        except urllib.error.HTTPError as e:
            code = e.code
        except:
            code = 0

        if code in (200, 301, 302, 403):
            color = R if code == 200 else Y
            symbol = "⚠" if code == 200 else "!"
            log(f"[{code}] {path:40} {symbol} {desc}", color)
            entry = {"path": path, "code": code, "desc": desc}
            if path in [p for p, _ in cms_paths.get(cms or "", [])]:
                result["data"]["cms_specific"].append(entry)
            else:
                result["data"]["found"].append(entry)

    if not result["data"]["found"] and not result["data"]["cms_specific"]:
        log("No sensitive paths exposed (good!)", G)

    return result

# ─── 6. Port Check (common web ports) ────────────────────────────────────────
def scan_ports(domain):
    section("Open Port Detection (Web-relevant)")
    result = {"module": "ports", "data": {}}

    ports = {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
        80: "HTTP", 443: "HTTPS", 3306: "MySQL",
        5432: "PostgreSQL", 6379: "Redis", 8080: "HTTP-Alt",
        8443: "HTTPS-Alt", 27017: "MongoDB"
    }
    open_ports = []
    log(f"Scanning {len(ports)} common ports on {domain}...", C)

    for port, service in ports.items():
        try:
            s = socket.socket()
            s.settimeout(2)
            r = s.connect_ex((domain, port))
            s.close()
            if r == 0:
                risk = ""
                if port in (21, 23, 3306, 5432, 6379, 27017):
                    risk = " ⚠ RISKY if public!"
                    log(f"Port {port:5} ({service:12}) : OPEN{risk}", R)
                else:
                    log(f"Port {port:5} ({service:12}) : OPEN", G)
                open_ports.append({"port": port, "service": service, "risky": bool(risk)})
        except:
            pass

    result["data"]["open_ports"] = open_ports
    if not open_ports:
        log("No notable open ports detected (or filtered)", Y)
    return result

# ──────────────────────────────────────────────────────────────────────────────
#  INTELLIGENCE ENGINE — Generate Testing Priority Guide
# ──────────────────────────────────────────────────────────────────────────────

def generate_guide(scan_results: dict) -> dict:
    """
    Analyzes all scan data and produces a structured testing guide with:
    - Priority 1 (Critical): Must test immediately
    - Priority 2 (High): Important security tests
    - Priority 3 (Medium): Should test
    - Priority 4 (Informational): Good to verify
    """
    guide = {
        "critical": [],
        "high": [],
        "medium": [],
        "informational": [],
        "checklist_steps": []
    }

    basic = scan_results.get("basic", {}).get("data", {})
    ssl_d = scan_results.get("ssl", {}).get("data", {})
    hdrs  = scan_results.get("headers", {}).get("data", {})
    dns_d = scan_results.get("dns", {}).get("data", {})
    paths = scan_results.get("paths", {}).get("data", {})
    ports = scan_results.get("ports", {}).get("data", {})
    cms   = basic.get("cms", None)

    # ── SSL ──────────────────────────────────────────────────────────────────
    if not ssl_d.get("ssl_valid"):
        guide["critical"].append({
            "test"  : "SSL Certificate Invalid / Missing",
            "why"   : "All traffic is unencrypted. Passwords and data can be intercepted.",
            "steps" : ["Open browser → address bar → click lock icon",
                       "Check certificate details, issuer, expiry",
                       "Try: https://www.ssllabs.com/ssltest/"],
            "tools" : "SSLLabs, testssl.sh"
        })
    elif ssl_d.get("days_left", 999) < 30:
        guide["critical"].append({
            "test"  : f"SSL Certificate Expiring Soon ({ssl_d['days_left']} days)",
            "why"   : "Expired SSL = browser warning = site inaccessible for users",
            "steps" : ["Notify client immediately to renew certificate",
                       "Check auto-renewal settings in hosting panel"],
            "tools" : "SSLLabs"
        })

    # ── Security Headers ─────────────────────────────────────────────────────
    missing_critical = []
    missing_high = []
    for header, info in hdrs.items():
        if info["status"] == "MISSING":
            if info["importance"] == "CRITICAL":
                missing_critical.append(header)
            elif info["importance"] == "HIGH":
                missing_high.append(header)

    if missing_critical:
        guide["critical"].append({
            "test"  : f"Missing Critical Headers: {', '.join(missing_critical)}",
            "why"   : "HSTS missing = downgrade attack possible. Site can be forced to HTTP.",
            "steps" : ["Use https://securityheaders.com to scan",
                       "Check server config (nginx/apache/.htaccess)",
                       "Verify HSTS header: curl -I <url> | grep -i strict"],
            "tools" : "SecurityHeaders.com, curl"
        })

    if missing_high:
        guide["high"].append({
            "test"  : f"Missing Important Headers: {', '.join(missing_high)}",
            "why"   : "Missing CSP = XSS attacks easier. Missing X-Frame-Options = clickjacking.",
            "steps" : ["Test CSP with: https://csp-evaluator.withgoogle.com",
                       "Try embedding site in iframe to test clickjacking",
                       "Run: curl -I <url> | grep -i 'x-frame\\|content-security'"],
            "tools" : "CSP Evaluator, SecurityHeaders.com"
        })

    # ── Server disclosure ────────────────────────────────────────────────────
    server = basic.get("server", "")
    if server and server != "Not disclosed" and any(
            v in server.lower() for v in ["apache/", "nginx/", "iis/"]):
        guide["high"].append({
            "test"  : f"Server Version Disclosed: {server}",
            "why"   : "Attacker can search CVEs for this exact version.",
            "steps" : ["Check if version has known CVEs: https://cve.mitre.org",
                       "Test with curl -I <url> | grep Server",
                       "Check for exploit-db entries for this version"],
            "tools" : "curl, Shodan, CVE.mitre.org"
        })

    xpb = basic.get("x_powered_by")
    if xpb:
        guide["high"].append({
            "test"  : f"Technology Version Disclosed: X-Powered-By: {xpb}",
            "why"   : "PHP/framework version leakage helps attackers target specific exploits.",
            "steps" : ["Search exploitdb for disclosed version",
                       "Verify in response headers: curl -I <url>"],
            "tools" : "Exploit-DB, curl"
        })

    # ── Exposed paths ────────────────────────────────────────────────────────
    for entry in paths.get("found", []):
        if entry["code"] == 200:
            if ".git" in entry["path"] or ".env" in entry["path"]:
                guide["critical"].append({
                    "test"  : f"Critical File Exposed: {entry['path']}",
                    "why"   : entry["desc"],
                    "steps" : [f"Browse to: <url>{entry['path']}",
                               "Check for credentials, API keys, or source code",
                               "Immediately report to client for removal"],
                    "tools" : "Browser, curl"
                })
            elif "admin" in entry["path"] or "phpmyadmin" in entry["path"]:
                guide["high"].append({
                    "test"  : f"Admin Panel Exposed: {entry['path']}",
                    "why"   : "Open admin panel = brute force target",
                    "steps" : ["Try default credentials (admin/admin, admin/password)",
                               "Test for username enumeration",
                               "Check for rate limiting on login"],
                    "tools" : "Burp Suite, Hydra"
                })
            elif "xmlrpc" in entry["path"]:
                guide["critical"].append({
                    "test"  : "WordPress XML-RPC Enabled",
                    "why"   : "Allows brute force via multicall. Can DDoS amplification.",
                    "steps" : ["POST to /xmlrpc.php with system.listMethods",
                               "Test credential stuffing via multicall",
                               "Recommend client disable it if unused"],
                    "tools" : "curl, wpscan"
                })
            else:
                guide["medium"].append({
                    "test"  : f"Sensitive File Found: {entry['path']}",
                    "why"   : entry["desc"],
                    "steps" : [f"Review contents of {entry['path']}",
                               "Check if information reveals system details"],
                    "tools" : "Browser, curl"
                })

    # ── CMS-specific ─────────────────────────────────────────────────────────
    if cms == "WordPress":
        guide["high"].append({
            "test"  : "WordPress Detected — Full WP Security Audit Required",
            "why"   : "WordPress is #1 targeted CMS. Plugin vulns, user enum, outdated core.",
            "steps" : ["Run: wpscan --url <target> --enumerate u,p,t",
                       "Check /wp-json/wp/v2/users for user enumeration",
                       "Test /xmlrpc.php (brute force)",
                       "Check all plugins: searchsploit wordpress <plugin>",
                       "Check core version in /readme.html"],
            "tools" : "WPScan, searchsploit, Burp Suite"
        })
        guide["medium"].append({
            "test"  : "WordPress Plugin Vulnerability Check",
            "why"   : "60%+ of WP hacks are through outdated/vulnerable plugins",
            "steps" : ["List plugins from page source or wpscan",
                       "Check each plugin on WPVulnDB: https://wpscan.com/plugins",
                       "Test for known CVEs per plugin"],
            "tools" : "WPScan, WPVulnDB, Burp Suite"
        })

    elif cms == "Joomla":
        guide["high"].append({
            "test"  : "Joomla CMS Detected — Joomla Audit Required",
            "why"   : "Joomla has known RCE, SQLi, and auth bypass CVEs",
            "steps" : ["Run: joomscan --url <target>",
                       "Check Joomla version in /administrator",
                       "Test for known CVEs via exploitdb"],
            "tools" : "JoomScan, Burp Suite"
        })

    # ── Risky open ports ────────────────────────────────────────────────────
    for p in ports.get("open_ports", []):
        if p["risky"]:
            guide["critical"].append({
                "test"  : f"Risky Port Open: {p['port']} ({p['service']})",
                "why"   : f"{p['service']} exposed to internet — unauthorized access risk",
                "steps" : [f"Test connection: nc -v <host> {p['port']}",
                           "Try default credentials for the service",
                           "Check if access is needed — recommend firewall rule"],
                "tools" : f"nmap, netcat, {p['service'].lower()}-client"
            })

    # ── Standard always-include tests ────────────────────────────────────────
    guide["high"].append({
        "test"  : "SQL Injection Testing",
        "why"   : "Database compromise possible via unsanitized inputs",
        "steps" : ["Find all input fields, search boxes, login forms, URL params",
                   "Test manually: ' OR '1'='1 in inputs",
                   "Use sqlmap: sqlmap -u <url>?id=1 --dbs",
                   "Check error messages for SQL syntax leaks"],
        "tools" : "sqlmap, Burp Suite, manual testing"
    })

    guide["high"].append({
        "test"  : "Cross-Site Scripting (XSS) Testing",
        "why"   : "Session hijacking, credential theft via injected scripts",
        "steps" : ["Find all reflection points: search, comment, contact forms",
                   "Test: <script>alert('XSS')</script>",
                   "Test: <img src=x onerror=alert(1)>",
                   "Use Burp Suite Scanner for automated detection",
                   "Test stored, reflected, and DOM-based XSS"],
        "tools" : "Burp Suite, XSStrike, OWASP ZAP"
    })

    guide["medium"].append({
        "test"  : "Authentication & Session Management",
        "why"   : "Weak auth = account takeover",
        "steps" : ["Test login form for: rate limiting, account lockout",
                   "Check password policy strength",
                   "Inspect session cookie flags (HttpOnly, Secure, SameSite)",
                   "Test remember-me token predictability",
                   "Try: curl -I <url> | grep Set-Cookie"],
        "tools" : "Burp Suite, browser DevTools"
    })

    guide["medium"].append({
        "test"  : "CSRF (Cross-Site Request Forgery) Testing",
        "why"   : "Victim can be tricked into performing actions on their behalf",
        "steps" : ["Identify state-changing actions (profile edit, password change)",
                   "Check if CSRF token is present in forms",
                   "Test if token is validated server-side",
                   "Try replaying request without token in Burp Suite"],
        "tools" : "Burp Suite, manual"
    })

    guide["medium"].append({
        "test"  : "File Upload Security Testing",
        "why"   : "Malicious file upload = Remote Code Execution (RCE)",
        "steps" : ["Find all file upload features",
                   "Try uploading: .php, .php5, .phtml files",
                   "Test MIME type bypass (change content-type header)",
                   "Check if uploaded files are accessible via URL",
                   "Test for path traversal in filename"],
        "tools" : "Burp Suite, manual testing"
    })

    guide["informational"].append({
        "test"  : "Information Disclosure & Error Handling",
        "why"   : "Stack traces reveal framework, paths, and DB structure",
        "steps" : ["Trigger 404/500 errors intentionally",
                   "Check if error messages contain stack traces",
                   "Try non-existent pages: /doesnotexist123",
                   "Submit invalid data in forms and observe errors"],
        "tools" : "Browser, curl"
    })

    guide["informational"].append({
        "test"  : "Third-party Script & Dependency Audit",
        "why"   : "Outdated JS libraries have known vulnerabilities",
        "steps" : ["View page source → note all external scripts",
                   "Use: https://retire.insecurity.today/ or",
                   "Burp Suite extension: Retire.js",
                   "Check CDN-hosted jQuery/Bootstrap version"],
        "tools" : "Retire.js, Burp Suite, browser DevTools"
    })

    # Build sequential checklist
    step = 1
    for priority, label in [
        ("critical", "🔴 CRITICAL"), ("high", "🟠 HIGH"),
        ("medium", "🟡 MEDIUM"), ("informational", "🔵 INFO")
    ]:
        for item in guide[priority]:
            guide["checklist_steps"].append({
                "step"    : step,
                "priority": label,
                "test"    : item["test"],
                "tools"   : item.get("tools", "Manual"),
            })
            step += 1

    return guide

# ══════════════════════════════════════════════════════════════════════════════
#  PDF REPORT GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

def generate_pdf(target_url, domain, scan_results, guide, output_path):
    if not PDF_OK:
        print(f"\n{R}  ✗ ReportLab not installed. Run: pip install reportlab{RST}")
        return False

    doc = SimpleDocTemplate(
        output_path,
        pagesize=A4,
        rightMargin=2*cm, leftMargin=2*cm,
        topMargin=2*cm, bottomMargin=2*cm
    )

    styles = getSampleStyleSheet()
    W_COLOR = colors.HexColor("#0d1117")
    ACCENT  = colors.HexColor("#00d4ff")
    DANGER  = colors.HexColor("#ff4444")
    WARNING = colors.HexColor("#ff8800")
    SUCCESS = colors.HexColor("#00cc66")
    INFO    = colors.HexColor("#4488ff")
    GRAY    = colors.HexColor("#8b9198")
    LIGHT   = colors.HexColor("#f0f6fc")

    # Custom styles
    title_style = ParagraphStyle("title",
        fontName="Helvetica-Bold", fontSize=22,
        textColor=ACCENT, spaceAfter=4, alignment=TA_CENTER)
    sub_style = ParagraphStyle("sub",
        fontName="Helvetica", fontSize=10,
        textColor=GRAY, spaceAfter=2, alignment=TA_CENTER)
    h1_style = ParagraphStyle("h1",
        fontName="Helvetica-Bold", fontSize=14,
        textColor=ACCENT, spaceBefore=14, spaceAfter=6)
    h2_style = ParagraphStyle("h2",
        fontName="Helvetica-Bold", fontSize=11,
        textColor=colors.HexColor("#e6edf3"), spaceBefore=8, spaceAfter=4)
    body_style = ParagraphStyle("body",
        fontName="Helvetica", fontSize=9,
        textColor=colors.HexColor("#8b9198"), spaceAfter=3, leading=14)
    step_style = ParagraphStyle("step",
        fontName="Helvetica", fontSize=8.5,
        textColor=colors.HexColor("#8b9198"), spaceAfter=2,
        leftIndent=12, leading=13)
    bold_body = ParagraphStyle("bold_body",
        fontName="Helvetica-Bold", fontSize=9,
        textColor=colors.HexColor("#e6edf3"), spaceAfter=2)
    code_style = ParagraphStyle("code",
        fontName="Courier", fontSize=8,
        textColor=colors.HexColor("#79c0ff"), spaceAfter=3,
        leftIndent=10, backColor=colors.HexColor("#161b22"))

    story = []

    # ── Cover ────────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1.5*cm))
    story.append(Paragraph("WebSecScout", title_style))
    story.append(Paragraph("Intelligent Website Security Testing Guide", sub_style))
    story.append(Spacer(1, 0.3*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.3*cm))

    now = datetime.datetime.now().strftime("%B %d, %Y — %H:%M")
    meta = [
        ["Target Website", target_url],
        ["Domain", domain],
        ["Report Generated", now],
        ["Generated By", "WebSecScout | HexaCyberLab"],
        ["Analyst", "Md. Jony Hassain"],
    ]
    basic = scan_results.get("basic", {}).get("data", {})
    if basic.get("cms"):
        meta.append(["CMS Detected", basic["cms"]])
    if basic.get("server"):
        meta.append(["Server", basic["server"]])

    meta_table = Table(meta, colWidths=[5*cm, 11*cm])
    meta_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (0,-1), colors.HexColor("#161b22")),
        ("BACKGROUND", (1,0), (1,-1), colors.HexColor("#0d1117")),
        ("TEXTCOLOR", (0,0), (0,-1), ACCENT),
        ("TEXTCOLOR", (1,0), (1,-1), colors.HexColor("#e6edf3")),
        ("FONTNAME", (0,0), (0,-1), "Helvetica-Bold"),
        ("FONTNAME", (1,0), (1,-1), "Helvetica"),
        ("FONTSIZE", (0,0), (-1,-1), 9),
        ("ROWBACKGROUNDS", (0,0), (-1,-1),
         [colors.HexColor("#161b22"), colors.HexColor("#0d1117")]),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
        ("PADDING", (0,0), (-1,-1), 6),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.8*cm))

    # ── Summary stats ────────────────────────────────────────────────────────
    story.append(Paragraph("Scan Summary", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
    story.append(Spacer(1, 0.2*cm))

    counts = {
        "🔴 Critical": len(guide["critical"]),
        "🟠 High"    : len(guide["high"]),
        "🟡 Medium"  : len(guide["medium"]),
        "🔵 Info"    : len(guide["informational"]),
    }
    stat_data = [list(counts.keys()), list(counts.values())]
    stat_colors = [DANGER, WARNING, colors.HexColor("#f0e040"), INFO]
    stat_table = Table(
        [[Paragraph(f"<b>{k}</b>", ParagraphStyle("sc", fontName="Helvetica-Bold",
            fontSize=10, textColor=stat_colors[i], alignment=TA_CENTER))
          for i, k in enumerate(counts.keys())],
         [Paragraph(f"<b>{v}</b>", ParagraphStyle("sv", fontName="Helvetica-Bold",
            fontSize=20, textColor=stat_colors[i], alignment=TA_CENTER))
          for i, v in enumerate(counts.values())]],
        colWidths=[4*cm]*4
    )
    stat_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,-1), colors.HexColor("#161b22")),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
        ("PADDING", (0,0), (-1,-1), 10),
        ("ALIGN", (0,0), (-1,-1), "CENTER"),
    ]))
    story.append(stat_table)
    story.append(Spacer(1, 0.6*cm))

    # ── Step-by-step guide ───────────────────────────────────────────────────
    story.append(Paragraph("Security Testing Guide — Step by Step", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))

    priority_order = [
        ("critical",      "🔴 CRITICAL PRIORITY",  DANGER),
        ("high",          "🟠 HIGH PRIORITY",       WARNING),
        ("medium",        "🟡 MEDIUM PRIORITY",     colors.HexColor("#f0e040")),
        ("informational", "🔵 INFORMATIONAL",       INFO),
    ]

    for key, label, color in priority_order:
        items = guide[key]
        if not items:
            continue

        story.append(Spacer(1, 0.4*cm))
        hdr = Table([[Paragraph(f"  {label}", ParagraphStyle("ph",
            fontName="Helvetica-Bold", fontSize=11, textColor=W_COLOR))]],
            colWidths=[17*cm])
        hdr.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (0,0), color),
            ("PADDING", (0,0), (0,0), 8),
        ]))
        story.append(hdr)

        for i, item in enumerate(items, 1):
            story.append(Spacer(1, 0.2*cm))
            story.append(Paragraph(f"  ▶  {item['test']}", h2_style))
            story.append(Paragraph(f"Why: {item['why']}", body_style))
            story.append(Paragraph("Steps:", bold_body))
            for s in item["steps"]:
                safe_s = s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            story.append(Paragraph(f"  → {safe_s}", step_style))
            if item.get("tools"):
                story.append(Paragraph(f"Tools: {item['tools']}", code_style))
            story.append(HRFlowable(width="100%", thickness=0.3,
                                    color=colors.HexColor("#21262d")))

    # ── Full checklist ───────────────────────────────────────────────────────
    story.append(Spacer(1, 0.6*cm))
    story.append(Paragraph("Quick Testing Checklist", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))
    story.append(Spacer(1, 0.2*cm))

    checklist_data = [
        [Paragraph("<b>#</b>", bold_body),
         Paragraph("<b>Priority</b>", bold_body),
         Paragraph("<b>Test</b>", bold_body),
         Paragraph("<b>Tools</b>", bold_body),
         Paragraph("<b>✓</b>", bold_body)]
    ]
    for row in guide["checklist_steps"]:
        p_color = {"🔴": DANGER, "🟠": WARNING, "🟡": colors.HexColor("#f0e040"), "🔵": INFO}
        emoji = row["priority"][:2]
        pcol = p_color.get(emoji, INFO)
        checklist_data.append([
            Paragraph(str(row["step"]), body_style),
            Paragraph(f'<font color="#{"%02x%02x%02x" % (int(pcol.red*255), int(pcol.green*255), int(pcol.blue*255))}">{row["priority"]}</font>',
                      ParagraphStyle("pc", fontName="Helvetica", fontSize=8)),
            Paragraph(row["test"], body_style),
            Paragraph(row["tools"], ParagraphStyle("tc", fontName="Courier", fontSize=7.5,
                      textColor=colors.HexColor("#79c0ff"))),
            Paragraph("□", body_style),
        ])

    cl_table = Table(checklist_data, colWidths=[0.7*cm, 2.8*cm, 7.5*cm, 4.5*cm, 0.8*cm])
    cl_table.setStyle(TableStyle([
        ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#161b22")),
        ("ROWBACKGROUNDS", (0,1), (-1,-1),
         [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
        ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
        ("PADDING", (0,0), (-1,-1), 5),
        ("VALIGN", (0,0), (-1,-1), "TOP"),
    ]))
    story.append(cl_table)

    # ── Raw scan data summary ─────────────────────────────────────────────────
    story.append(Spacer(1, 0.6*cm))
    story.append(Paragraph("Raw Scan Data", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.5, color=colors.HexColor("#30363d")))

    # SSL
    ssl_d = scan_results.get("ssl", {}).get("data", {})
    if ssl_d:
        story.append(Paragraph("SSL/TLS", h2_style))
        for k, v in ssl_d.items():
            story.append(Paragraph(f"{k}: {v}", body_style))

    # Headers
    hdrs = scan_results.get("headers", {}).get("data", {})
    if hdrs:
        story.append(Paragraph("Security Headers", h2_style))
        hdr_rows = [["Header", "Status", "Importance"]]
        for h, info in hdrs.items():
            status_color = SUCCESS if info["status"] == "PRESENT" else (
                DANGER if info["importance"] in ("CRITICAL","HIGH") else WARNING)
            hdr_rows.append([
                Paragraph(h, ParagraphStyle("hc", fontName="Courier", fontSize=8,
                           textColor=colors.HexColor("#79c0ff"))),
                Paragraph(info["status"], ParagraphStyle("hs", fontName="Helvetica-Bold",
                           fontSize=8, textColor=status_color)),
                Paragraph(info["importance"], body_style),
            ])
        hdr_table = Table(hdr_rows, colWidths=[8*cm, 3*cm, 3*cm])
        hdr_table.setStyle(TableStyle([
            ("BACKGROUND", (0,0), (-1,0), colors.HexColor("#161b22")),
            ("ROWBACKGROUNDS", (0,1), (-1,-1),
             [colors.HexColor("#0d1117"), colors.HexColor("#161b22")]),
            ("GRID", (0,0), (-1,-1), 0.3, colors.HexColor("#30363d")),
            ("PADDING", (0,0), (-1,-1), 5),
        ]))
        story.append(hdr_table)

    # Open ports
    open_ports = scan_results.get("ports", {}).get("data", {}).get("open_ports", [])
    if open_ports:
        story.append(Paragraph("Open Ports", h2_style))
        for p in open_ports:
            story.append(Paragraph(
                f"Port {p['port']} ({p['service']}) — {'⚠ RISKY' if p['risky'] else 'OK'}",
                body_style))

    # ── Footer ───────────────────────────────────────────────────────────────
    story.append(Spacer(1, 1*cm))
    story.append(HRFlowable(width="100%", thickness=1, color=ACCENT))
    story.append(Spacer(1, 0.2*cm))
    footer_style = ParagraphStyle("footer",
        fontName="Helvetica", fontSize=8, textColor=GRAY, alignment=TA_CENTER)
    story.append(Paragraph(
        "Generated by WebSecScout | HexaCyberLab | github.com/jonyhossan110",
        footer_style))
    story.append(Paragraph(
        "⚠ For authorized security testing only. Use responsibly and ethically.",
        ParagraphStyle("warn", fontName="Helvetica-Bold", fontSize=7.5,
                       textColor=WARNING, alignment=TA_CENTER)))

    doc.build(story)
    return True

# ══════════════════════════════════════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════════════════════════════════════

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="WebSecScout — Intelligent Website Security Testing Guide Generator",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("url", nargs="?", help="Target website URL (e.g. example.com)")
    parser.add_argument("-o", "--output", default=None,
                        help="PDF output path (default: auto-named)")
    parser.add_argument("--no-ports", action="store_true",
                        help="Skip port scanning (faster)")
    parser.add_argument("--no-paths", action="store_true",
                        help="Skip sensitive path discovery")
    args = parser.parse_args()

    if not args.url:
        target = input(f"{C}  Enter target website URL: {RST}").strip()
    else:
        target = args.url

    url    = normalize_url(target)
    domain = get_domain(url)

    print(f"\n{G}  Target : {W}{url}")
    print(f"{G}  Domain : {W}{domain}")
    print(f"{G}  Time   : {W}{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"\n{Y}  ⚡ Starting reconnaissance...{RST}\n")

    scan_results = {}

    # Run scans
    scan_results["basic"] = scan_basic(url, domain)
    cms = scan_results["basic"]["data"].get("cms")

    scan_results["ssl"]  = scan_ssl(domain)
    scan_results["headers"] = scan_headers(url)
    scan_results["dns"]  = scan_dns(domain)

    if not args.no_paths:
        scan_results["paths"] = scan_paths(url, cms)
    else:
        scan_results["paths"] = {"module": "paths", "data": {"found":[], "cms_specific":[]}}

    if not args.no_ports:
        scan_results["ports"] = scan_ports(domain)
    else:
        scan_results["ports"] = {"module": "ports", "data": {"open_ports": []}}

    # Generate intelligence guide
    section("Generating Security Testing Guide")
    guide = generate_guide(scan_results)

    total = (len(guide["critical"]) + len(guide["high"]) +
             len(guide["medium"]) + len(guide["informational"]))

    log(f"Total Test Cases : {total}", C)
    log(f"Critical         : {len(guide['critical'])}", R if guide['critical'] else G)
    log(f"High             : {len(guide['high'])}", Y if guide['high'] else G)
    log(f"Medium           : {len(guide['medium'])}", Y)
    log(f"Informational    : {len(guide['informational'])}", B)

    # Save PDF
    safe_name = re.sub(r"[^a-zA-Z0-9_-]", "_", domain)
    timestamp  = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    pdf_path   = args.output or f"WebSecScout_{safe_name}_{timestamp}.pdf"

    section("Generating PDF Report")
    log(f"Output file: {pdf_path}", C)

    success = generate_pdf(url, domain, scan_results, guide, pdf_path)

    if success:
        size = os.path.getsize(pdf_path) // 1024
        print(f"\n{G}{'═'*66}")
        print(f"  ✅  Report saved: {pdf_path} ({size} KB)")
        print(f"{'═'*66}{RST}\n")
    else:
        print(f"\n{R}  PDF generation failed. Check ReportLab installation.{RST}\n")

    # Also save JSON
    json_path = pdf_path.replace(".pdf", ".json")
    with open(json_path, "w") as f:
        json.dump({"target": url, "domain": domain,
                   "scan": scan_results, "guide": guide}, f, indent=2, default=str)
    log(f"JSON data saved : {json_path}", DIM)

if __name__ == "__main__":
    main()
