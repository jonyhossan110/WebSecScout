# 🔐 WebSecScout

> **Intelligent Website Security Testing Guide Generator**
> Built by [Md. Jony Hassain](https://linkedin.com/in/md-jony-hassain-web-cybersecurity-expert/) | [HexaCyberLab](https://facebook.com/HexaCyberLab)

---

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20Mac-lightgrey?style=flat-square)
![Usage](https://img.shields.io/badge/Use-Ethical%20Hacking%20Only-red?style=flat-square)

---

## 🎯 What is WebSecScout?

WebSecScout is a **one-command website security analysis tool** for professional web penetration testers. 

You give it a client's website URL → it automatically fingerprints the website, analyzes all attack surfaces, and **generates a perfect PDF testing guide** showing exactly:

- ✅ What CMS/technology the site uses
- ✅ What security headers are missing (and why it matters)
- ✅ Which sensitive files are exposed
- ✅ SSL/TLS certificate status
- ✅ Open ports and their risks
- ✅ A **prioritized, step-by-step manual testing checklist** (Critical → High → Medium → Info)
- ✅ Exact commands and tools to use for each test

---

## 📸 Output Example

```
  ─── Basic Connectivity & Meta ──────────────────────────────
  • HTTP Status     : 200
  • Server Header   : Apache/2.4.51
  • CMS Detected    : WordPress
  
  ─── SSL / TLS Certificate Analysis ──────────────────────────
  • SSL Valid       : ✓ Yes
  • Expires         : Dec 25 00:00:00 2025 GMT (45 days left)
  
  ─── HTTP Security Headers ────────────────────────────────────
  • [CRITICAL] Strict-Transport-Security: MISSING ✗
  • [HIGH] Content-Security-Policy: MISSING ✗
  • [HIGH] X-Frame-Options: Present ✓
```

And then a **full PDF report** with:
- Prioritized test guide (🔴 Critical → 🔵 Informational)
- Step-by-step manual testing instructions
- Tools recommendation per test
- Full checklist table with checkboxes

---

## ⚙️ Installation

```bash
git clone https://github.com/jonyhossan110/WebSecScout.git
cd WebSecScout
pip install -r requirements.txt
```

---

## 🚀 Usage

### Basic scan:
```bash
python websecscout.py example.com
```

### With custom PDF output path:
```bash
python websecscout.py example.com -o client_report.pdf
```

### Skip port scanning (faster):
```bash
python websecscout.py example.com --no-ports
```

### Interactive mode (no arguments):
```bash
python websecscout.py
# Enter target website URL: example.com
```

---

## 📦 What It Scans

| Module | What it checks |
|--------|---------------|
| **Basic** | HTTP status, server header, technology disclosure, CMS detection |
| **SSL/TLS** | Certificate validity, expiry, issuer, wildcard, TLS version |
| **Security Headers** | HSTS, CSP, X-Frame-Options, CORS, Cache-Control, etc. |
| **DNS/WHOIS** | A/MX/TXT/NS records, domain registration info, IP resolution |
| **Sensitive Paths** | .git, .env, admin panels, backups, config files, CMS-specific files |
| **Port Scan** | 12 common web-related ports (MySQL, Redis, MongoDB, FTP, SSH, etc.) |

---

## 📋 Intelligence Engine

After scanning, WebSecScout automatically analyzes results and generates a **prioritized guide**:

- 🔴 **Critical** — Must fix / test immediately (e.g., exposed .env, XML-RPC enabled)
- 🟠 **High** — Important tests (SQLi, XSS, admin panels, version disclosure)
- 🟡 **Medium** — Should test (CSRF, file upload, auth weaknesses)
- 🔵 **Informational** — Good to verify (error handling, third-party scripts)

Each item includes:
- **Why** it matters
- **Exact steps** to test manually
- **Recommended tools** (sqlmap, Burp Suite, WPScan, etc.)

---

## 📄 Output Files

| File | Description |
|------|-------------|
| `WebSecScout_<domain>_<date>.pdf` | Full printable PDF report with guide + checklist |
| `WebSecScout_<domain>_<date>.json` | Raw scan data in JSON format |

---

## 🛠️ Dependencies

```
reportlab     — PDF generation
dnspython     — DNS record analysis
python-whois  — Domain WHOIS lookup
beautifulsoup4 — HTML parsing (future use)
```

---

## ⚠️ Disclaimer

> This tool is for **authorized security testing only**.
> Only scan websites you own or have **explicit written permission** to test.
> Unauthorized scanning is illegal. The author is not responsible for misuse.

---

## 👨‍💻 Author

**Md. Jony Hassain**
Web Cybersecurity Expert | Ethical Hacker | Web Penetration Tester

- 🌐 Agency: [HexaCyberLab](https://facebook.com/HexaCyberLab)
- 💼 LinkedIn: [md-jony-hassain-web-cybersecurity-expert](https://linkedin.com/in/md-jony-hassain-web-cybersecurity-expert/)
- 💻 Upwork: [HexaCyberLab Profile](https://upwork.com/freelancers/~01fb775c14cdfe8922)
- 🐙 GitHub: [jonyhossan110](https://github.com/jonyhossan110)

---

## 📜 License

MIT License — Free to use, modify, and distribute with attribution.

---

> *"Security is not a product, but a process."* — Bruce Schneier
