# 🔍 GitSecScan — GitHub Secret Leakage Scanner

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.8+-blue?style=flat-square&logo=python"/>
  <img src="https://img.shields.io/badge/License-MIT-green?style=flat-square"/>
  <img src="https://img.shields.io/badge/Made%20in-India-orange?style=flat-square"/>
  <img src="https://img.shields.io/badge/For-Ethical%20Use%20Only-red?style=flat-square"/>
</p>

> Scan GitHub users, organizations, and repositories for accidentally exposed secrets — API keys, tokens, passwords, private keys, and more. Generates a clean HTML report in seconds.

---

## 🎬 Demo

<!-- After recording, replace YOUR_ID_HERE with the ID from your asciinema upload -->
[![Demo](https://asciinema.org/a/YOUR_ID_HERE.svg)](https://asciinema.org/a/YOUR_ID_HERE)

> **How to record and upload your demo:**
> ```bash
> # Install asciinema (Kali/Ubuntu)
> sudo apt install asciinema
>
> # Record the terminal (idle gaps capped at 2s so it stays snappy)
> asciinema rec --idle-time-limit 2 demo.cast
>
> # Run the scanner inside the recording
> ./scanner.py --user Brainrotshiva
>
> # Press Ctrl+D to stop recording
>
> # Upload to asciinema.org — get a shareable link
> asciinema upload demo.cast
> ```
> Copy the ID from the link (e.g. `https://asciinema.org/a/abc123` → ID is `abc123`)  
> Then replace `YOUR_ID_HERE` in both URLs above.

---

## 🚨 What It Finds

| Secret Type | Severity |
|---|---|
| AWS Access & Secret Keys | 🔴 CRITICAL |
| GitHub Personal Access Tokens | 🔴 CRITICAL |
| Stripe Live Keys | 🔴 CRITICAL |
| RSA / SSH / PGP Private Keys | 🔴 CRITICAL |
| Google API Keys | 🟠 HIGH |
| Slack Tokens & Webhooks | 🟠 HIGH |
| Database URLs (Postgres, MySQL, MongoDB) | 🟠 HIGH |
| Firebase API Keys | 🟠 HIGH |
| JWT Tokens | 🟠 HIGH |
| Azure Storage Keys | 🔴 CRITICAL |
| Twilio, SendGrid, Mailgun Keys | 🟠 HIGH |
| Telegram Bot Tokens | 🟠 HIGH |
| NPM Tokens | 🟠 HIGH |
| Generic Passwords & API Keys | 🟡 MEDIUM |
| **25+ patterns total** | |

---

## ⚡ Quick Start

**No dependencies. Pure Python 3.8+. Install nothing.**

```bash
git clone https://github.com/Brainrotshiva/github-secret-scanner
cd github-secret-scanner

# Make it executable (do this once)
chmod +x scanner.py

# Scan an organization
./scanner.py --org netflix

# Scan a user
./scanner.py --user torvalds

# Scan a specific repo
./scanner.py --repo https://github.com/target/repo

# Use a GitHub token to avoid rate limits (recommended)
./scanner.py --org mycompany --token ghp_yourtoken

# Custom output file
./scanner.py --org mycompany --output company_report.html

# Also export as JSON
./scanner.py --org mycompany --output report.html --json findings.json
```

> **Tip:** Add an alias so you can run it from anywhere:
> ```bash
> echo "alias scanner='~/github-secret-scanner/scanner.py'" >> ~/.bashrc && source ~/.bashrc
> scanner --user Brainrotshiva
> ```

---

## ⚡ Live Dashboard (Real-time Browser Updates)

Install one dependency, then run `live_scanner.py` for a live browser dashboard that updates as the scan runs:

```bash
pip install websockets

chmod +x live_scanner.py

# Scan and watch results appear live in browser
./live_scanner.py --org netflix
./live_scanner.py --user torvalds
./live_scanner.py --repo https://github.com/target/repo --token ghp_xxxx
```

Browser opens automatically at `http://localhost:8765` — every new finding appears instantly with no refresh needed.

---

## 📊 Sample Output

**Terminal:**
```
🔍 GitSecScan — GitHub Secret Leakage Scanner
==================================================
📡 Fetching repos for: demo-company
✅ Found 12 public repos

  📂 Scanning demo-company/backend-api...
    🔴 [CRITICAL] AWS Access Key in config/prod.env:14
    🔴 [CRITICAL] AWS Secret Key in config/prod.env:15
    🔴 [CRITICAL] RSA Private Key in certs/server.pem:1
  📂 Scanning demo-company/mobile-app...
    🔴 [CRITICAL] Stripe Secret Key in src/stripe.js:7
    🟠 [HIGH] Firebase API Key in src/firebase.js:3

==================================================
📊 SCAN COMPLETE
   Repos scanned : 12
   Files scanned : 347
   Total findings: 10
   🔴 Critical   : 6
   🟠 High       : 3
   🟡 Medium     : 1

📄 HTML report saved → report.html
```

**HTML Report:** A dark-themed, professional report with severity badges, file links, line numbers, and redacted previews.

---

## 🔑 GitHub Token (Recommended)

Without a token, GitHub limits you to **60 requests/hour**.  
With a token, you get **5,000 requests/hour**.

Generate a free token at: `GitHub → Settings → Developer Settings → Personal Access Tokens`  
Only needs `public_repo` read scope (no write permissions needed).

---

## 🛡️ Responsible Use

This tool is built for:
- Security researchers doing authorized audits
- Developers checking their own repos
- Bug bounty hunters (within program scope)
- Companies auditing their own GitHub organization

**Do NOT use this tool on targets you don't own or have explicit permission to test.**  
Unauthorized scanning may violate GitHub's Terms of Service and applicable laws.

---

## 🏗️ Architecture

```
scanner.py
├── SECRET_PATTERNS      # 25+ compiled regex patterns
├── get_repos()          # GitHub API: fetch all repos
├── get_repo_files()     # Recursive file tree walker
├── get_file_content()   # Base64 decode + smart skip logic
├── scan_content()       # Line-by-line pattern matching
├── redact()             # Safe partial masking of found secrets
└── generate_html_report() # Full dark-theme HTML report generator
```

---

## 📁 Output Files

| File | Description |
|---|---|
| `report.html` | Visual HTML report (open in browser) |
| `findings.json` | Machine-readable findings (optional) |

---

## 🗺️ Roadmap

- [ ] v1.1 — Scan local folders/repos
- [ ] v1.2 — GitHub Actions integration
- [ ] v1.3 — Slack/webhook alert on findings
- [ ] v1.4 — Entropy-based secret detection
- [ ] v2.0 — Web dashboard UI

---

## 👤 Author

**Badam Shiva Sai**  
Cybersecurity Researcher | ISC2 CC | CEH (In Progress)  
📍 Hyderabad, India

- GitHub: [@Brainrotshiva](https://github.com/Brainrotshiva)
- LinkedIn: [Badam Shiva Sai](https://linkedin.com/in/your-profile)

---

## 📜 License

MIT License — free to use, modify, and distribute.  
If you find this useful, consider giving it a ⭐

---

*For responsible disclosure only. Built to make the internet more secure, one repo at a time.*
