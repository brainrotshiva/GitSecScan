#!/usr/bin/env python3
"""
GitHub Secret Leakage Scanner
Author: Badam Shiva Sai (Brainrotshiva)
GitHub: https://github.com/Brainrotshiva
"""

import re
import sys
import json
import base64
import argparse
import urllib.request
import urllib.error
from datetime import datetime
from dataclasses import dataclass, field
from typing import Optional

# ─────────────────────────────────────────────
#  SECRET PATTERNS
# ─────────────────────────────────────────────
SECRET_PATTERNS = [
    {"name": "AWS Access Key",          "severity": "CRITICAL", "pattern": r"AKIA[0-9A-Z]{16}"},
    {"name": "AWS Secret Key",          "severity": "CRITICAL", "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]"},
    {"name": "GitHub Token",            "severity": "CRITICAL", "pattern": r"ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{82}"},
    {"name": "GitHub OAuth Token",      "severity": "CRITICAL", "pattern": r"gho_[a-zA-Z0-9]{36}"},
    {"name": "Google API Key",          "severity": "HIGH",     "pattern": r"AIza[0-9A-Za-z\-_]{35}"},
    {"name": "Google OAuth",            "severity": "HIGH",     "pattern": r"[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com"},
    {"name": "Stripe Secret Key",       "severity": "CRITICAL", "pattern": r"sk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Stripe Publishable Key",  "severity": "MEDIUM",   "pattern": r"pk_live_[0-9a-zA-Z]{24,}"},
    {"name": "Slack Token",             "severity": "HIGH",     "pattern": r"xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}"},
    {"name": "Slack Webhook",           "severity": "HIGH",     "pattern": r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"},
    {"name": "Twilio API Key",          "severity": "HIGH",     "pattern": r"SK[0-9a-fA-F]{32}"},
    {"name": "SendGrid API Key",        "severity": "HIGH",     "pattern": r"SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}"},
    {"name": "Mailgun API Key",         "severity": "HIGH",     "pattern": r"key-[0-9a-zA-Z]{32}"},
    {"name": "Firebase URL",            "severity": "MEDIUM",   "pattern": r"https://[a-z0-9-]+\.firebaseio\.com"},
    {"name": "Firebase API Key",        "severity": "HIGH",     "pattern": r"(?i)firebase.{0,30}['\"][A-Za-z0-9_\-]{39}['\"]"},
    {"name": "RSA Private Key",         "severity": "CRITICAL", "pattern": r"-----BEGIN RSA PRIVATE KEY-----"},
    {"name": "Private Key (Generic)",   "severity": "CRITICAL", "pattern": r"-----BEGIN (EC|PGP|DSA|OPENSSH) PRIVATE KEY-----"},
    {"name": "SSH Private Key",         "severity": "CRITICAL", "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----"},
    {"name": "JWT Token",               "severity": "HIGH",     "pattern": r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"},
    {"name": "Basic Auth Credentials",  "severity": "HIGH",     "pattern": r"(?i)(https?://)[a-z0-9_\-]+:[a-z0-9_\-]+@[a-z0-9\-\.]+"},
    {"name": "Generic Password",        "severity": "MEDIUM",   "pattern": r"(?i)(password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]"},
    {"name": "Generic Secret",          "severity": "MEDIUM",   "pattern": r"(?i)(secret|api_secret|app_secret)\s*[:=]\s*['\"][^'\"]{6,}['\"]"},
    {"name": "Generic API Key",         "severity": "MEDIUM",   "pattern": r"(?i)(api_key|apikey|api-key)\s*[:=]\s*['\"][^'\"]{6,}['\"]"},
    {"name": "Database URL",            "severity": "HIGH",     "pattern": r"(?i)(mysql|postgres|mongodb|redis|mssql):\/\/[^\s\"']+"},
    {"name": "Heroku API Key",          "severity": "HIGH",     "pattern": r"[hH]eroku.{0,30}[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}"},
    {"name": "Telegram Bot Token",      "severity": "HIGH",     "pattern": r"[0-9]{8,10}:[a-zA-Z0-9_\-]{35}"},
    {"name": "NPM Token",               "severity": "HIGH",     "pattern": r"npm_[a-zA-Z0-9]{36}"},
    {"name": "Azure Storage Key",       "severity": "CRITICAL", "pattern": r"(?i)AccountKey=[a-zA-Z0-9+/]{86}=="},
    {"name": "PayPal/Braintree Token",  "severity": "CRITICAL", "pattern": r"access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}"},
]

SKIP_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico', '.webp',
    '.mp4', '.mp3', '.wav', '.zip', '.tar', '.gz', '.pdf',
    '.ttf', '.woff', '.woff2', '.eot', '.lock', '.sum',
}

SKIP_FILES = {
    'package-lock.json', 'yarn.lock', 'composer.lock', 'Podfile.lock',
    'Gemfile.lock', 'go.sum', 'cargo.lock',
}

# ─────────────────────────────────────────────
#  DATA CLASSES
# ─────────────────────────────────────────────
@dataclass
class Finding:
    repo_name: str
    file_path: str
    file_url: str
    secret_type: str
    severity: str
    line_number: int
    line_preview: str
    matched_value: str


@dataclass
class ScanResult:
    target: str
    scan_type: str  # 'org', 'user', 'repo'
    started_at: str
    finished_at: str = ""
    repos_scanned: int = 0
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    errors: list = field(default_factory=list)


# ─────────────────────────────────────────────
#  GITHUB API HELPERS
# ─────────────────────────────────────────────
def github_get(url: str, token: Optional[str] = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "GitHubSecretScanner/1.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())


def get_repos(target: str, token: Optional[str] = None) -> list[dict]:
    """Fetch all repos for a user or org."""
    repos = []
    page = 1
    while True:
        url = f"https://api.github.com/users/{target}/repos?per_page=100&page={page}&type=public"
        try:
            data = github_get(url, token)
        except urllib.error.HTTPError as e:
            if e.code == 404:
                # Try org endpoint
                url = f"https://api.github.com/orgs/{target}/repos?per_page=100&page={page}&type=public"
                try:
                    data = github_get(url, token)
                except Exception:
                    break
            else:
                break
        if not data:
            break
        repos.extend(data)
        if len(data) < 100:
            break
        page += 1
    return repos


def get_repo_files(owner: str, repo: str, token: Optional[str] = None, path: str = "") -> list[dict]:
    """Recursively get all files in a repo."""
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    try:
        items = github_get(url, token)
    except Exception:
        return []

    files = []
    if not isinstance(items, list):
        return []

    for item in items:
        if item["type"] == "file":
            files.append(item)
        elif item["type"] == "dir":
            files.extend(get_repo_files(owner, repo, token, item["path"]))
    return files


def get_file_content(file_info: dict, token: Optional[str] = None) -> Optional[str]:
    """Download and decode a file's content."""
    ext = "." + file_info["name"].split(".")[-1] if "." in file_info["name"] else ""
    if ext.lower() in SKIP_EXTENSIONS:
        return None
    if file_info["name"] in SKIP_FILES:
        return None
    if file_info.get("size", 0) > 500_000:  # skip files > 500KB
        return None

    try:
        data = github_get(file_info["url"], token)
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    except Exception:
        return None
    return None


# ─────────────────────────────────────────────
#  SCANNING LOGIC
# ─────────────────────────────────────────────
def scan_content(content: str, repo_name: str, file_path: str, file_url: str) -> list[Finding]:
    findings = []
    lines = content.splitlines()
    for line_num, line in enumerate(lines, 1):
        for pattern_info in SECRET_PATTERNS:
            matches = re.findall(pattern_info["pattern"], line)
            if matches:
                match_val = matches[0] if isinstance(matches[0], str) else matches[0][0]
                # Redact middle of matched value for display
                redacted = redact(match_val)
                preview = line.strip()[:120]
                findings.append(Finding(
                    repo_name=repo_name,
                    file_path=file_path,
                    file_url=file_url,
                    secret_type=pattern_info["name"],
                    severity=pattern_info["severity"],
                    line_number=line_num,
                    line_preview=preview,
                    matched_value=redacted,
                ))
    return findings


def redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]


def scan_repo(owner: str, repo_name: str, token: Optional[str], result: ScanResult):
    print(f"  📂 Scanning {owner}/{repo_name}...")
    files = get_repo_files(owner, repo_name, token)
    for f in files:
        content = get_file_content(f, token)
        if content is None:
            continue
        result.files_scanned += 1
        html_url = f.get("html_url", f.get("url", ""))
        findings = scan_content(content, f"{owner}/{repo_name}", f["path"], html_url)
        result.findings.extend(findings)
        if findings:
            for finding in findings:
                sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(finding.severity, "🔵")
                print(f"    {sev_icon} [{finding.severity}] {finding.secret_type} in {finding.file_path}:{finding.line_number}")
    result.repos_scanned += 1


# ─────────────────────────────────────────────
#  REPORT GENERATION
# ─────────────────────────────────────────────
def generate_html_report(result: ScanResult) -> str:
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    sorted_findings = sorted(result.findings, key=lambda f: severity_order.get(f.severity, 9))

    critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
    high     = sum(1 for f in result.findings if f.severity == "HIGH")
    medium   = sum(1 for f in result.findings if f.severity == "MEDIUM")

    risk_level = "CRITICAL" if critical > 0 else "HIGH" if high > 0 else "MEDIUM" if medium > 0 else "CLEAN"
    risk_color = {"CRITICAL": "#ff2d55", "HIGH": "#ff6b35", "MEDIUM": "#ffd60a", "CLEAN": "#30d158"}[risk_level]

    rows = ""
    for f in sorted_findings:
        sev_class = f.severity.lower()
        rows += f"""
        <tr>
            <td><span class="badge {sev_class}">{f.severity}</span></td>
            <td>{f.secret_type}</td>
            <td class="mono">{f.repo_name}</td>
            <td><a href="{f.file_url}" target="_blank" class="file-link">{f.file_path}</a></td>
            <td class="mono center">{f.line_number}</td>
            <td class="mono truncate" title="{f.line_preview}">{f.line_preview}</td>
        </tr>"""

    if not sorted_findings:
        rows = '<tr><td colspan="6" class="empty">✅ No secrets detected</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1.0"/>
<title>Secret Scan Report — {result.target}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:       #0a0a0f;
    --surface:  #111118;
    --border:   #1e1e2e;
    --text:     #e2e2f0;
    --muted:    #6e6e8a;
    --accent:   #7c6aff;
    --critical: #ff2d55;
    --high:     #ff6b35;
    --medium:   #ffd60a;
    --low:      #30d158;
  }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: 'Inter', sans-serif;
    font-size: 14px;
    line-height: 1.6;
    min-height: 100vh;
  }}

  /* ── HEADER ── */
  header {{
    border-bottom: 1px solid var(--border);
    padding: 28px 40px;
    display: flex;
    align-items: center;
    justify-content: space-between;
    background: var(--surface);
  }}
  .logo {{
    display: flex;
    align-items: center;
    gap: 12px;
  }}
  .logo-icon {{
    width: 36px; height: 36px;
    background: var(--accent);
    border-radius: 8px;
    display: flex; align-items: center; justify-content: center;
    font-size: 18px;
  }}
  .logo-text {{
    font-size: 16px;
    font-weight: 600;
    letter-spacing: -0.3px;
  }}
  .logo-sub {{
    font-size: 11px;
    color: var(--muted);
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}
  .header-meta {{
    text-align: right;
    color: var(--muted);
    font-size: 12px;
  }}
  .header-meta strong {{
    color: var(--text);
    display: block;
    font-size: 14px;
    margin-bottom: 2px;
  }}

  /* ── MAIN ── */
  main {{ padding: 36px 40px; max-width: 1400px; margin: 0 auto; }}

  /* ── RISK BANNER ── */
  .risk-banner {{
    border: 1px solid {risk_color}33;
    background: {risk_color}0d;
    border-radius: 12px;
    padding: 20px 28px;
    display: flex;
    align-items: center;
    gap: 20px;
    margin-bottom: 32px;
  }}
  .risk-dot {{
    width: 14px; height: 14px;
    border-radius: 50%;
    background: {risk_color};
    box-shadow: 0 0 12px {risk_color};
    flex-shrink: 0;
  }}
  .risk-label {{
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--muted);
  }}
  .risk-value {{
    font-size: 22px;
    font-weight: 700;
    color: {risk_color};
    letter-spacing: -0.5px;
  }}
  .risk-target {{
    margin-left: auto;
    font-family: 'JetBrains Mono', monospace;
    color: var(--muted);
    font-size: 13px;
  }}

  /* ── STATS GRID ── */
  .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 16px; margin-bottom: 36px; }}
  .stat-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px 24px;
  }}
  .stat-label {{ font-size: 11px; text-transform: uppercase; letter-spacing: 0.8px; color: var(--muted); margin-bottom: 8px; }}
  .stat-value {{ font-size: 32px; font-weight: 700; letter-spacing: -1px; font-family: 'JetBrains Mono', monospace; }}
  .stat-value.critical {{ color: var(--critical); }}
  .stat-value.high     {{ color: var(--high); }}
  .stat-value.medium   {{ color: var(--medium); }}
  .stat-value.neutral  {{ color: var(--text); }}

  /* ── TABLE ── */
  .table-header {{
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin-bottom: 16px;
  }}
  .table-title {{ font-size: 16px; font-weight: 600; }}
  .finding-count {{
    background: var(--accent)22;
    color: var(--accent);
    border: 1px solid var(--accent)44;
    padding: 4px 12px;
    border-radius: 20px;
    font-size: 12px;
    font-weight: 600;
  }}

  .table-wrap {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; }}
  thead th {{
    background: #0d0d14;
    padding: 12px 16px;
    text-align: left;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.8px;
    color: var(--muted);
    font-weight: 500;
    border-bottom: 1px solid var(--border);
  }}
  thead th.center {{ text-align: center; }}
  tbody tr {{ border-bottom: 1px solid var(--border); transition: background 0.15s; }}
  tbody tr:last-child {{ border-bottom: none; }}
  tbody tr:hover {{ background: #ffffff06; }}
  td {{ padding: 12px 16px; vertical-align: top; }}
  td.mono {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; }}
  td.center {{ text-align: center; }}
  td.truncate {{ max-width: 280px; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }}
  td.empty {{ text-align: center; padding: 48px; color: var(--low); font-size: 15px; }}

  .badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 5px;
    font-size: 11px;
    font-weight: 700;
    letter-spacing: 0.5px;
    text-transform: uppercase;
  }}
  .badge.critical {{ background: var(--critical)22; color: var(--critical); border: 1px solid var(--critical)44; }}
  .badge.high     {{ background: var(--high)22;     color: var(--high);     border: 1px solid var(--high)44; }}
  .badge.medium   {{ background: var(--medium)22;   color: var(--medium);   border: 1px solid var(--medium)44; }}
  .badge.low      {{ background: var(--low)22;      color: var(--low);      border: 1px solid var(--low)44; }}

  .file-link {{ color: var(--accent); text-decoration: none; font-size: 12px; font-family: 'JetBrains Mono', monospace; }}
  .file-link:hover {{ text-decoration: underline; }}

  /* ── FOOTER ── */
  footer {{
    text-align: center;
    padding: 32px 40px;
    color: var(--muted);
    font-size: 12px;
    border-top: 1px solid var(--border);
    margin-top: 48px;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}
</style>
</head>
<body>

<header>
  <div class="logo">
    <div class="logo-icon">🔍</div>
    <div>
      <div class="logo-text">GitSecScan</div>
      <div class="logo-sub">Secret Leakage Scanner</div>
    </div>
  </div>
  <div class="header-meta">
    <strong>{result.target}</strong>
    Scanned {result.started_at}
  </div>
</header>

<main>

  <div class="risk-banner">
    <div class="risk-dot"></div>
    <div>
      <div class="risk-label">Overall Risk Level</div>
      <div class="risk-value">{risk_level}</div>
    </div>
    <div class="risk-target">
      {result.repos_scanned} repos · {result.files_scanned} files · {len(result.findings)} findings
    </div>
  </div>

  <div class="stats">
    <div class="stat-card">
      <div class="stat-label">Critical</div>
      <div class="stat-value critical">{critical}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">High</div>
      <div class="stat-value high">{high}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Medium</div>
      <div class="stat-value medium">{medium}</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Files Scanned</div>
      <div class="stat-value neutral">{result.files_scanned}</div>
    </div>
  </div>

  <div class="table-header">
    <div class="table-title">Findings</div>
    <div class="finding-count">{len(result.findings)} secrets detected</div>
  </div>

  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th>
          <th>Secret Type</th>
          <th>Repository</th>
          <th>File</th>
          <th class="center">Line</th>
          <th>Preview</th>
        </tr>
      </thead>
      <tbody>
        {rows}
      </tbody>
    </table>
  </div>

</main>

<footer>
  Generated by <a href="https://github.com/Brainrotshiva/github-secret-scanner" target="_blank">GitSecScan</a>
  by <a href="https://github.com/Brainrotshiva" target="_blank">Brainrotshiva</a> ·
  For responsible disclosure only · {result.finished_at}
</footer>

</body>
</html>"""


# ─────────────────────────────────────────────
#  CLI ENTRYPOINT
# ─────────────────────────────────────────────
def parse_repo_url(url: str) -> tuple[str, str]:
    """Extract owner and repo name from a GitHub URL."""
    url = url.rstrip("/").replace("https://github.com/", "")
    parts = url.split("/")
    if len(parts) < 2:
        raise ValueError(f"Invalid repo URL: {url}")
    return parts[0], parts[1]


def main():
    parser = argparse.ArgumentParser(
        description="🔍 GitSecScan — GitHub Secret Leakage Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./scanner.py --org netflix
  ./scanner.py --user torvalds
  ./scanner.py --repo https://github.com/target/repo
  ./scanner.py --org mycompany --token ghp_xxxx --output report.html

First time setup:
  chmod +x scanner.py
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--org",  metavar="NAME", help="Scan all public repos of a GitHub organization")
    group.add_argument("--user", metavar="NAME", help="Scan all public repos of a GitHub user")
    group.add_argument("--repo", metavar="URL",  help="Scan a single GitHub repository")

    parser.add_argument("--token",  metavar="TOKEN", help="GitHub personal access token (avoids rate limits)")
    parser.add_argument("--output", metavar="FILE",  default="report.html", help="Output HTML report path (default: report.html)")
    parser.add_argument("--json",   metavar="FILE",  help="Also export findings as JSON")

    args = parser.parse_args()

    token = args.token

    print("\n🔍 GitSecScan — GitHub Secret Leakage Scanner")
    print("=" * 50)

    result = ScanResult(
        target=args.org or args.user or args.repo,
        scan_type="org" if args.org else "user" if args.user else "repo",
        started_at=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    )

    try:
        if args.repo:
            owner, repo_name = parse_repo_url(args.repo)
            scan_repo(owner, repo_name, token, result)
        else:
            target = args.org or args.user
            print(f"📡 Fetching repos for: {target}")
            repos = get_repos(target, token)
            if not repos:
                print("❌ No repos found or invalid target.")
                sys.exit(1)
            print(f"✅ Found {len(repos)} public repos\n")
            for repo in repos:
                scan_repo(repo["owner"]["login"], repo["name"], token, result)

    except KeyboardInterrupt:
        print("\n⚠️  Scan interrupted by user.")

    result.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Summary ──
    print("\n" + "=" * 50)
    print(f"📊 SCAN COMPLETE")
    print(f"   Repos scanned : {result.repos_scanned}")
    print(f"   Files scanned : {result.files_scanned}")
    print(f"   Total findings: {len(result.findings)}")
    critical = sum(1 for f in result.findings if f.severity == "CRITICAL")
    high     = sum(1 for f in result.findings if f.severity == "HIGH")
    medium   = sum(1 for f in result.findings if f.severity == "MEDIUM")
    if critical: print(f"   🔴 Critical   : {critical}")
    if high:     print(f"   🟠 High       : {high}")
    if medium:   print(f"   🟡 Medium     : {medium}")

    # ── HTML Report ──
    html = generate_html_report(result)
    with open(args.output, "w", encoding="utf-8") as fh:
        fh.write(html)
    print(f"\n📄 HTML report saved → {args.output}")

    # ── JSON Export ──
    if args.json:
        import dataclasses
        with open(args.json, "w", encoding="utf-8") as fh:
            json.dump({
                "target": result.target,
                "scan_type": result.scan_type,
                "started_at": result.started_at,
                "finished_at": result.finished_at,
                "stats": {
                    "repos_scanned": result.repos_scanned,
                    "files_scanned": result.files_scanned,
                    "total_findings": len(result.findings),
                    "critical": critical, "high": high, "medium": medium,
                },
                "findings": [dataclasses.asdict(f) for f in result.findings],
            }, fh, indent=2)
        print(f"📦 JSON export saved  → {args.json}")

    print()


if __name__ == "__main__":
    main()
