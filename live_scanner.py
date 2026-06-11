#!/usr/bin/env python3
"""
GitSecScan — Live Dashboard
Author: Badam Shiva Sai (Brainrotshiva)
GitHub: https://github.com/Brainrotshiva

Run: ./live_scanner.py --org netflix
Then open: http://localhost:8765 in your browser
"""

import re
import sys
import json
import base64
import asyncio
import argparse
import webbrowser
import urllib.request
import urllib.error
import threading
from datetime import datetime
from dataclasses import dataclass, field, asdict
from typing import Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

try:
    import websockets
except ImportError:
    print("❌ Missing dependency. Run: pip install websockets")
    sys.exit(1)

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
class ScanState:
    target: str = ""
    status: str = "idle"       # idle | scanning | done | error
    current_repo: str = ""
    repos_total: int = 0
    repos_scanned: int = 0
    files_scanned: int = 0
    findings: list = field(default_factory=list)
    started_at: str = ""
    finished_at: str = ""

# Global state + connected WebSocket clients
state = ScanState()
clients: set = set()

# ─────────────────────────────────────────────
#  BROADCAST
# ─────────────────────────────────────────────
def broadcast(event: str, data: dict):
    """Send a message to all connected browser clients."""
    if not clients:
        return
    msg = json.dumps({"event": event, "data": data})
    # Schedule in the event loop
    loop = asyncio.get_event_loop()
    asyncio.run_coroutine_threadsafe(_broadcast(msg), loop)

async def _broadcast(msg: str):
    dead = set()
    for ws in clients:
        try:
            await ws.send(msg)
        except Exception:
            dead.add(ws)
    clients.difference_update(dead)

# ─────────────────────────────────────────────
#  GITHUB HELPERS
# ─────────────────────────────────────────────
def github_get(url: str, token: Optional[str] = None) -> dict:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github.v3+json")
    req.add_header("User-Agent", "GitSecScan/2.0")
    if token:
        req.add_header("Authorization", f"token {token}")
    with urllib.request.urlopen(req, timeout=15) as resp:
        return json.loads(resp.read().decode())

def get_repos(target: str, token: Optional[str] = None) -> list:
    repos, page = [], 1
    while True:
        url = f"https://api.github.com/users/{target}/repos?per_page=100&page={page}&type=public"
        try:
            data = github_get(url, token)
        except urllib.error.HTTPError as e:
            if e.code == 404:
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

def get_repo_files(owner: str, repo: str, token: Optional[str] = None, path: str = "") -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    try:
        items = github_get(url, token)
    except Exception:
        return []
    if not isinstance(items, list):
        return []
    files = []
    for item in items:
        if item["type"] == "file":
            files.append(item)
        elif item["type"] == "dir":
            files.extend(get_repo_files(owner, repo, token, item["path"]))
    return files

def get_file_content(file_info: dict, token: Optional[str] = None) -> Optional[str]:
    ext = "." + file_info["name"].split(".")[-1] if "." in file_info["name"] else ""
    if ext.lower() in SKIP_EXTENSIONS or file_info["name"] in SKIP_FILES:
        return None
    if file_info.get("size", 0) > 500_000:
        return None
    try:
        data = github_get(file_info["url"], token)
        if data.get("encoding") == "base64":
            return base64.b64decode(data["content"]).decode("utf-8", errors="ignore")
    except Exception:
        return None

def redact(value: str) -> str:
    if len(value) <= 8:
        return "****"
    return value[:4] + "*" * (len(value) - 8) + value[-4:]

def scan_content(content: str, repo_name: str, file_path: str, file_url: str) -> list:
    findings = []
    for line_num, line in enumerate(content.splitlines(), 1):
        for p in SECRET_PATTERNS:
            matches = re.findall(p["pattern"], line)
            if matches:
                match_val = matches[0] if isinstance(matches[0], str) else matches[0][0]
                findings.append(Finding(
                    repo_name=repo_name,
                    file_path=file_path,
                    file_url=file_url,
                    secret_type=p["name"],
                    severity=p["severity"],
                    line_number=line_num,
                    line_preview=line.strip()[:120],
                    matched_value=redact(match_val),
                ))
    return findings

# ─────────────────────────────────────────────
#  SCAN RUNNER (runs in a background thread)
# ─────────────────────────────────────────────
def run_scan(target: str, scan_type: str, token: Optional[str]):
    global state
    state.target = target
    state.status = "scanning"
    state.started_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    state.findings = []
    state.files_scanned = 0
    state.repos_scanned = 0

    broadcast("status", {"status": "scanning", "target": target, "started_at": state.started_at})

    try:
        if scan_type == "repo":
            url = target.rstrip("/").replace("https://github.com/", "")
            parts = url.split("/")
            owner, repo_name = parts[0], parts[1]
            repos = [{"owner": {"login": owner}, "name": repo_name}]
        else:
            print(f"📡 Fetching repos for: {target}")
            repos = get_repos(target, token)

        state.repos_total = len(repos)
        broadcast("repos_found", {"count": len(repos)})
        print(f"✅ Found {len(repos)} repos\n")

        for repo in repos:
            owner = repo["owner"]["login"]
            repo_name = repo["name"]
            full_name = f"{owner}/{repo_name}"
            state.current_repo = full_name

            broadcast("repo_start", {"repo": full_name})
            print(f"  📂 Scanning {full_name}...")

            files = get_repo_files(owner, repo_name, token)
            for f in files:
                content = get_file_content(f, token)
                if content is None:
                    continue
                state.files_scanned += 1
                html_url = f.get("html_url", f.get("url", ""))
                new_findings = scan_content(content, full_name, f["path"], html_url)
                for finding in new_findings:
                    state.findings.append(finding)
                    sev_icon = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(finding.severity, "🔵")
                    print(f"    {sev_icon} [{finding.severity}] {finding.secret_type} in {finding.file_path}:{finding.line_number}")
                    # Push each finding live to browser
                    broadcast("finding", asdict(finding))

            state.repos_scanned += 1
            broadcast("repo_done", {
                "repo": full_name,
                "repos_scanned": state.repos_scanned,
                "repos_total": state.repos_total,
                "files_scanned": state.files_scanned,
                "total_findings": len(state.findings),
            })

    except Exception as e:
        state.status = "error"
        broadcast("error", {"message": str(e)})
        print(f"❌ Error: {e}")
        return

    state.status = "done"
    state.finished_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    critical = sum(1 for f in state.findings if f.severity == "CRITICAL")
    high     = sum(1 for f in state.findings if f.severity == "HIGH")
    medium   = sum(1 for f in state.findings if f.severity == "MEDIUM")

    broadcast("done", {
        "repos_scanned": state.repos_scanned,
        "files_scanned": state.files_scanned,
        "total_findings": len(state.findings),
        "critical": critical,
        "high": high,
        "medium": medium,
        "finished_at": state.finished_at,
    })

    print(f"\n✅ Scan complete — {len(state.findings)} findings")

# ─────────────────────────────────────────────
#  WEBSOCKET SERVER
# ─────────────────────────────────────────────
async def ws_handler(websocket):
    clients.add(websocket)
    print(f"🌐 Browser connected ({len(clients)} client(s))")
    # Send current state immediately on connect
    await websocket.send(json.dumps({"event": "state", "data": {
        "status": state.status,
        "target": state.target,
        "repos_total": state.repos_total,
        "repos_scanned": state.repos_scanned,
        "files_scanned": state.files_scanned,
        "findings": [asdict(f) for f in state.findings],
        "started_at": state.started_at,
        "finished_at": state.finished_at,
    }}))
    try:
        async for _ in websocket:
            pass
    finally:
        clients.discard(websocket)

# ─────────────────────────────────────────────
#  HTTP SERVER (serves the dashboard HTML)
# ─────────────────────────────────────────────
DASHBOARD_HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>GitSecScan — Live Dashboard</title>
<style>
@import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Inter:wght@300;400;500;600;700&display=swap');
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#0a0a0f;--surface:#111118;--border:#1e1e2e;
  --text:#e2e2f0;--muted:#6e6e8a;--accent:#7c6aff;
  --critical:#ff2d55;--high:#ff6b35;--medium:#ffd60a;--low:#30d158;
}
body{background:var(--bg);color:var(--text);font-family:'Inter',sans-serif;font-size:14px;min-height:100vh}

/* HEADER */
header{border-bottom:1px solid var(--border);padding:20px 36px;display:flex;align-items:center;justify-content:space-between;background:var(--surface)}
.logo{display:flex;align-items:center;gap:12px}
.logo-icon{width:34px;height:34px;background:var(--accent);border-radius:8px;display:flex;align-items:center;justify-content:center;font-size:16px}
.logo-text{font-size:15px;font-weight:600}
.logo-sub{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.5px}
.conn-badge{padding:4px 12px;border-radius:20px;font-size:11px;font-weight:600;border:1px solid}
.conn-badge.connected{background:var(--low)15;color:var(--low);border-color:var(--low)44}
.conn-badge.disconnected{background:var(--critical)15;color:var(--critical);border-color:var(--critical)44}

/* MAIN */
main{padding:28px 36px;max-width:1400px;margin:0 auto}

/* STATUS BAR */
.status-bar{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 24px;margin-bottom:24px;display:flex;align-items:center;gap:20px}
.pulse{width:10px;height:10px;border-radius:50%;background:var(--muted);flex-shrink:0}
.pulse.scanning{background:var(--accent);animation:pulse 1.2s infinite}
.pulse.done{background:var(--low)}
.pulse.error{background:var(--critical)}
@keyframes pulse{0%,100%{opacity:1;transform:scale(1)}50%{opacity:.5;transform:scale(1.3)}}
.status-text{font-size:13px;color:var(--muted)}
.status-text strong{color:var(--text)}
.progress-wrap{margin-left:auto;display:flex;align-items:center;gap:12px;font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace}

/* STATS */
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:24px}
.stat{background:var(--surface);border:1px solid var(--border);border-radius:10px;padding:18px 20px}
.stat-label{font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);margin-bottom:6px}
.stat-value{font-size:28px;font-weight:700;font-family:'JetBrains Mono',monospace;letter-spacing:-1px}
.stat-value.c{color:var(--critical)}.stat-value.h{color:var(--high)}.stat-value.m{color:var(--medium)}.stat-value.n{color:var(--text)}

/* CURRENT REPO */
.current-repo{background:var(--accent)0d;border:1px solid var(--accent)33;border-radius:8px;padding:10px 18px;margin-bottom:20px;font-size:12px;color:var(--muted);font-family:'JetBrains Mono',monospace;display:none}
.current-repo span{color:var(--accent)}

/* TABLE */
.table-header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
.table-title{font-size:15px;font-weight:600}
.badge-count{background:var(--accent)22;color:var(--accent);border:1px solid var(--accent)44;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:600}
.table-wrap{background:var(--surface);border:1px solid var(--border);border-radius:12px;overflow:hidden}
table{width:100%;border-collapse:collapse}
thead th{background:#0d0d14;padding:10px 14px;text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.8px;color:var(--muted);font-weight:500;border-bottom:1px solid var(--border)}
tbody tr{border-bottom:1px solid var(--border);animation:fadeIn .3s ease}
tbody tr:last-child{border-bottom:none}
tbody tr:hover{background:#ffffff06}
@keyframes fadeIn{from{opacity:0;transform:translateY(-4px)}to{opacity:1;transform:translateY(0)}}
td{padding:10px 14px;vertical-align:top}
td.mono{font-family:'JetBrains Mono',monospace;font-size:11px}
td.trunc{max-width:260px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis}
td.empty{text-align:center;padding:48px;color:var(--muted);font-size:13px}
.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-size:10px;font-weight:700;letter-spacing:.5px;text-transform:uppercase}
.badge.critical{background:var(--critical)22;color:var(--critical);border:1px solid var(--critical)44}
.badge.high{background:var(--high)22;color:var(--high);border:1px solid var(--high)44}
.badge.medium{background:var(--medium)22;color:var(--medium);border:1px solid var(--medium)44}
.file-link{color:var(--accent);text-decoration:none;font-size:11px;font-family:'JetBrains Mono',monospace}
.file-link:hover{text-decoration:underline}

/* PROGRESS BAR */
.progress-bar-wrap{background:var(--border);border-radius:4px;height:3px;overflow:hidden;margin-top:8px}
.progress-bar{height:100%;background:var(--accent);transition:width .4s ease;width:0}

footer{text-align:center;padding:24px;color:var(--muted);font-size:11px;border-top:1px solid var(--border);margin-top:40px}
footer a{color:var(--accent);text-decoration:none}
</style>
</head>
<body>
<header>
  <div class="logo">
    <div class="logo-icon">🔍</div>
    <div>
      <div class="logo-text">GitSecScan</div>
      <div class="logo-sub">Live Dashboard</div>
    </div>
  </div>
  <span id="connBadge" class="conn-badge disconnected">● Connecting...</span>
</header>

<main>
  <div class="status-bar">
    <div id="pulse" class="pulse"></div>
    <div class="status-text" id="statusText"><strong>Waiting</strong> — open a scan from terminal</div>
    <div class="progress-wrap">
      <span id="repoProgress">0 / 0 repos</span>
      <span>·</span>
      <span id="filesCount">0 files</span>
    </div>
  </div>
  <div class="progress-bar-wrap"><div class="progress-bar" id="progressBar"></div></div>
  <br/>

  <div class="current-repo" id="currentRepo">Scanning: <span id="currentRepoName">—</span></div>

  <div class="stats">
    <div class="stat"><div class="stat-label">Critical</div><div class="stat-value c" id="sCritical">0</div></div>
    <div class="stat"><div class="stat-label">High</div><div class="stat-value h" id="sHigh">0</div></div>
    <div class="stat"><div class="stat-label">Medium</div><div class="stat-value m" id="sMedium">0</div></div>
    <div class="stat"><div class="stat-label">Files Scanned</div><div class="stat-value n" id="sFiles">0</div></div>
  </div>

  <div class="table-header">
    <div class="table-title">Live Findings</div>
    <div class="badge-count" id="findingCount">0 secrets</div>
  </div>
  <div class="table-wrap">
    <table>
      <thead>
        <tr>
          <th>Severity</th><th>Secret Type</th><th>Repository</th>
          <th>File</th><th>Line</th><th>Preview</th>
        </tr>
      </thead>
      <tbody id="tbody">
        <tr><td colspan="6" class="empty" id="emptyRow">⏳ Waiting for scan to start...</td></tr>
      </tbody>
    </table>
  </div>
</main>

<footer>
  <a href="https://github.com/Brainrotshiva/github-secret-scanner" target="_blank">GitSecScan</a>
  by <a href="https://github.com/Brainrotshiva" target="_blank">Brainrotshiva</a>
  — For responsible disclosure only
</footer>

<script>
let ws, findings = [], critical = 0, high = 0, medium = 0;
const SEV = {CRITICAL:'critical', HIGH:'high', MEDIUM:'medium', LOW:'low'};

function connect() {
  ws = new WebSocket('ws://localhost:8766');

  ws.onopen = () => {
    document.getElementById('connBadge').className = 'conn-badge connected';
    document.getElementById('connBadge').textContent = '● Live';
  };

  ws.onclose = () => {
    document.getElementById('connBadge').className = 'conn-badge disconnected';
    document.getElementById('connBadge').textContent = '● Disconnected';
    setTimeout(connect, 2000);
  };

  ws.onmessage = (e) => {
    const {event, data} = JSON.parse(e.data);
    handle(event, data);
  };
}

function handle(event, data) {
  const pulse = document.getElementById('pulse');
  const statusText = document.getElementById('statusText');

  if (event === 'state') {
    // Restore full state on reconnect
    findings = data.findings || [];
    findings.forEach(f => addRow(f, false));
    updateStats();
    if (data.status === 'scanning') {
      pulse.className = 'pulse scanning';
      statusText.innerHTML = `<strong>Scanning</strong> — ${data.target}`;
    } else if (data.status === 'done') {
      pulse.className = 'pulse done';
      statusText.innerHTML = `<strong>Done</strong> — ${data.target} · ${data.finished_at}`;
    }
    updateProgress(data.repos_scanned, data.repos_total, data.files_scanned);
  }

  else if (event === 'status') {
    pulse.className = 'pulse scanning';
    statusText.innerHTML = `<strong>Scanning</strong> — ${data.target}`;
    document.getElementById('currentRepo').style.display = 'block';
  }

  else if (event === 'repos_found') {
    document.getElementById('repoProgress').textContent = `0 / ${data.count} repos`;
  }

  else if (event === 'repo_start') {
    document.getElementById('currentRepoName').textContent = data.repo;
  }

  else if (event === 'repo_done') {
    updateProgress(data.repos_scanned, data.repos_total, data.files_scanned);
  }

  else if (event === 'finding') {
    findings.push(data);
    addRow(data, true);
    updateStats();
  }

  else if (event === 'done') {
    pulse.className = 'pulse done';
    statusText.innerHTML = `<strong>✅ Scan Complete</strong> — ${data.total_findings} secrets found · ${data.finished_at}`;
    document.getElementById('currentRepo').style.display = 'none';
    updateProgress(data.repos_scanned, data.repos_scanned, data.files_scanned);
  }

  else if (event === 'error') {
    pulse.className = 'pulse error';
    statusText.innerHTML = `<strong>❌ Error</strong> — ${data.message}`;
  }
}

function addRow(f, animate) {
  const tbody = document.getElementById('tbody');
  const empty = document.getElementById('emptyRow');
  if (empty) empty.remove();

  const tr = document.createElement('tr');
  if (!animate) tr.style.animation = 'none';
  tr.innerHTML = `
    <td><span class="badge ${SEV[f.severity] || 'low'}">${f.severity}</span></td>
    <td>${f.secret_type}</td>
    <td class="mono">${f.repo_name}</td>
    <td><a href="${f.file_url}" target="_blank" class="file-link">${f.file_path}</a></td>
    <td class="mono" style="text-align:center">${f.line_number}</td>
    <td class="mono trunc" title="${f.line_preview}">${f.line_preview}</td>
  `;
  tbody.insertBefore(tr, tbody.firstChild);
}

function updateStats() {
  critical = findings.filter(f => f.severity === 'CRITICAL').length;
  high     = findings.filter(f => f.severity === 'HIGH').length;
  medium   = findings.filter(f => f.severity === 'MEDIUM').length;
  document.getElementById('sCritical').textContent = critical;
  document.getElementById('sHigh').textContent = high;
  document.getElementById('sMedium').textContent = medium;
  document.getElementById('findingCount').textContent = `${findings.length} secret${findings.length !== 1 ? 's' : ''}`;
}

function updateProgress(scanned, total, files) {
  document.getElementById('repoProgress').textContent = `${scanned} / ${total} repos`;
  document.getElementById('filesCount').textContent = `${files} files`;
  document.getElementById('sFiles').textContent = files;
  const pct = total > 0 ? (scanned / total) * 100 : 0;
  document.getElementById('progressBar').style.width = pct + '%';
}

connect();
</script>
</body>
</html>"""

class DashboardHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()
        self.wfile.write(DASHBOARD_HTML.encode())

    def log_message(self, *args):
        pass  # Silence HTTP logs

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────
async def start_ws_server():
    async with websockets.serve(ws_handler, "localhost", 8766):
        print("✅ WebSocket server running on ws://localhost:8766")
        await asyncio.Future()  # run forever

def start_http_server():
    server = HTTPServer(("localhost", 8765), DashboardHandler)
    print("✅ Dashboard running on http://localhost:8765")
    server.serve_forever()

def main():
    parser = argparse.ArgumentParser(
        description="🔍 GitSecScan — Live Dashboard Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ./live_scanner.py --org netflix
  ./live_scanner.py --user torvalds
  ./live_scanner.py --repo https://github.com/target/repo
  ./live_scanner.py --org mycompany --token ghp_xxxx

First time setup:
  chmod +x live_scanner.py
        """
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--org",  metavar="NAME", help="Scan all public repos of a GitHub organization")
    group.add_argument("--user", metavar="NAME", help="Scan all public repos of a GitHub user")
    group.add_argument("--repo", metavar="URL",  help="Scan a single GitHub repository")
    parser.add_argument("--token", metavar="TOKEN", help="GitHub personal access token")
    parser.add_argument("--no-browser", action="store_true", help="Don't auto-open browser")

    args = parser.parse_args()

    target    = args.org or args.user or args.repo
    scan_type = "org" if args.org else "user" if args.user else "repo"

    print("\n🔍 GitSecScan — Live Dashboard")
    print("=" * 45)

    # Start HTTP server (serves dashboard) in background thread
    t_http = threading.Thread(target=start_http_server, daemon=True)
    t_http.start()

    # Start scan in background thread
    def start_scan():
        import time; time.sleep(1.5)  # Let servers start first
        run_scan(target, scan_type, args.token)

    t_scan = threading.Thread(target=start_scan, daemon=True)

    # Open browser
    if not args.no_browser:
        import time; time.sleep(0.5)
        webbrowser.open("http://localhost:8765")
        print("🌐 Opening browser → http://localhost:8765")

    t_scan.start()

    # Run WebSocket server (blocks forever)
    print("=" * 45)
    print(f"🎯 Target : {target}")
    print(f"📡 Type   : {scan_type}")
    print("=" * 45 + "\n")

    try:
        asyncio.run(start_ws_server())
    except KeyboardInterrupt:
        print("\n⚠️  Stopped.")

if __name__ == "__main__":
    main()
