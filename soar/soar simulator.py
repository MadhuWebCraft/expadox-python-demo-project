"""
ShieldFlow SOAR Simulator
=========================
Reads SARIF files from ./sarif-reports/ and prints TheHive-style alerts
to the terminal. Simulates ingestion, enrichment, deduplication, and
playbook execution without needing a real TheHive instance.
 
Usage:
    python soar_simulator.py                    # scans ./sarif-reports/
    python soar_simulator.py --dir /path/to/    # custom SARIF directory
    python soar_simulator.py --json             # also dump alerts as JSON
    python soar_simulator.py --slack            # also send Slack summary
"""
 
import argparse
import glob
import hashlib
import json
import os
import sys
from datetime import datetime, timezone
 
# ── optional: real Slack notifications ─────────────────────────────────
try:
    import urllib.request
    SLACK_AVAILABLE = True
except ImportError:
    SLACK_AVAILABLE = False
 
# ── terminal colours (no external deps) ────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
YELLOW = "\033[93m"
CYAN   = "\033[96m"
GREEN  = "\033[92m"
GREY   = "\033[90m"
PURPLE = "\033[95m"
WHITE  = "\033[97m"
 
SEV_COLOUR = {
    "CRITICAL": RED + BOLD,
    "HIGH":     YELLOW + BOLD,
    "MEDIUM":   CYAN,
    "LOW":      GREEN,
    "INFO":     GREY,
}
 
SEV_ICON = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
    "INFO":     "⚪",
}
 
PLAYBOOK_RULES = {
    # rule_id fragment → playbook name
    "aws-access-token":  "PB-01 · Secret exposed",
    "google-api-key":    "PB-01 · Secret exposed",
    "github-token":      "PB-01 · Secret exposed",
    "private-key":       "PB-01 · Secret exposed",
    "CVE-":              "PB-02 · Critical CVE",
    "sqli":              "PB-03 · OWASP Top 10 flaw",
    "xss":               "PB-03 · OWASP Top 10 flaw",
    "injection":         "PB-03 · OWASP Top 10 flaw",
    "ZAP-":              "PB-03 · OWASP Top 10 flaw",
}
 
SARIF_LEVEL = {"error": 3, "warning": 2, "note": 1, "none": 0}
 
 
# ── helpers ────────────────────────────────────────────────────────────
 
def colour(text, col):
    return f"{col}{text}{RESET}"
 
def make_source_ref(tool: str, rule_id: str, uri: str, line: int) -> str:
    """Stable dedup key — same finding across reruns = same ref."""
    raw = f"{tool}:{rule_id}:{uri}:{line}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]
 
def classify_severity(result: dict, rule: dict) -> str:
    """
    Map a SARIF result to CRITICAL / HIGH / MEDIUM / LOW / INFO.
    Reads tool-specific properties first (most accurate), then falls
    back to the generic SARIF level field.
    """
    # 1. Trivy embeds CVSS float in rule properties
    try:
        cvss = float(rule.get("properties", {}).get("security-severity", ""))
        if cvss >= 9.0:
            return "CRITICAL"
        if cvss >= 7.0:
            return "HIGH"
        if cvss >= 4.0:
            return "MEDIUM"
        return "LOW"
    except (ValueError, TypeError):
        pass
 
    # 2. Semgrep / Gitleaks embed severity string in properties
    sev_str = (
        result.get("properties", {}).get("severity", "") or
        rule.get("properties", {}).get("severity", "")
    ).upper()
    if sev_str in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        return sev_str
 
    # 3. Fall back to SARIF level
    level = result.get("level", "note")
    rule_level = rule.get("defaultConfiguration", {}).get("level", level)
    effective = max(
        SARIF_LEVEL.get(level, 0),
        SARIF_LEVEL.get(rule_level, 0),
    )
    return {3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}.get(effective, "INFO")
 
def pick_playbook(rule_id: str, severity: str) -> str | None:
    for fragment, name in PLAYBOOK_RULES.items():
        if fragment.lower() in rule_id.lower():
            return name
    if severity == "CRITICAL":
        return "PB-02 · Critical CVE"
    return None
 
 
# ── SARIF parser ───────────────────────────────────────────────────────
 
def parse_sarif_dir(directory: str) -> list[dict]:
    """Load all *.sarif files from directory and return flat list of findings."""
    findings = []
    files = sorted(glob.glob(os.path.join(directory, "*.sarif")))
    if not files:
        print(colour(f"\n  No SARIF files found in {directory}\n", GREY))
        return findings
 
    for fpath in files:
        try:
            with open(fpath) as f:
                sarif = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(colour(f"  ⚠  Could not read {fpath}: {e}", YELLOW))
            continue
 
        for run in sarif.get("runs", []):
            tool = run.get("tool", {}).get("driver", {}).get("name", "Unknown")
            rules_index = {
                r["id"]: r
                for r in run.get("tool", {}).get("driver", {}).get("rules", [])
            }
            for result in run.get("results", []):
                rule_id = result.get("ruleId", "unknown")
                rule = rules_index.get(rule_id, {})
                loc = result.get("locations", [{}])[0]
                uri = (
                    loc.get("physicalLocation", {})
                       .get("artifactLocation", {})
                       .get("uri", "unknown")
                )
                line = (
                    loc.get("physicalLocation", {})
                       .get("region", {})
                       .get("startLine", 1)
                )
                findings.append({
                    "tool":        tool,
                    "rule_id":     rule_id,
                    "title":       rule.get("shortDescription", {}).get("text", rule_id),
                    "description": result.get("message", {}).get("text", ""),
                    "uri":         uri,
                    "line":        line,
                    "severity":    classify_severity(result, rule),
                    "source_ref":  make_source_ref(tool, rule_id, uri, line),
                    "playbook":    pick_playbook(rule_id, classify_severity(result, rule)),
                })
    return findings
 
 
# ── display ────────────────────────────────────────────────────────────
 
def print_header():
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    print()
    print(colour("╔══════════════════════════════════════════════════════════╗", PURPLE))
    print(colour("║  ShieldFlow SOAR Simulator — TheHive-style alert output  ║", PURPLE))
    print(colour("╚══════════════════════════════════════════════════════════╝", PURPLE))
    print(colour(f"  Run at: {ts}", GREY))
    print()
 
def print_alert(alert: dict, index: int, total: int, is_dupe: bool = False):
    sev   = alert["severity"]
    col   = SEV_COLOUR.get(sev, WHITE)
    icon  = SEV_ICON.get(sev, "⚪")
    dupe  = colour("  [DEDUPLICATED — skipped]", GREY) if is_dupe else ""
 
    print(colour("  ─" * 30, GREY))
    print(
        f"  {icon} {colour(f'ALERT {index:02d}/{total:02d}', GREY)}  "
        f"{colour(f'[{sev}]', col)}  "
        f"{colour(alert['title'], BOLD)}"
        f"{dupe}"
    )
    if is_dupe:
        return
 
    print(f"  {colour('Tool:      ', GREY)}{alert['tool']}")
    print(f"  {colour('Rule ID:   ', GREY)}{alert['rule_id']}")
    print(f"  {colour('Location:  ', GREY)}{alert['uri']}:{alert['line']}")
    print(f"  {colour('Source ref:', GREY)}{alert['source_ref']}")
 
    # description — wrap at 70 chars
    desc = alert["description"]
    if len(desc) > 70:
        desc = desc[:67] + "..."
    print(f"  {colour('Detail:    ', GREY)}{desc}")
 
    # playbook
    if alert["playbook"]:
        print(f"  {colour('Playbook:  ', GREY)}{colour('▶ ' + alert['playbook'], CYAN)}")
        _print_playbook_actions(alert)
 
    print()
 
def _print_playbook_actions(alert: dict):
    pb = alert["playbook"]
    sev = alert["severity"]
    actions = []
 
    if "PB-01" in pb:
        actions = [
            "→ Rotate / invalidate exposed credential immediately",
            "→ Alert credential owner via email",
            "→ Open TheHive case with commit SHA as evidence",
            "→ Block PR merge until rotation confirmed",
        ]
    elif "PB-02" in pb:
        actions = [
            "→ Block deployment pipeline",
            f"→ Enrich with NVD data for {alert['rule_id']}",
            "→ Assign case to dev team with fixed-version details",
            "→ Slack notification to #appsec channel",
        ]
    elif "PB-03" in pb:
        actions = [
            "→ Create tracked case in TheHive",
            "→ Notify AppSec lead with ZAP/SAST evidence attached",
            "→ Set SLA timer based on severity",
            "→ Link to OWASP remediation guidance",
        ]
    else:
        actions = [
            "→ Create TheHive alert",
            "→ Notify security team",
        ]
 
    for action in actions:
        print(f"             {colour(action, GREEN)}")
 
def print_summary(counts: dict, posted: int, dupes: int, blocked: bool, alerts: list):
    print(colour("  ═" * 30, PURPLE))
    print(colour("  SOAR INGESTION SUMMARY", PURPLE + BOLD))
    print(colour("  ═" * 30, PURPLE))
    print()
 
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        n = counts.get(sev, 0)
        if n == 0:
            continue
        col = SEV_COLOUR.get(sev, WHITE)
        bar = colour("█" * min(n, 30), col)
        print(f"  {colour(f'{sev:<10}', col)}  {bar}  {colour(str(n), BOLD)}")
 
    print()
    print(f"  {colour('Alerts posted:  ', GREY)}{colour(str(posted), GREEN + BOLD)}")
    print(f"  {colour('Deduplicated:   ', GREY)}{colour(str(dupes), YELLOW)}")
    print(f"  {colour('Total findings: ', GREY)}{posted + dupes}")
    print()
 
    gate = colour("🚫 BLOCKED — CRITICAL finding(s) present", RED + BOLD) if blocked \
           else colour("✅ PASSED — no CRITICAL findings", GREEN + BOLD)
    print(f"  Gate decision:  {gate}")
 
    # MTTT estimate
    print()
    print(colour("  MTTT (Mean Time To Triage)", GREY))
    print(f"  {colour('Manual estimate:  ', GREY)}~{colour('3–5 business days', YELLOW)}")
    print(f"  {colour('Automated (this): ', GREY)} {colour('<30 seconds', GREEN + BOLD)}")
    print()
 
def print_playbook_summary(alerts: list):
    triggered = [a for a in alerts if a.get("playbook")]
    if not triggered:
        return
    print(colour("  PLAYBOOKS TRIGGERED", CYAN + BOLD))
    by_pb: dict[str, list] = {}
    for a in triggered:
        by_pb.setdefault(a["playbook"], []).append(a)
    for pb, items in by_pb.items():
        print(f"  {colour('▶', CYAN)} {colour(pb, BOLD)}  ×{len(items)}")
    print()
 
 
# ── optional Slack notification ────────────────────────────────────────
 
def send_slack(webhook_url: str, counts: dict, posted: int, blocked: bool):
    icon = "🚫" if blocked else "✅"
    gate_text = "BLOCKED — CRITICAL findings present" if blocked else "PASSED — no CRITICAL findings"
    payload = {
        "text": f"{icon} ShieldFlow SOAR scan complete",
        "blocks": [
            {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": f"{icon} *ShieldFlow SOAR — scan complete*\n"
                                 f"*Gate:* {gate_text}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn",
                         "text": (
                             f"*CRITICAL:* {counts.get('CRITICAL',0)}  "
                             f"*HIGH:* {counts.get('HIGH',0)}  "
                             f"*MEDIUM:* {counts.get('MEDIUM',0)}  "
                             f"*LOW:* {counts.get('LOW',0)}\n"
                             f"*Alerts posted:* {posted}"
                         )}
            }
        ]
    }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            print(colour(f"\n  Slack notification sent ({resp.status})", GREEN))
    except Exception as e:
        print(colour(f"\n  Slack notification failed: {e}", YELLOW))
 
 
# ── main ───────────────────────────────────────────────────────────────
 
def main():
    parser = argparse.ArgumentParser(
        description="ShieldFlow SOAR Simulator — parses SARIF files and prints TheHive-style alerts"
    )
    parser.add_argument(
        "--dir", default="sarif-reports",
        help="Directory containing *.sarif files (default: ./sarif-reports)"
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Also write all alerts to soar_output.json"
    )
    parser.add_argument(
        "--slack", metavar="WEBHOOK_URL",
        help="Send summary to a Slack webhook URL"
    )
    parser.add_argument(
        "--no-colour", action="store_true",
        help="Disable terminal colours (for piped output)"
    )
    args = parser.parse_args()
 
    # disable colours if piped or flag set
    if args.no_colour or not sys.stdout.isatty():
        global RESET,BOLD,RED,YELLOW,CYAN,GREEN,GREY,PURPLE,WHITE
        RESET=BOLD=RED=YELLOW=CYAN=GREEN=GREY=PURPLE=WHITE=""
        for k in SEV_COLOUR: SEV_COLOUR[k]=""
 
    print_header()
 
    # parse
    print(colour(f"  📂 Scanning SARIF files in: {args.dir}", GREY))
    findings = parse_sarif_dir(args.dir)
 
    if not findings:
        print(colour("  No findings to process. Exiting.\n", GREY))
        return
 
    print(colour(f"  Found {len(findings)} raw finding(s) across all scanners.\n", GREY))
 
    # deduplicate
    seen_refs: set[str] = set()
    alerts: list[dict] = []
    dupes = 0
    for f in findings:
        ref = f["source_ref"]
        f["is_dupe"] = ref in seen_refs
        if f["is_dupe"]:
            dupes += 1
        else:
            seen_refs.add(ref)
        alerts.append(f)
 
    # sort: CRITICAL first, then HIGH, then by tool name
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    alerts.sort(key=lambda a: (sev_order.get(a["severity"], 5), a["tool"]))
 
    # print each alert
    print(colour("  THEHIVE ALERT STREAM", PURPLE + BOLD))
    total = len(alerts)
    for i, alert in enumerate(alerts, 1):
        print_alert(alert, i, total, is_dupe=alert["is_dupe"])
 
    # counts
    counts: dict[str, int] = {}
    for a in alerts:
        if not a["is_dupe"]:
            counts[a["severity"]] = counts.get(a["severity"], 0) + 1
 
    posted = total - dupes
    blocked = counts.get("CRITICAL", 0) > 0
 
    print_playbook_summary([a for a in alerts if not a["is_dupe"]])
    print_summary(counts, posted, dupes, blocked, alerts)
 
    # optional JSON export
    if args.json:
        output = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "summary": {"posted": posted, "deduplicated": dupes, "gate_blocked": blocked, "counts": counts},
            "alerts": [{k: v for k, v in a.items() if k != "is_dupe"} for a in alerts if not a["is_dupe"]],
        }
        with open("soar_output.json", "w") as f:
            json.dump(output, f, indent=2)
        print(colour("  JSON export written to soar_output.json", GREY))
 
    # optional Slack
    if args.slack:
        send_slack(args.slack, counts, posted, blocked)
 
    # exit code mirrors the real gate
    sys.exit(1 if blocked else 0)
 
 
if __name__ == "__main__":
    main()
 
