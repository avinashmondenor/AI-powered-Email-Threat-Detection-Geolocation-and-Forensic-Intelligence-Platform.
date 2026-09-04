from typing import Dict, Any

def generate_soc_report(analysis_data: Dict[str, Any]) -> str:
    """
    Generates a structured SOC Analyst Investigation Report in GitHub-flavored Markdown format.
    """
    analysis_id = analysis_data.get("analysis_id", "N/A")
    timestamp = analysis_data.get("timestamp", "N/A")
    score = analysis_data.get("risk_score", 0)
    classification = analysis_data.get("classification", "UNKNOWN")
    email = analysis_data.get("email", {})
    auth = analysis_data.get("authentication", {})
    infra = analysis_data.get("infrastructure", {})
    domains = analysis_data.get("domains", [])
    urls = analysis_data.get("urls", [])
    attachments = analysis_data.get("attachments", [])
    reasons = analysis_data.get("reasons", [])
    ml_info = analysis_data.get("ml_threat_analysis", {})

    report = []
    report.append(f"# EMAIL THREAT INVESTIGATION REPORT")
    report.append(f"**Analysis ID**: `{analysis_id}`  ")
    report.append(f"**Timestamp**: `{timestamp}`  ")
    report.append(f"**Mode**: `{'DEMO / MOCK INTELLIGENCE' if analysis_data.get('is_mock') else 'LIVE INTELLIGENCE'}`  ")
    report.append("\n---\n")

    report.append(f"## 1. EXECUTIVE THREAT SUMMARY")
    report.append(f"- **Risk Score**: **{score} / 100**")
    report.append(f"- **Risk Classification**: **{classification}**")
    report.append(f"- **ML Malicious Probability**: `{ml_info.get('ml_threat_probability', 'N/A')}` ({ml_info.get('ml_prediction', 'N/A')})")
    report.append(f"- **Subject**: `{email.get('subject', 'No Subject')}`")
    report.append(f"- **From**: `{email.get('from', 'N/A')}`")
    report.append(f"- **Reply-To**: `{email.get('reply_to', 'N/A')}`")
    
    if reasons:
        report.append("\n### Primary Risk Factors Identified:\n")
        for idx, r in enumerate(reasons, 1):
            report.append(f"{idx}. {r}")
    else:
        report.append("\n*No significant threat indicators detected.*")

    report.append("\n---\n")
    report.append(f"## 2. EMAIL IDENTITY & AUTHENTICATION")
    report.append(f"| Protocol | Result | Source | Alignment / Details |")
    report.append(f"|---|---|---|---|")
    spf = auth.get("spf", {})
    dkim = auth.get("dkim", {})
    dmarc = auth.get("dmarc", {})
    report.append(f"| **SPF** | `{spf.get('result')}` | `{spf.get('source')}` | Domain: `{spf.get('domain')}` |")
    report.append(f"| **DKIM** | `{dkim.get('result')}` | `{dkim.get('source')}` | Selector: `{dkim.get('selector')}`, Domain: `{dkim.get('domain')}` |")
    report.append(f"| **DMARC** | `{dmarc.get('result')}` | `{dmarc.get('source')}` | Policy: `{dmarc.get('policy')}`, SPF Align: `{dmarc.get('spf_alignment')}`, DKIM Align: `{dmarc.get('dkim_alignment')}` |")

    report.append("\n---\n")
    report.append(f"## 3. INFRASTRUCTURE & ROUTE ANALYSIS")
    hops = infra.get("received_hops", [])
    if hops:
        report.append("| Hop # | IP Address | Hostname | Geo / Org | Flags |")
        report.append("|---|---|---|---|---|")
        for hop in hops:
            ip = hop.get("ip", "N/A")
            # find matching ip info
            ip_info = next((i for i in infra.get("observed_ips", []) if i.get("ip") == ip), {})
            geo = f"{ip_info.get('country', '')}, {ip_info.get('organization', '')}"
            flags = []
            if ip_info.get("tor"): flags.append("TOR")
            if ip_info.get("vpn"): flags.append("VPN")
            if ip_info.get("proxy"): flags.append("PROXY")
            if ip_info.get("hosting"): flags.append("HOSTING")
            flag_str = ", ".join(flags) if flags else "CLEAN"
            report.append(f"| {hop.get('hop_number')} | `{ip}` | `{hop.get('from_host')}` | {geo} | `{flag_str}` |")
    else:
        report.append("*No Received hop headers present.*")

    report.append("\n> **Infrastructure Caveat**: Observed IPs indicate relay and mail server hops; they may include legitimate providers, proxies, Tor, or compromised systems.")

    report.append("\n---\n")
    report.append(f"## 4. DOMAIN & LOOK-ALIKE ANALYSIS")
    lk = analysis_data.get("lookalike_analysis", {})
    if lk.get("lookalike"):
        report.append(f"> [!WARNING]\n> **Look-alike Domain Detected!**\n> Domain `{email.get('sender_domain')}` is a look-alike of reference brand **`{lk.get('reference')}`** (Similarity Score: `{lk.get('similarity_score')}`). Reason: {lk.get('reason')}")
    else:
        report.append(f"Sender domain: `{email.get('sender_domain')}` (No brand typosquatting detected).")

    report.append("\n---\n")
    report.append(f"## 5. EMBEDDED URLS ({len(urls)})")
    if urls:
        report.append("| URL | Domain | Reputation | Suspicious Indicators |")
        report.append("|---|---|---|---|")
        for u in urls:
            chars = ", ".join(u.get("suspicious_characteristics", [])) or "None"
            report.append(f"| `{u.get('url')[:60]}` | `{u.get('domain')}` | `{u.get('reputation')}` | {chars} |")
    else:
        report.append("*No embedded URLs found.*")

    report.append("\n---\n")
    report.append(f"## 6. ATTACHMENTS ({len(attachments)})")
    if attachments:
        report.append("| Filename | MIME Type | Size | SHA-256 | Risk Flag |")
        report.append("|---|---|---|---|---|")
        for a in attachments:
            flag = "HIGH RISK" if a.get("is_suspicious_extension") else "CLEAN"
            report.append(f"| `{a.get('filename')}` | `{a.get('mime_type')}` | {a.get('size_bytes')} B | `{a.get('sha256')[:16]}...` | `{flag}` |")
    else:
        report.append("*No attachments present.*")

    report.append("\n---\n")
    report.append(f"## 7. RECOMMENDATION & SOC WORKFLOW ACTION")
    if classification in ("CRITICAL", "HIGH"):
        report.append("> [!CAUTION]\n> **RECOMMENDED ACTION**: Block domain, purge message from user inboxes, add IP indicators to firewall blocklist, and revoke compromised credentials if clicked.")
    elif classification == "MEDIUM":
        report.append("> [!IMPORTANT]\n> **RECOMMENDED ACTION**: Quarantine message, notify recipient, and request user verification before releasing.")
    else:
        report.append("> [!NOTE]\n> **RECOMMENDED ACTION**: Deliver email normally. No threat indicators requiring SOC intervention.")

    return "\n".join(report)
