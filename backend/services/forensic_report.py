from typing import Dict, Any, List

def compile_forensic_findings(
    evidence_data: Dict[str, Any],
    header_forensics: Dict[str, Any],
    auth_data: Dict[str, Any],
    origin_data: Dict[str, Any],
    infra_data: Dict[str, Any],
    lookalike_data: Dict[str, Any],
    urls_data: List[Dict[str, Any]],
    attachments_data: List[Dict[str, Any]],
    confidence_data: Dict[str, Any],
    risk_score: int,
    classification: str
) -> Dict[str, Any]:
    """
    Stage 8: Forensic Findings Compilation.
    Maps forensic evidence to specific structured findings with explicit confidence levels.
    """
    findings = []
    finding_counter = 1

    headers = header_forensics.get("headers", {})
    anomalies = header_forensics.get("identity_anomalies", {})

    # 1. Look-alike Brand Typosquatting Finding
    if lookalike_data.get("lookalike"):
        findings.append({
            "finding_number": finding_counter,
            "category": "BRAND_IMPERSONATION",
            "title": "Look-alike Domain Typosquatting",
            "description": f"Domain '{anomalies.get('sender_domain')}' mimics reference brand '{lookalike_data.get('reference')}'",
            "evidence": f"Similarity Score: {lookalike_data.get('similarity_score')} ({lookalike_data.get('reason')})",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 2. Display Name Spoofing
    if anomalies.get("display_name_spoofing"):
        findings.append({
            "finding_number": finding_counter,
            "category": "DISPLAY_NAME_SPOOFING",
            "title": "Executive / Brand Display Name Spoofing",
            "description": f"Display name '{headers.get('display_name')}' contains brand '{anomalies.get('spoofed_brand')}' but sender domain is '{anomalies.get('sender_domain')}'",
            "evidence": f"From Header: {headers.get('from')}",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 3. Reply-To Mismatch
    if anomalies.get("reply_to_mismatch"):
        findings.append({
            "finding_number": finding_counter,
            "category": "HEADER_ANOMALY",
            "title": "Reply-To Address Mismatch",
            "description": "Reply-To domain differs from From header sender domain",
            "evidence": f"From Domain: {anomalies.get('sender_domain')} vs Reply-To: {headers.get('reply_to')}",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 4. Authentication Failure Finding
    dmarc = auth_data.get("dmarc", {})
    if dmarc.get("result") == "FAIL":
        findings.append({
            "finding_number": finding_counter,
            "category": "AUTHENTICATION_FAILURE",
            "title": "DMARC Alignment Verification Failure",
            "description": f"DMARC check failed with policy '{dmarc.get('policy')}'",
            "evidence": f"SPF Aligned: {dmarc.get('spf_alignment')}, DKIM Aligned: {dmarc.get('dkim_alignment')} (Source: {dmarc.get('source')})",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 5. Infrastructure Anonymizer Finding
    if origin_data.get("has_anonymizer"):
        findings.append({
            "finding_number": finding_counter,
            "category": "INFRASTRUCTURE_ANOMALY",
            "title": "Intermediary Anonymization Infrastructure Observed",
            "description": "Tor exit node, VPN, or proxy IP detected in Received mail transit hops",
            "evidence": f"Probable Origin IP: {origin_data.get('probable_origin', {}).get('ip')} ({origin_data.get('attribution_caveat')})",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 6. Malicious / Suspicious URL Finding
    mal_urls = [u for u in urls_data if u.get("reputation") in ("MALICIOUS", "SUSPICIOUS")]
    if mal_urls:
        findings.append({
            "finding_number": finding_counter,
            "category": "SUSPICIOUS_URL",
            "title": f"Suspicious or IP-Based Link Embedded ({len(mal_urls)})",
            "description": f"Extracted URL '{mal_urls[0].get('url')}' exhibits suspicious characteristics",
            "evidence": f"Reputation: {mal_urls[0].get('reputation')} | Characteristics: {', '.join(mal_urls[0].get('suspicious_characteristics', []))}",
            "confidence": "HIGH"
        })
        finding_counter += 1

    # 7. High-Risk Attachment Finding
    susp_att = [a for a in attachments_data if a.get("is_suspicious_extension")]
    if susp_att:
        findings.append({
            "finding_number": finding_counter,
            "category": "SUSPICIOUS_ATTACHMENT",
            "title": "High-Risk Executable or Macro Attachment",
            "description": f"Attachment '{susp_att[0].get('filename')}' exhibits dangerous file extension or double extension",
            "evidence": f"File: {susp_att[0].get('filename')} | MIME: {susp_att[0].get('mime_type')} | SHA-256: {susp_att[0].get('sha256')}",
            "confidence": "HIGH"
        })
        finding_counter += 1

    verdict_text = "Malicious" if classification == "CRITICAL" else ("Suspicious" if classification in ("HIGH", "MEDIUM") else "Benign")

    return {
        "overall_verdict": verdict_text,
        "threat_score": risk_score,
        "risk_level": classification,
        "overall_confidence": confidence_data.get("threat_confidence", "HIGH"),
        "findings_count": len(findings),
        "findings": findings
    }
