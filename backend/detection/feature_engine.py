from typing import Dict, Any, List

def build_feature_vector(
    evidence: Dict[str, Any],
    spf_res: Dict[str, Any],
    dkim_res: Dict[str, Any],
    dmarc_res: Dict[str, Any],
    ip_intel: List[Dict[str, Any]],
    domain_intel: Dict[str, Any],
    lookalike_res: Dict[str, Any],
    urls_res: List[Dict[str, Any]],
    content_res: Dict[str, Any],
    attachment_res: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Extracts normalized boolean and numeric features from raw evidence & intelligence modules.
    """
    # Sender vs Reply-to mismatch check
    sender_dom = evidence.get("sender_domain", "").lower()
    reply_dom = evidence.get("reply_to_domain", "").lower()
    reply_to_mismatch = bool(sender_dom and reply_dom and sender_dom != reply_dom)

    # Auth flags
    spf_fail = spf_res.get("result") in ("FAIL", "SOFTFAIL")
    dkim_fail = dkim_res.get("result") in ("FAIL",)
    dmarc_fail = dmarc_res.get("result") in ("FAIL",)

    # IP intel flags
    vpn_detected = any(ip.get("vpn", False) for ip in ip_intel)
    proxy_detected = any(ip.get("proxy", False) for ip in ip_intel)
    tor_detected = any(ip.get("tor", False) for ip in ip_intel)
    hosting_ip = any(ip.get("hosting", False) for ip in ip_intel)

    # Domain flags
    new_domain = domain_intel.get("is_new_domain", False)
    lookalike_domain = lookalike_res.get("lookalike", False)

    # URL flags
    suspicious_url = any(u.get("reputation") in ("MALICIOUS", "SUSPICIOUS") for u in urls_res)
    redirect_detected = any(u.get("redirect_info", {}).get("has_redirect", False) for u in urls_res)

    # Content flags
    urgency_language = content_res.get("urgency", False)
    credential_request = content_res.get("credential_request", False)
    financial_request = content_res.get("financial_request", False)

    # Attachment flags
    suspicious_attachment = attachment_res.get("suspicious_attachment", False)

    features = {
        "spf_fail": spf_fail,
        "dkim_fail": dkim_fail,
        "dmarc_fail": dmarc_fail,
        "reply_to_mismatch": reply_to_mismatch,

        "vpn_detected": vpn_detected,
        "proxy_detected": proxy_detected,
        "tor_detected": tor_detected,
        "hosting_ip": hosting_ip,

        "new_domain": new_domain,
        "lookalike_domain": lookalike_domain,

        "suspicious_url": suspicious_url,
        "redirect_detected": redirect_detected,

        "urgency_language": urgency_language,
        "credential_request": credential_request,
        "financial_request": financial_request,

        "suspicious_attachment": suspicious_attachment
    }

    return features
