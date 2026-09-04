from typing import Dict, Any, List

# Feature weight mappings
FEATURE_WEIGHTS = {
    "lookalike_domain": (25, "Look-alike domain detected"),
    "dmarc_fail": (15, "DMARC authentication failed"),
    "reply_to_mismatch": (15, "Reply-To address mismatch detected"),
    "suspicious_url": (15, "Suspicious or malicious link embedded"),
    "credential_request": (15, "Credential harvesting language detected"),
    "suspicious_attachment": (15, "Suspicious or high-risk attachment detected"),
    "tor_detected": (15, "Tor exit node network observed in mail route"),
    "new_domain": (10, "Sender domain registered recently (< 30 days)"),
    "urgency_language": (10, "High urgency or account suspension language used"),
    "financial_request": (10, "Financial payment or wire transfer request detected"),
    "spf_fail": (10, "SPF authentication failed"),
    "dkim_fail": (10, "DKIM signature verification failed"),
    "vpn_detected": (5, "VPN service IP observed in mail route"),
    "proxy_detected": (5, "Proxy server IP observed in mail route"),
    "hosting_ip": (5, "Datacenter/Hosting IP observed in mail hops"),
    "redirect_detected": (5, "URL shortener or link redirect detected")
}

def calculate_risk_score(features: Dict[str, bool], details: Dict[str, Any] = None) -> Dict[str, Any]:
    raw_score = 0
    reasons = []
    contributions = []

    # Iterate through weights in descending order of severity
    sorted_features = sorted(FEATURE_WEIGHTS.items(), key=lambda x: x[1][0], reverse=True)

    for feat_key, (weight, default_msg) in sorted_features:
        if features.get(feat_key, False):
            raw_score += weight
            
            # Enrich reason string with specific evidence if available
            custom_msg = default_msg
            if details:
                if feat_key == "lookalike_domain" and details.get("lookalike"):
                    lk = details["lookalike"]
                    custom_msg = f"Look-alike domain detected: '{lk.get('reference')}' target ({lk.get('reason')})"
                elif feat_key == "reply_to_mismatch" and details.get("sender") and details.get("reply_to"):
                    custom_msg = f"Reply-To mismatch: From domain '{details.get('sender_domain')}' differs from Reply-To '{details.get('reply_to_domain')}'"
                elif feat_key == "dmarc_fail" and details.get("dmarc"):
                    custom_msg = f"DMARC authentication failed (Policy={details['dmarc'].get('policy')}, Alignment={details['dmarc'].get('spf_alignment')})"
                elif feat_key == "suspicious_url" and details.get("urls"):
                    mal_urls = [u["url"] for u in details["urls"] if u.get("reputation") in ("MALICIOUS", "SUSPICIOUS")]
                    if mal_urls:
                        custom_msg = f"Suspicious URL detected: '{mal_urls[0]}'"

            reasons.append(custom_msg)
            contributions.append({
                "feature": feat_key,
                "weight": weight,
                "description": custom_msg
            })

    # Cap score strictly to 0-100
    final_score = min(100, max(0, raw_score))

    # Classification threshold
    if final_score >= 80:
        classification = "CRITICAL"
    elif final_score >= 60:
        classification = "HIGH"
    elif final_score >= 30:
        classification = "MEDIUM"
    else:
        classification = "LOW"

    return {
        "risk_score": final_score,
        "classification": classification,
        "reasons": reasons,
        "contributions": contributions,
        "feature_count": len(reasons)
    }
