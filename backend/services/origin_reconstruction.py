from typing import Dict, Any, List

TRUSTED_PROVIDERS = {"google.com", "microsoft.com", "outlook.com", "sendgrid.net", "mailgun.org", "amazonses.com"}
ANONYMIZATION_KEYWORDS = {"tor", "vpn", "proxy", "exit", "bulletproof", "chocoping", "m247", "zwiebel"}

def reconstruct_origin(received_hops: List[Dict[str, Any]], observed_ips_intel: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Stage 4: Trust-Aware Origin Reconstruction.
    Safely parses Received hop routing chain, handles missing/malformed hops, and evaluates origin confidence.
    """
    received_hops = received_hops or []
    observed_ips_intel = observed_ips_intel or []

    classified_hops = []
    has_anonymizer = False
    has_untrusted_relay = False
    origin_ip = None
    origin_host = None

    for idx, hop in enumerate(received_hops):
        if not isinstance(hop, dict):
            continue

        ip = hop.get("ip")
        from_host = str(hop.get("from_host") or "unknown").strip()
        by_host = str(hop.get("by_host") or "unknown").strip()
        
        # Match IP intelligence
        ip_info = next((i for i in observed_ips_intel if isinstance(i, dict) and i.get("ip") == ip), {})
        
        org = str(ip_info.get("organization") or "").lower()
        isp = str(ip_info.get("isp") or "").lower()
        is_tor = bool(ip_info.get("tor", False))
        is_vpn = bool(ip_info.get("vpn", False))
        is_proxy = bool(ip_info.get("proxy", False))
        is_hosting = bool(ip_info.get("hosting", False))

        classification = "UNKNOWN"
        notes = []

        from_host_lower = from_host.lower()

        if is_tor or is_vpn or is_proxy or any(k in org for k in ANONYMIZATION_KEYWORDS) or any(k in isp for k in ANONYMIZATION_KEYWORDS):
            classification = "ANONYMIZATION / PRIVACY INFRASTRUCTURE"
            has_anonymizer = True
            notes.append("Intermediary anonymization network observed")
        elif any(provider in from_host_lower or provider in org for provider in TRUSTED_PROVIDERS):
            classification = "KNOWN MAIL PROVIDER"
        elif is_hosting:
            classification = "RELAY / DATACENTER"
            has_untrusted_relay = True
        else:
            classification = "ORGANIZATIONAL"

        # First observed hop is origin candidate
        if idx == 0 and ip:
            origin_ip = ip
            origin_host = from_host

        classified_hops.append({
            "hop_number": hop.get("hop_number", idx + 1),
            "ip": ip or "Unparsed",
            "from_host": from_host,
            "by_host": by_host,
            "classification": classification,
            "country": ip_info.get("country", "Unknown"),
            "organization": ip_info.get("organization", "Unknown"),
            "notes": ", ".join(notes) if notes else "Standard mail transit hop"
        })

    # Evaluate Origin Attribution Confidence
    if not origin_ip:
        origin_confidence = "LOW"
        confidence_reason = "No valid IP addresses could be parsed from Received headers."
        caveat = "Attribution cannot be established from available evidence."
    elif has_anonymizer:
        origin_confidence = "LOW"
        confidence_reason = "Origin attribution confidence reduced due to intermediary anonymization/Tor/VPN infrastructure."
        caveat = "Intermediary anonymization infrastructure detected. The observed IP is an exit node, proxy, or relay, not necessarily the attacker's true physical endpoint."
    elif has_untrusted_relay:
        origin_confidence = "MEDIUM"
        confidence_reason = "Observed sending infrastructure uses third-party cloud hosting or open relay servers."
        caveat = "Observed sending infrastructure represents a transit relay or datacenter host."
    else:
        origin_confidence = "HIGH"
        confidence_reason = "Mail chain follows standard organizational mail server route with matching domain PTR records."
        caveat = "Observed infrastructure represents verified originating mail server."

    return {
        "reconstructed_chain": classified_hops,
        "probable_origin": {
            "ip": origin_ip or "Unavailable",
            "host": origin_host or "Unavailable",
            "infrastructure_type": classified_hops[0]["classification"] if classified_hops else "UNKNOWN"
        },
        "origin_confidence": origin_confidence,
        "confidence_reason": confidence_reason,
        "attribution_caveat": caveat,
        "has_anonymizer": has_anonymizer,
        "total_hops": len(classified_hops)
    }
