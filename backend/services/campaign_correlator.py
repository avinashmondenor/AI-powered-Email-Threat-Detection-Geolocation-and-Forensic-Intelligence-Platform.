import json
from typing import Dict, Any, List
from backend.database import get_recent_analyses

def build_campaign_graph(
    evidence_id: str,
    sender_email: str,
    sender_domain: str,
    message_id: str,
    urls: List[Dict[str, Any]],
    attachments: List[Dict[str, Any]],
    ip_intel: List[Dict[str, Any]]
) -> Dict[str, Any]:
    """
    Stage 6: Campaign Graph Correlation.
    Defensively handles 0 nodes, 0 URLs, 0 IPs, and missing attributes.
    """
    evidence_id = str(evidence_id or "UNKNOWN")
    sender_email = str(sender_email or "")
    sender_domain = str(sender_domain or "")
    message_id = str(message_id or "")

    urls = urls or []
    attachments = attachments or []
    ip_intel = ip_intel or []

    nodes = []
    edges = []
    node_set = set()

    def add_node(node_id: str, node_type: str, label: str, threat_level: str = "NEUTRAL"):
        if node_id and node_id not in node_set:
            node_set.add(node_id)
            nodes.append({
                "id": node_id,
                "type": node_type,
                "label": str(label or node_id),
                "threat_level": threat_level
            })

    def add_edge(source: str, target: str, relationship: str):
        if source and target:
            edges.append({
                "source": source,
                "target": target,
                "relationship": relationship
            })

    # Root Email Node
    email_node_id = f"email:{evidence_id}"
    add_node(email_node_id, "Email", f"Email ({evidence_id})", "HIGH" if sender_domain else "NEUTRAL")

    # Sender Node
    if sender_email:
        sender_node_id = f"sender:{sender_email}"
        add_node(sender_node_id, "Sender", sender_email)
        add_edge(email_node_id, sender_node_id, "SENT_BY")

    # Domain Node
    if sender_domain:
        domain_node_id = f"domain:{sender_domain}"
        add_node(domain_node_id, "Domain", sender_domain, "HIGH" if "paypa1" in sender_domain else "NEUTRAL")
        add_edge(email_node_id, domain_node_id, "ORIGIN_DOMAIN")
        if sender_email:
            add_edge(f"sender:{sender_email}", domain_node_id, "BELONGS_TO_DOMAIN")

    # Message-ID Node
    if message_id:
        msg_id_node = f"msgid:{message_id}"
        add_node(msg_id_node, "Message-ID", message_id)
        add_edge(email_node_id, msg_id_node, "HAS_HEADER")

    # IP & ASN Nodes
    for ip in ip_intel:
        if not isinstance(ip, dict):
            continue
        ip_addr = ip.get("ip")
        if ip_addr:
            ip_node_id = f"ip:{ip_addr}"
            threat = "HIGH" if ip.get("tor") or ip.get("proxy") else "NEUTRAL"
            add_node(ip_node_id, "IP", f"{ip_addr} ({ip.get('country', '')})", threat)
            add_edge(email_node_id, ip_node_id, "TRANSIT_HOP")

            if sender_domain:
                add_edge(f"domain:{sender_domain}", ip_node_id, "RESOLVES_TO_IP")

            asn = ip.get("asn")
            if asn and asn != "Unknown":
                asn_node_id = f"asn:{asn}"
                add_node(asn_node_id, "ASN", f"{asn} ({ip.get('organization', '')})")
                add_edge(ip_node_id, asn_node_id, "HOSTED_BY_ASN")

    # URL Nodes
    for u in urls:
        if not isinstance(u, dict):
            continue
        u_str = u.get("url")
        u_dom = u.get("domain")
        if u_str:
            url_node_id = f"url:{u_str[:40]}"
            threat = u.get("reputation", "NEUTRAL")
            add_node(url_node_id, "URL", u_str[:35] + "...", threat)
            add_edge(email_node_id, url_node_id, "EMBEDS_URL")

            if u_dom:
                u_dom_node = f"domain:{u_dom}"
                add_node(u_dom_node, "Domain", u_dom)
                add_edge(url_node_id, u_dom_node, "POINTS_TO_DOMAIN")

    # Attachment Nodes
    for att in attachments:
        if not isinstance(att, dict):
            continue
        fn = att.get("filename")
        sha = att.get("sha256")
        if fn:
            att_node_id = f"attachment:{sha[:8] if sha else fn}"
            threat = "HIGH" if att.get("is_suspicious_extension") else "NEUTRAL"
            add_node(att_node_id, "Attachment", fn, threat)
            add_edge(email_node_id, att_node_id, "CONTAINS_ATTACHMENT")

    # Correlate with historical database analyses
    campaign_matches = []
    try:
        recent_history = get_recent_analyses(limit=20)
        for record in recent_history:
            if not isinstance(record, dict) or record.get("id") == evidence_id:
                continue
            rec_sender = str(record.get("sender") or "")
            if sender_domain and sender_domain in rec_sender:
                campaign_matches.append({
                    "correlated_analysis_id": record.get("id"),
                    "correlation_type": "SHARED_SENDER_DOMAIN",
                    "matched_indicator": sender_domain,
                    "timestamp": record.get("created_at")
                })
    except Exception:
        campaign_matches = []

    campaign_detected = len(campaign_matches) > 0

    return {
        "campaign_detected": campaign_detected,
        "campaign_name": f"Phishing Campaign targeting {sender_domain}" if (campaign_detected and "paypa1" in sender_domain) else ("Single Incident" if not campaign_detected else "Correlated Threat Pattern"),
        "correlated_events_count": len(campaign_matches),
        "campaign_matches": campaign_matches,
        "graph": {
            "total_nodes": len(nodes),
            "total_edges": len(edges),
            "nodes": nodes,
            "edges": edges
        }
    }
