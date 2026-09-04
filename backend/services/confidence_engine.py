from typing import Dict, Any

def evaluate_investigation_confidence(
    risk_score: int,
    features: Dict[str, bool],
    origin_info: Dict[str, Any],
    infra_info: Dict[str, Any],
    campaign_info: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Stage 7: Confidence-Based Investigation Engine.
    Safely calculates evidence-backed confidence metrics (LOW, MEDIUM, HIGH) without division by zero or crashing on empty attributes.
    """
    risk_score = risk_score or 0
    features = features or {}
    origin_info = origin_info or {}
    infra_info = infra_info or {}
    campaign_info = campaign_info or {}

    # 1. Threat Confidence
    active_threat_signals = sum(1 for v in features.values() if v)
    if active_threat_signals >= 4 or risk_score >= 80 or risk_score <= 15:
        threat_confidence = "HIGH"
        threat_reason = f"Based on {active_threat_signals} correlated threat indicators and convergent risk scoring."
    elif active_threat_signals >= 2 or risk_score >= 50:
        threat_confidence = "MEDIUM"
        threat_reason = "Multiple suspicious indicators observed with moderate alignment."
    else:
        threat_confidence = "LOW"
        threat_reason = "Limited or ambiguous threat signals observed."

    # 2. Origin Attribution Confidence
    origin_confidence = origin_info.get("origin_confidence", "LOW")
    origin_reason = origin_info.get("confidence_reason", "Extracted from Received hop routing headers.")

    # 3. Infrastructure Confidence
    total_ips = infra_info.get("total_ips_enriched", 0)
    if total_ips > 0:
        infra_confidence = "HIGH" if not str(infra_info.get("mode") or "").startswith("MOCK") else "MEDIUM"
        infra_reason = f"Enriched {total_ips} network hop IPs against threat intelligence databases."
    else:
        infra_confidence = "LOW"
        infra_reason = "No network hop IPs available for external intelligence enrichment."

    # 4. Campaign Confidence
    if campaign_info.get("campaign_detected"):
        campaign_confidence = "HIGH" if campaign_info.get("correlated_events_count", 0) >= 2 else "MEDIUM"
        campaign_reason = f"Correlated across {campaign_info.get('correlated_events_count')} historical analysis events."
    else:
        campaign_confidence = "LOW"
        campaign_reason = "Single isolated incident; insufficient correlated dataset for campaign cluster confidence."

    return {
        "threat_confidence": threat_confidence,
        "threat_confidence_reason": threat_reason,

        "origin_confidence": origin_confidence,
        "origin_confidence_reason": origin_reason,
        "origin_caveat": origin_info.get("attribution_caveat", ""),

        "infrastructure_confidence": infra_confidence,
        "infrastructure_confidence_reason": infra_reason,

        "campaign_confidence": campaign_confidence,
        "campaign_confidence_reason": campaign_reason
    }
