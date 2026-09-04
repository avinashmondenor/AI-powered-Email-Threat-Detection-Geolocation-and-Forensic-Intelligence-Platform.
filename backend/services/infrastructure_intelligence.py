from typing import Dict, Any, List
from backend.intelligence.ip_intelligence import analyze_ips
from backend.intelligence.domain_intelligence import analyze_domain
from backend.intelligence.url_intelligence import analyze_urls

def enrich_infrastructure_intelligence(
    received_ips: List[str],
    sender_domain: str,
    extracted_urls: List[Dict[str, Any]],
    is_mock: bool = True
) -> Dict[str, Any]:
    """
    Stage 5: Infrastructure Intelligence.
    Enriches IP, Domain, and URL indicators, labeling source as Mock or Live API.
    """
    ip_results = analyze_ips(received_ips)
    domain_result = analyze_domain(sender_domain)
    url_results = analyze_urls(extracted_urls)

    return {
        "mode": "MOCK INTELLIGENCE" if is_mock else "LIVE API INTELLIGENCE",
        "ips": ip_results,
        "domain": domain_result,
        "urls": url_results,
        "total_ips_enriched": len(ip_results),
        "total_urls_enriched": len(url_results)
    }
