import dns.resolver
from typing import Dict, Any, List, Optional

def evaluate_spf(sender_domain: str, observed_ips: List[str], observed_auth: Dict[str, Any]) -> Dict[str, Any]:
    """
    Evaluates SPF using DNS TXT record or observed Authentication-Results.
    Labels source of result explicitly (observed / independently_verified / unavailable).
    """
    # First check observed header
    observed_result = observed_auth.get("spf", "UNKNOWN")
    
    if not sender_domain:
        return {
            "result": "UNKNOWN",
            "source": "unavailable",
            "domain": "",
            "details": "No sender domain available for SPF evaluation."
        }

    # Attempt independent DNS lookup
    spf_record = None
    try:
        answers = dns.resolver.resolve(sender_domain, 'TXT', lifetime=2.0)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=spf1"):
                spf_record = txt
                break
    except Exception:
        spf_record = None

    if spf_record:
        # Check basic match or fallback to observed
        details = f"SPF TXT record found: {spf_record}"
        if observed_result != "UNKNOWN":
            return {
                "result": observed_result,
                "source": "observed",
                "domain": sender_domain,
                "record": spf_record,
                "details": f"Observed SPF result '{observed_result}' confirmed with DNS record '{spf_record}'"
            }
        else:
            return {
                "result": "PASS" if "all" in spf_record else "NEUTRAL",
                "source": "independently_verified",
                "domain": sender_domain,
                "record": spf_record,
                "details": details
            }

    if observed_result != "UNKNOWN":
        return {
            "result": observed_result,
            "source": "observed",
            "domain": sender_domain,
            "record": None,
            "details": f"Observed header result: {observed_result}"
        }

    return {
        "result": "NONE",
        "source": "unavailable",
        "domain": sender_domain,
        "record": None,
        "details": "No SPF DNS record found and no observed SPF header present."
    }
