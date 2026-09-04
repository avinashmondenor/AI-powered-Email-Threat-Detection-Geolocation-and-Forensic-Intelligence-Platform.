import re
import dns.resolver
from typing import Dict, Any

def evaluate_dmarc(
    from_domain: str,
    spf_res: Dict[str, Any],
    dkim_res: Dict[str, Any],
    observed_auth: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluates DMARC policy and alignment between From header domain and SPF/DKIM domains.
    """
    observed_result = observed_auth.get("dmarc", "UNKNOWN")

    if not from_domain:
        return {
            "result": "UNKNOWN",
            "policy": "none",
            "spf_alignment": False,
            "dkim_alignment": False,
            "source": "unavailable",
            "details": "No From header domain available for DMARC check."
        }

    # Fetch DMARC record from DNS
    policy = "none"
    record = None
    try:
        txt_domain = f"_dmarc.{from_domain}"
        answers = dns.resolver.resolve(txt_domain, 'TXT', lifetime=2.0)
        for rdata in answers:
            txt = rdata.to_text().strip('"')
            if txt.startswith("v=DMARC1"):
                record = txt
                p_match = re.search(r'p=(none|quarantine|reject)', txt, re.IGNORECASE)
                if p_match:
                    policy = p_match.group(1).lower()
                break
    except Exception:
        record = None

    # Evaluate SPF alignment (strict/relaxed match between From domain and SPF domain)
    spf_domain = spf_res.get("domain", "")
    spf_pass = spf_res.get("result", "") == "PASS"
    spf_aligned = spf_pass and (from_domain == spf_domain or from_domain.endswith("." + spf_domain) or spf_domain.endswith("." + from_domain))

    # Evaluate DKIM alignment
    dkim_domain = dkim_res.get("domain", "")
    dkim_pass = dkim_res.get("result", "") == "PASS"
    dkim_aligned = dkim_pass and (from_domain == dkim_domain or from_domain.endswith("." + dkim_domain) or dkim_domain.endswith("." + from_domain))

    # DMARC passes if EITHER (SPF Pass AND SPF aligned) OR (DKIM Pass AND DKIM aligned)
    dmarc_pass = spf_aligned or dkim_aligned
    dmarc_result = "PASS" if dmarc_pass else "FAIL"

    # Use observed if independent evaluation didn't have full DNS info
    source = "independently_verified" if record else ("observed" if observed_result != "UNKNOWN" else "unavailable")
    final_result = dmarc_result if record else (observed_result if observed_result != "UNKNOWN" else dmarc_result)

    return {
        "result": final_result,
        "policy": policy,
        "record": record,
        "spf_alignment": spf_aligned,
        "dkim_alignment": dkim_aligned,
        "source": source,
        "details": f"DMARC policy='{policy}'. SPF aligned={spf_aligned}, DKIM aligned={dkim_aligned}. Final={final_result}"
    }
