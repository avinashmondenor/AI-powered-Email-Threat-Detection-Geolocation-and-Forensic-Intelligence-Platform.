import re
import dkim
import dns.resolver
from typing import Dict, Any, Optional

def evaluate_dkim(dkim_header: str, eml_bytes: Optional[bytes], observed_auth: Dict[str, Any]) -> Dict[str, Any]:
    observed_result = observed_auth.get("dkim", "UNKNOWN")

    if not dkim_header:
        return {
            "result": "NONE",
            "source": "observed" if observed_result != "UNKNOWN" else "unavailable",
            "domain": "",
            "selector": "",
            "algorithm": "",
            "details": "No DKIM-Signature header present."
        }

    # Extract d= and s= and a=
    d_match = re.search(r'd=([a-zA-Z0-9\.\-_]+)', dkim_header)
    s_match = re.search(r's=([a-zA-Z0-9\.\-_]+)', dkim_header)
    a_match = re.search(r'a=([a-zA-Z0-9\.\-_]+)', dkim_header)

    domain = d_match.group(1) if d_match else ""
    selector = s_match.group(1) if s_match else ""
    algorithm = a_match.group(1) if a_match else "rsa-sha256"

    # Attempt verification using dkimpy if eml_bytes provided
    verified = False
    if eml_bytes:
        try:
            verified = dkim.verify(eml_bytes)
        except Exception:
            verified = False

    if verified:
        return {
            "result": "PASS",
            "source": "independently_verified",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "details": "DKIM signature cryptographically verified against public key."
        }

    if observed_result != "UNKNOWN":
        return {
            "result": observed_result,
            "source": "observed",
            "domain": domain,
            "selector": selector,
            "algorithm": algorithm,
            "details": f"Observed DKIM header result: {observed_result}"
        }

    # Check DNS selector record
    dns_found = False
    if domain and selector:
        try:
            txt_name = f"{selector}._domainkey.{domain}"
            answers = dns.resolver.resolve(txt_name, 'TXT', lifetime=2.0)
            if answers:
                dns_found = True
        except Exception:
            dns_found = False

    return {
        "result": "FAIL" if (domain and not dns_found) else "UNKNOWN",
        "source": "independently_verified" if dns_found else "unavailable",
        "domain": domain,
        "selector": selector,
        "algorithm": algorithm,
        "details": f"Public key DNS record {'found' if dns_found else 'not found'} for {selector}._domainkey.{domain}"
    }
