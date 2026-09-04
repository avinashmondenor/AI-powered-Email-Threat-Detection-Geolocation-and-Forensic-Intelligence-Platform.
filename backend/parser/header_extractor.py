import re
import email.utils
import tldextract
from typing import Dict, List, Any, Optional

IP_REGEX = re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b')

def extract_domain(email_address: str) -> str:
    """Extract registrable domain or domain from email string e.g. 'John <john@example.com>' -> 'example.com'"""
    if not email_address:
        return ""
    clean_addr = email.utils.parseaddr(email_address)[1]
    if "@" in clean_addr:
        domain = clean_addr.split("@")[-1].lower().strip()
        ext = tldextract.extract(domain)
        if ext.registered_domain:
            return ext.registered_domain
        return domain
    return ""

def parse_received_headers(received_headers: List[str]) -> Dict[str, Any]:
    """
    ParseReceived headers bottom-to-top (chronological route from origin to final recipient).
    Extracts IPs, hostnames, timestamps, and hop sequence.
    """
    hops = []
    all_ips = []
    all_hosts = []

    # Received headers are stored top-to-bottom (newest first). Reversing gives origin to recipient.
    for idx, header_val in enumerate(reversed(received_headers)):
        ips = IP_REGEX.findall(header_val)
        # Filter private/loopback IPs if needed, but preserve observed IPs
        valid_ips = [ip for ip in ips if not ip.startswith("127.") and not ip.startswith("10.") and not ip.startswith("192.168.")]
        if not valid_ips and ips:
            valid_ips = ips

        # Extract hostname from 'from <host>' pattern
        from_match = re.search(r'from\s+([a-zA-Z0-9\.\-_]+)', header_val, re.IGNORECASE)
        by_match = re.search(r'by\s+([a-zA-Z0-9\.\-_]+)', header_val, re.IGNORECASE)
        
        from_host = from_match.group(1) if from_match else "unknown"
        by_host = by_match.group(1) if by_match else "unknown"
        
        hop_ip = valid_ips[0] if valid_ips else None

        if hop_ip and hop_ip not in all_ips:
            all_ips.append(hop_ip)
        if from_host != "unknown" and from_host not in all_hosts:
            all_hosts.append(from_host)

        hops.append({
            "hop_number": idx + 1,
            "from_host": from_host,
            "by_host": by_host,
            "ip": hop_ip,
            "raw_header": header_val.strip()
        })

    return {
        "hops": hops,
        "ips": all_ips,
        "hosts": all_hosts
    }

def parse_auth_headers(auth_results_header: Optional[str], received_spf_header: Optional[str]) -> Dict[str, Any]:
    """
    Parses observed Authentication-Results and Received-SPF headers.
    """
    results = {
        "spf": "UNKNOWN",
        "dkim": "UNKNOWN",
        "dmarc": "UNKNOWN",
        "raw_authentication_results": auth_results_header or "",
        "raw_received_spf": received_spf_header or ""
    }

    if auth_results_header:
        text = auth_results_header.lower()
        if "spf=pass" in text:
            results["spf"] = "PASS"
        elif "spf=fail" in text:
            results["spf"] = "FAIL"
        elif "spf=softfail" in text:
            results["spf"] = "SOFTFAIL"
        elif "spf=neutral" in text:
            results["spf"] = "NEUTRAL"

        if "dkim=pass" in text:
            results["dkim"] = "PASS"
        elif "dkim=fail" in text:
            results["dkim"] = "FAIL"

        if "dmarc=pass" in text:
            results["dmarc"] = "PASS"
        elif "dmarc=fail" in text:
            results["dmarc"] = "FAIL"

    if received_spf_header and results["spf"] == "UNKNOWN":
        text = received_spf_header.lower()
        if text.startswith("pass"):
            results["spf"] = "PASS"
        elif text.startswith("fail"):
            results["spf"] = "FAIL"
        elif text.startswith("softfail"):
            results["spf"] = "SOFTFAIL"
        elif text.startswith("neutral"):
            results["spf"] = "NEUTRAL"

    return results
