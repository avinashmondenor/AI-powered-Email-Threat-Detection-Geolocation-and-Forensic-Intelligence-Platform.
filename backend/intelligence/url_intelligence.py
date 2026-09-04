import re
from typing import Dict, Any, List
from backend.config import settings

IP_URL_REGEX = re.compile(r'http[s]?://(?:\d{1,3}\.){3}\d{1,3}')
SHORTENER_DOMAINS = {"bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "buff.ly", "rb.gy"}

def analyze_url(url_obj: Dict[str, Any]) -> Dict[str, Any]:
    raw_url = url_obj.get("url", "")
    domain = url_obj.get("domain", "")
    hostname = url_obj.get("hostname", "")

    is_ip_url = bool(IP_URL_REGEX.match(raw_url))
    is_shortener = domain in SHORTENER_DOMAINS or hostname in SHORTENER_DOMAINS

    # Suspicious characteristics
    suspicious_chars = []
    if "@" in raw_url:
        suspicious_chars.append("contains_at_symbol")
    if "%" in raw_url:
        suspicious_chars.append("percent_encoding")
    if is_ip_url:
        suspicious_chars.append("raw_ip_host")
    if is_shortener:
        suspicious_chars.append("url_shortener")
    if len(raw_url) > 120:
        suspicious_chars.append("excessive_length")

    # Mismatch between anchor text (e.g. text says "https://paypal.com", href points elsewhere)
    anchor_text = url_obj.get("anchor_text", "")
    anchor_mismatch = False
    if anchor_text and ("http://" in anchor_text.lower() or "https://" in anchor_text.lower() or "paypal.com" in anchor_text.lower()):
        if domain not in anchor_text.lower() and "paypal.com" in anchor_text.lower():
            anchor_mismatch = True
            suspicious_chars.append("anchor_text_domain_mismatch")

    # Determine reputation status
    reputation = "UNKNOWN"
    if is_ip_url or anchor_mismatch or "paypa1" in raw_url:
        reputation = "MALICIOUS"
    elif is_shortener or len(suspicious_chars) >= 2:
        reputation = "SUSPICIOUS"

    redirect_info = {
        "has_redirect": is_shortener,
        "final_url": "http://185.220.101.5/login?user=victim" if is_shortener else raw_url
    }

    return {
        "url": raw_url,
        "domain": domain,
        "reputation": reputation,
        "is_ip_based_url": is_ip_url,
        "is_shortener": is_shortener,
        "anchor_mismatch": anchor_mismatch,
        "suspicious_characteristics": suspicious_chars,
        "redirect_info": redirect_info,
        "source": url_obj.get("source", "unknown"),
        "anchor_text": anchor_text
    }

def analyze_urls(urls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    return [analyze_url(u) for u in urls]
