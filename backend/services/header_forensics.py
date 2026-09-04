import re
import email.utils
from typing import Dict, Any, List
from backend.parser.header_extractor import extract_domain
from backend.detection.lookalike import detect_lookalike_domain

def extract_display_name(from_header: str) -> str:
    if not from_header:
        return ""
    try:
        name, addr = email.utils.parseaddr(str(from_header))
        return name.strip()
    except Exception:
        return ""

def analyze_header_forensics(evidence: Dict[str, Any], eml_msg: Any = None) -> Dict[str, Any]:
    """
    Stage 3: Threat & Header Forensics Analysis.
    Defensively handles null or missing headers.
    """
    evidence = evidence or {}
    headers = evidence.get("headers") or {}
    
    from_raw = str(headers.get("from") or "")
    to_raw = str(headers.get("to") or "")
    cc_raw = str(headers.get("cc") or "")
    reply_to_raw = str(headers.get("reply_to") or "")
    return_path_raw = str(headers.get("return_path") or "")
    subject = str(headers.get("subject") or "")
    date = str(headers.get("date") or "")
    message_id = str(headers.get("message_id") or "")

    sender_domain = str(evidence.get("sender_domain") or "")
    reply_to_domain = str(evidence.get("reply_to_domain") or "")
    return_path_domain = extract_domain(return_path_raw) if return_path_raw else sender_domain

    display_name = extract_display_name(from_raw)

    # Display-Name Spoofing Detection
    display_name_spoofing = False
    spoofed_brand = ""
    known_brands = ["paypal", "microsoft", "google", "apple", "amazon", "chase", "bank of america", "wells fargo", "docusign", "hr department", "helpdesk"]
    if display_name:
        disp_lower = display_name.lower()
        for brand in known_brands:
            if brand in disp_lower:
                brand_key = brand.replace(" ", "")
                if sender_domain and brand_key not in sender_domain:
                    display_name_spoofing = True
                    spoofed_brand = brand
                    break

    # Mismatches
    reply_to_mismatch = bool(sender_domain and reply_to_domain and sender_domain != reply_to_domain)
    return_path_mismatch = bool(sender_domain and return_path_domain and sender_domain != return_path_domain)

    # X-Headers Extraction
    x_originating_ip = ""
    x_mailer = ""
    user_agent = ""
    custom_x_headers = {}

    if eml_msg:
        try:
            x_originating_ip = str(eml_msg.get("X-Originating-IP") or "")
            x_mailer = str(eml_msg.get("X-Mailer") or "")
            user_agent = str(eml_msg.get("User-Agent") or "")
            
            for k, v in eml_msg.items():
                if k and k.lower().startswith("x-") and k.lower() not in ("x-originating-ip", "x-mailer"):
                    custom_x_headers[str(k)] = str(v)
        except Exception:
            pass

    lookalike_info = detect_lookalike_domain(sender_domain, reply_to_domain)

    return {
        "headers": {
            "from": from_raw,
            "display_name": display_name,
            "to": to_raw,
            "cc": cc_raw,
            "reply_to": reply_to_raw,
            "return_path": return_path_raw,
            "subject": subject,
            "date": date,
            "message_id": message_id,
            "x_originating_ip": x_originating_ip,
            "x_mailer": x_mailer,
            "user_agent": user_agent,
            "x_headers": custom_x_headers
        },
        "identity_anomalies": {
            "display_name_spoofing": display_name_spoofing,
            "spoofed_brand": spoofed_brand,
            "reply_to_mismatch": reply_to_mismatch,
            "return_path_mismatch": return_path_mismatch,
            "sender_domain": sender_domain,
            "reply_to_domain": reply_to_domain,
            "return_path_domain": return_path_domain,
            "lookalike": lookalike_info
        }
    }
