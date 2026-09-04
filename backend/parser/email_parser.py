import email
import email.policy
from typing import Dict, Any
from backend.parser.header_extractor import extract_domain, parse_received_headers, parse_auth_headers
from backend.parser.url_extractor import extract_urls
from backend.parser.attachment_extractor import extract_attachments

def parse_eml(eml_bytes: bytes) -> Dict[str, Any]:
    """
    Parses raw .eml bytes into normalized evidence model.
    """
    msg = email.message_from_bytes(eml_bytes, policy=email.policy.default)

    # Extract primary headers
    from_header = str(msg.get("From", ""))
    to_header = str(msg.get("To", ""))
    cc_header = str(msg.get("Cc", ""))
    reply_to_header = str(msg.get("Reply-To", ""))
    subject_header = str(msg.get("Subject", ""))
    date_header = str(msg.get("Date", ""))
    message_id_header = str(msg.get("Message-ID", ""))
    return_path_header = str(msg.get("Return-Path", ""))

    sender_domain = extract_domain(from_header)
    reply_to_domain = extract_domain(reply_to_header) if reply_to_header else sender_domain

    # Received headers
    received_headers = [str(h) for h in msg.get_all("Received", [])]
    received_data = parse_received_headers(received_headers)

    # Observed Auth headers
    auth_results_header = msg.get("Authentication-Results")
    received_spf_header = msg.get("Received-SPF")
    auth_results = parse_auth_headers(
        str(auth_results_header) if auth_results_header else None,
        str(received_spf_header) if received_spf_header else None
    )

    # Body extraction
    body_text = ""
    body_html = ""

    if msg.is_multipart():
        for part in msg.walk():
            ctype = part.get_content_type()
            cdisp = str(part.get('Content-Disposition', ''))
            if 'attachment' in cdisp:
                continue
            if ctype == 'text/plain' and not body_text:
                try:
                    body_text = part.get_content()
                except Exception:
                    pass
            elif ctype == 'text/html' and not body_html:
                try:
                    body_html = part.get_content()
                except Exception:
                    pass
    else:
        ctype = msg.get_content_type()
        if ctype == 'text/plain':
            try:
                body_text = msg.get_content()
            except Exception:
                pass
        elif ctype == 'text/html':
            try:
                body_html = msg.get_content()
            except Exception:
                pass

    # Extract URLs & Attachments
    urls = extract_urls(body_text, body_html)
    attachments = extract_attachments(msg)

    # Extract distinct domains from URLs and headers
    domains = set()
    if sender_domain:
        domains.add(sender_domain)
    if reply_to_domain:
        domains.add(reply_to_domain)
    for u in urls:
        if u.get("domain"):
            domains.add(u["domain"])

    return {
        "headers": {
            "from": from_header,
            "to": to_header,
            "cc": cc_header,
            "reply_to": reply_to_header,
            "subject": subject_header,
            "date": date_header,
            "message_id": message_id_header,
            "return_path": return_path_header,
            "dkim_signature": str(msg.get("DKIM-Signature", ""))
        },
        "sender": from_header,
        "sender_domain": sender_domain,
        "reply_to": reply_to_header or from_header,
        "reply_to_domain": reply_to_domain,
        "subject": subject_header,

        "received_ips": received_data["ips"],
        "received_hosts": received_data["hosts"],
        "received_hops": received_data["hops"],

        "authentication_results": auth_results,

        "urls": urls,
        "domains": list(domains),
        "attachments": attachments,

        "body_text": body_text,
        "body_html": body_html
    }
