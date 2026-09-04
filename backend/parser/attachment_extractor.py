import hashlib
import os
import email.message
from typing import List, Dict, Any

HIGH_RISK_EXTENSIONS = {
    ".exe", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".lnk", ".iso", ".img",
    ".docm", ".xlsm", ".pptm", ".js", ".jse", ".wsf", ".wsh", ".hta", ".cpl"
}

def extract_attachments(msg: email.message.Message) -> List[Dict[str, Any]]:
    attachments = []

    for part in msg.walk():
        if part.get_content_maintype() == 'multipart':
            continue
        
        filename = part.get_filename()
        content_disposition = part.get("Content-Disposition", "")

        # Check if it's explicitly an attachment or has a filename
        if not filename and "attachment" not in content_disposition.lower():
            continue

        if not filename:
            filename = f"unnamed_attachment_{len(attachments)+1}.dat"

        payload = part.get_payload(decode=True)
        if payload is None:
            payload = b""

        size = len(payload)
        sha256 = hashlib.sha256(payload).hexdigest()
        
        _, ext = os.path.splitext(filename)
        ext = ext.lower()

        # Check for double extension e.g., invoice.pdf.exe
        parts = filename.split(".")
        is_double_ext = len(parts) > 2 and f".{parts[-1].lower()}" in HIGH_RISK_EXTENSIONS

        is_suspicious_ext = ext in HIGH_RISK_EXTENSIONS or is_double_ext

        attachments.append({
            "filename": filename,
            "extension": ext,
            "mime_type": part.get_content_type(),
            "size_bytes": size,
            "sha256": sha256,
            "is_suspicious_extension": is_suspicious_ext,
            "is_double_extension": is_double_ext
        })

    return attachments
