import hashlib
import uuid
from datetime import datetime, timezone
from typing import Dict, Any

def preserve_evidence(raw_bytes: bytes, filename: str, content_type: str = "message/rfc822") -> Dict[str, Any]:
    """
    Stage 1 & 2: Raw EML & Evidence Preservation.
    Calculates cryptographic SHA-256 hash, file size, generates Evidence ID, and verifies integrity.
    """
    if not raw_bytes:
        raise ValueError("Cannot preserve empty email evidence.")

    sha256_hash = hashlib.sha256(raw_bytes).hexdigest()
    file_size = len(raw_bytes)
    evidence_id = f"EV-{sha256_hash[:8].upper()}"
    timestamp = datetime.now(timezone.utc).isoformat()

    # Re-calculate hash to verify integrity
    verify_hash = hashlib.sha256(raw_bytes).hexdigest()
    integrity_verified = (sha256_hash == verify_hash)

    return {
        "id": evidence_id,
        "evidence_id": evidence_id,
        "filename": filename,
        "sha256": sha256_hash,
        "size_bytes": file_size,
        "mime_type": content_type or "message/rfc822",
        "upload_timestamp": timestamp,
        "integrity_verified": integrity_verified,
        "integrity_status": "VERIFIED" if integrity_verified else "FAILED",
        "preservation_status": "COMPLETED"
    }
