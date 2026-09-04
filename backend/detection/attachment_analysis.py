from typing import List, Dict, Any

MACRO_EXTENSIONS = {".docm", ".xlsm", ".pptm"}
EXEC_EXTENSIONS = {".exe", ".vbs", ".ps1", ".bat", ".cmd", ".scr", ".lnk", ".iso", ".js"}

def analyze_attachments(attachments: List[Dict[str, Any]]) -> Dict[str, Any]:
    has_suspicious = False
    has_double_ext = False
    has_macro = False
    has_executable = False
    flagged_files = []

    for att in attachments:
        ext = att.get("extension", "").lower()
        is_double = att.get("is_double_extension", False)
        
        reasons = []
        if is_double:
            has_double_ext = True
            reasons.append("double_extension_detected")
        if ext in MACRO_EXTENSIONS:
            has_macro = True
            reasons.append("macro_enabled_document")
        if ext in EXEC_EXTENSIONS:
            has_executable = True
            reasons.append("executable_file_format")

        if reasons:
            has_suspicious = True
            flagged_files.append({
                "filename": att.get("filename"),
                "extension": ext,
                "reasons": reasons,
                "sha256": att.get("sha256")
            })

    return {
        "has_attachments": len(attachments) > 0,
        "suspicious_attachment": has_suspicious,
        "has_double_extension": has_double_ext,
        "has_macro_document": has_macro,
        "has_executable": has_executable,
        "flagged_attachments": flagged_files,
        "total_attachments": len(attachments)
    }
