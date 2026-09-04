import tldextract

# Target reference domains commonly impersonated in phishing
REFERENCE_DOMAINS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com", "amazon.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "netflix.com",
    "linkedin.com", "facebook.com", "github.com", "microsoftonline.com",
    "office365.com", "outlook.com", "docusign.com"
]

CHARACTER_SUBSTITUTIONS = {
    '0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a', '5': 's',
    '8': 'b', '@': 'a', 'vv': 'w', 'rn': 'm', 'cl': 'd'
}

def get_registered_domain(domain_str: str) -> str:
    if not domain_str:
        return ""
    ext = tldextract.extract(domain_str)
    if hasattr(ext, 'top_domain_under_public_suffix') and ext.top_domain_under_public_suffix:
        return ext.top_domain_under_public_suffix
    if hasattr(ext, 'registered_domain') and ext.registered_domain:
        return ext.registered_domain
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return domain_str

def levenshtein_distance(s1: str, s2: str) -> int:
    """Computes Levenshtein edit distance between two strings."""
    if len(s1) < len(s2):
        return levenshtein_distance(s2, s1)

    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row

    return previous_row[-1]

def normalize_string(s: str) -> str:
    """Replaces common homoglyphs/typosquat substitutions with canonical letters."""
    norm = s.lower()
    for sub, canonical in CHARACTER_SUBSTITUTIONS.items():
        norm = norm.replace(sub, canonical)
    return norm

def detect_lookalike_domain(domain: str, recipient_domain: str = "") -> dict:
    """
    Checks if a domain is a look-alike / typosquat of major brands or the recipient's corporate domain.
    """
    if not domain:
        return {
            "lookalike": False,
            "reference": "",
            "similarity_score": 0.0,
            "reason": ""
        }

    candidate_reg = get_registered_domain(domain)
    candidate_name = candidate_reg.split(".")[0].lower()
    norm_candidate = normalize_string(candidate_name)

    # Build reference set
    ref_list = list(REFERENCE_DOMAINS)
    if recipient_domain:
        rec_reg = get_registered_domain(recipient_domain)
        if rec_reg and rec_reg not in ref_list:
            ref_list.append(rec_reg)

    best_match = None
    max_sim = 0.0
    reason = ""

    for ref in ref_list:
        ref_name = ref.split(".")[0].lower()
        if candidate_name == ref_name:
            continue  # Exact match is not a lookalike, it's the real domain

        norm_ref = normalize_string(ref_name)

        # 1. Exact match after character substitution normalization (e.g. paypa1 vs paypal)
        if norm_candidate == norm_ref:
            sim = 0.95
            if sim > max_sim:
                max_sim = sim
                best_match = ref
                reason = f"Character substitution detected in domain name ('{candidate_name}' vs '{ref_name}')"

        # 2. Levenshtein edit distance check on raw & normalized names
        dist_raw = levenshtein_distance(candidate_name, ref_name)
        dist_norm = levenshtein_distance(norm_candidate, norm_ref)
        min_dist = min(dist_raw, dist_norm)

        max_len = max(len(candidate_name), len(ref_name))
        if max_len > 0:
            sim = 1.0 - (min_dist / float(max_len))
            if min_dist in (1, 2) and len(ref_name) >= 4 and sim >= 0.75:
                if sim > max_sim:
                    max_sim = sim
                    best_match = ref
                    reason = f"Typosquatting edit distance of {min_dist} character(s) from reference brand '{ref}'"

        # 3. Substring / Hyphenated brand impersonation on normalized domain name (e.g. paypa1-security.com)
        if norm_ref in norm_candidate and len(norm_candidate) > len(norm_ref):
            sim = 0.90
            if sim > max_sim:
                max_sim = sim
                best_match = ref
                reason = f"Brand name '{ref}' impersonated in domain '{candidate_reg}'"

    if best_match and max_sim >= 0.75:
        return {
            "lookalike": True,
            "reference": best_match,
            "similarity_score": round(max_sim, 2),
            "reason": reason
        }

    return {
        "lookalike": False,
        "reference": "",
        "similarity_score": round(max_sim, 2),
        "reason": "No brand typosquatting detected"
    }
