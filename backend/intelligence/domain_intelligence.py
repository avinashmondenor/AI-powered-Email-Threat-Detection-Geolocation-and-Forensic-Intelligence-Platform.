import tldextract
import dns.resolver
from typing import Dict, Any, List
from backend.config import settings

# Mock age & reputation database for sample domains
MOCK_DOMAINS = {
    "paypa1-security.com": {
        "age_days": 3,
        "reputation": "MALICIOUS",
        "registrar": "NameCheap Inc. (Anonymous)",
        "suspicious_patterns": ["character_substitution", "recently_registered", "brand_impersonation"]
    },
    "it-desk-portal.net": {
        "age_days": 7,
        "reputation": "SUSPICIOUS",
        "registrar": "RegRu LLC",
        "suspicious_patterns": ["recently_registered", "generic_keywords"]
    },
    "fastmail-temp.com": {
        "age_days": 12,
        "reputation": "SUSPICIOUS",
        "registrar": "Tucows Domains",
        "suspicious_patterns": ["disposable_email_domain", "recently_registered"]
    },
    "supplier-update.com": {
        "age_days": 5,
        "reputation": "SUSPICIOUS",
        "registrar": "Shinjiru Host",
        "suspicious_patterns": ["recently_registered", "financial_keyword"]
    },
    "acme-corp.com": {
        "age_days": 4200,
        "reputation": "CLEAN",
        "registrar": "GoDaddy.com LLC",
        "suspicious_patterns": []
    },
    "company-hq.com": {
        "age_days": 2100,
        "reputation": "CLEAN",
        "registrar": "MarkMonitor Inc.",
        "suspicious_patterns": []
    },
    "paypal.com": {
        "age_days": 9800,
        "reputation": "CLEAN",
        "registrar": "CSC Corporate Domains",
        "suspicious_patterns": []
    }
}

def analyze_domain(domain_str: str) -> Dict[str, Any]:
    if not domain_str:
        return {
            "domain": "",
            "registrable_domain": "",
            "subdomain": "",
            "age_days": None,
            "reputation": "UNKNOWN",
            "is_new_domain": False,
            "mx_records": [],
            "is_mock": True
        }

    ext = tldextract.extract(domain_str)
    reg_domain = ext.registered_domain or domain_str
    subdomain = ext.subdomain

    # DNS MX lookup
    mx_records = []
    try:
        answers = dns.resolver.resolve(reg_domain, 'MX', lifetime=2.0)
        for rdata in answers:
            mx_records.append(rdata.exchange.to_text().strip('.'))
    except Exception:
        pass

    # Check mock DB
    if reg_domain in MOCK_DOMAINS:
        mock_info = MOCK_DOMAINS[reg_domain]
        age_days = mock_info["age_days"]
        reputation = mock_info["reputation"]
        patterns = mock_info["suspicious_patterns"]
    else:
        # Defaults for unknown domain
        age_days = 365
        reputation = "UNKNOWN"
        patterns = []

    is_new = age_days is not None and age_days < 30

    return {
        "domain": domain_str,
        "registrable_domain": reg_domain,
        "subdomain": subdomain,
        "age_days": age_days,
        "reputation": reputation,
        "is_new_domain": is_new,
        "mx_records": mx_records,
        "suspicious_patterns": patterns,
        "is_mock": settings.USE_MOCK_INTELLIGENCE
    }

def analyze_domains(domains: List[str]) -> List[Dict[str, Any]]:
    return [analyze_domain(d) for d in domains if d]
