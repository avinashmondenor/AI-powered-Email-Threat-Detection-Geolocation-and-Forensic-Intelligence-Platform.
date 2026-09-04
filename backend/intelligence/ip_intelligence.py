import httpx
from typing import Dict, Any, List
from backend.config import settings

class IPIntelligenceProvider:
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        raise NotImplementedError

class MockIPIntelligenceProvider(IPIntelligenceProvider):
    """
    Mock IP provider returning deterministic demo data for test IPs.
    Explicitly flags results as DEMO / MOCK.
    """
    # Demo DB of known sample IPs
    MOCK_DB = {
        "185.220.101.5": {
            "country": "Germany",
            "city": "Frankfurt",
            "asn": "AS205100",
            "organization": "Tor Exit Node Relay",
            "isp": "Zwiebel Network",
            "vpn": True,
            "proxy": True,
            "tor": True,
            "hosting": True
        },
        "198.51.100.23": {
            "country": "Netherlands",
            "city": "Amsterdam",
            "asn": "AS49544",
            "organization": "Hostinger Datacenter",
            "isp": "Hostinger International",
            "vpn": False,
            "proxy": False,
            "tor": False,
            "hosting": True
        },
        "209.85.220.41": {
            "country": "United States",
            "city": "Mountain View",
            "asn": "AS15169",
            "organization": "Google LLC",
            "isp": "Google Workspace Mail Relay",
            "vpn": False,
            "proxy": False,
            "tor": False,
            "hosting": True
        },
        "103.253.144.12": {
            "country": "Vietnam",
            "city": "Hanoi",
            "asn": "AS131435",
            "organization": "Untrusted Telecom Relay",
            "isp": "VNPT",
            "vpn": True,
            "proxy": True,
            "tor": False,
            "hosting": False
        },
        "45.142.214.88": {
            "country": "Russia",
            "city": "Moscow",
            "asn": "AS58271",
            "organization": "Bulletproof VPS Host",
            "isp": "Chocoping LLC",
            "vpn": False,
            "proxy": True,
            "tor": False,
            "hosting": True
        },
        "185.180.143.10": {
            "country": "Romania",
            "city": "Bucharest",
            "asn": "AS200019",
            "organization": "M247 Europe",
            "isp": "M247 Ltd",
            "vpn": True,
            "proxy": False,
            "tor": False,
            "hosting": True
        }
    }

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if ip in self.MOCK_DB:
            res = self.MOCK_DB[ip].copy()
        else:
            # Default fallback mock for arbitrary IP
            res = {
                "country": "United States",
                "city": "Ashburn",
                "asn": "AS14618",
                "organization": "Amazon Data Services",
                "isp": "AWS Cloud",
                "vpn": False,
                "proxy": False,
                "tor": False,
                "hosting": True
            }
        res["ip"] = ip
        res["is_mock"] = True
        res["provider"] = "Mock IP Intelligence Engine"
        return res

class LiveIPIntelligenceProvider(IPIntelligenceProvider):
    """
    Live API provider using ip-api.com or AbuseIPDB when available, with fallback to Mock.
    """
    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=3.0) as client:
                resp = client.get(f"http://ip-api.com/json/{ip}?fields=status,message,country,city,asn,org,isp,hosting")
                if resp.status_code == 200:
                    data = resp.json()
                    if data.get("status") == "success":
                        return {
                            "ip": ip,
                            "country": data.get("country", "Unknown"),
                            "city": data.get("city", "Unknown"),
                            "asn": data.get("asn", "Unknown"),
                            "organization": data.get("org", "Unknown"),
                            "isp": data.get("isp", "Unknown"),
                            "vpn": False, # ip-api free doesn't include VPN flag
                            "proxy": False,
                            "tor": False,
                            "hosting": data.get("hosting", False),
                            "is_mock": False,
                            "provider": "ip-api.com Live API"
                        }
        except Exception:
            pass

        # Fallback to Mock if API is unavailable or fails
        mock = MockIPIntelligenceProvider()
        res = mock.lookup_ip(ip)
        res["details"] = "Live API unavailable, fell back to internal intelligence provider."
        return res

def get_ip_intelligence_provider() -> IPIntelligenceProvider:
    if settings.USE_MOCK_INTELLIGENCE:
        return MockIPIntelligenceProvider()
    return LiveIPIntelligenceProvider()

def analyze_ips(ip_list: List[str]) -> List[Dict[str, Any]]:
    provider = get_ip_intelligence_provider()
    results = []
    for ip in ip_list:
        results.append(provider.lookup_ip(ip))
    return results
