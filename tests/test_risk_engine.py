from backend.risk.scoring import calculate_risk_score

def test_risk_scoring_phishing():
    features = {
        "lookalike_domain": True,
        "dmarc_fail": True,
        "reply_to_mismatch": True,
        "suspicious_url": True,
        "credential_request": True,
        "tor_detected": True,
        "urgency_language": True,
        "spf_fail": True
    }
    res = calculate_risk_score(features)
    assert res["risk_score"] >= 80
    assert res["classification"] == "CRITICAL"
    assert len(res["reasons"]) >= 5

def test_risk_scoring_clean():
    features = {
        "lookalike_domain": False,
        "dmarc_fail": False,
        "reply_to_mismatch": False,
        "suspicious_url": False
    }
    res = calculate_risk_score(features)
    assert res["risk_score"] < 30
    assert res["classification"] == "LOW"
