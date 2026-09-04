from backend.detection.lookalike import detect_lookalike_domain, levenshtein_distance

def test_levenshtein():
    assert levenshtein_distance("paypal", "paypal") == 0
    assert levenshtein_distance("paypa1", "paypal") == 1
    assert levenshtein_distance("paypall", "paypal") == 1

def test_detect_lookalike():
    res1 = detect_lookalike_domain("paypa1-security.com")
    assert res1["lookalike"] is True
    assert res1["reference"] == "paypal.com"
    assert res1["similarity_score"] >= 0.75

    res2 = detect_lookalike_domain("acme-corp.com")
    assert res2["lookalike"] is False
