import pytest
import os
from backend.parser.email_parser import parse_eml

def test_parse_phishing_eml():
    eml_path = os.path.join("samples", "phishing.eml")
    assert os.path.exists(eml_path)

    with open(eml_path, "rb") as f:
        data = f.read()

    evidence = parse_eml(data)

    assert "paypa1-security.com" in evidence["sender_domain"]
    assert "attacker.collect@gmail.com" in evidence["reply_to"]
    assert len(evidence["received_ips"]) > 0
    assert len(evidence["urls"]) > 0
    assert len(evidence["attachments"]) > 0
    assert evidence["attachments"][0]["filename"] == "Account_Update_Form.docm"

def test_parse_legitimate_eml():
    eml_path = os.path.join("samples", "legitimate.eml")
    assert os.path.exists(eml_path)

    with open(eml_path, "rb") as f:
        data = f.read()

    evidence = parse_eml(data)

    assert "acme-corp.com" in evidence["sender_domain"]
    assert evidence["sender_domain"] == evidence["reply_to_domain"]
    assert len(evidence["received_ips"]) > 0
