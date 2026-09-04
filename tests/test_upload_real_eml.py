import os
import pytest
from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_real_eml_upload():
    eml_path = os.path.join("samples", "phishing.eml")
    assert os.path.exists(eml_path)

    with open(eml_path, "rb") as f:
        file_bytes = f.read()

    response = client.post(
        "/api/analyze",
        files={"file": ("phishing.eml", file_bytes, "message/rfc822")}
    )

    assert response.status_code == 200
    data = response.json()

    assert data["success"] is True
    assert data["evidence"]["integrity_status"] == "VERIFIED"
    assert data["verdict"] in ("Malicious", "Suspicious", "Clean")
    assert data["risk_score"] >= 80
    assert "header_forensics" in data
    assert "origin_reconstruction" in data
    assert "infrastructure" in data
    assert "campaign" in data
    assert "confidence" in data
    assert "findings" in data
