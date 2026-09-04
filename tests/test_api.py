from fastapi.testclient import TestClient
from backend.main import app

client = TestClient(app)

def test_health_endpoint():
    response = client.get("/api/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_sample_analyze():
    response = client.get("/api/samples/phishing")
    assert response.status_code == 200
    data = response.json()
    assert data["classification"] == "CRITICAL"
    assert data["risk_score"] >= 80
    assert "email" in data
    assert "authentication" in data
    assert "reasons" in data
