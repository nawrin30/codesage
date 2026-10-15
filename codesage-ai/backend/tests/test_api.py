import os
os.environ["DATABASE_URL"] = "sqlite:///./test_codesage.db"
os.environ["JWT_SECRET"] = "test-secret-for-tests"
from fastapi.testclient import TestClient
from app.main import app
client = TestClient(app)

def test_health():
    assert client.get("/api/health").json()["status"] == "ok"

def token_for(email="test@example.com"):
    response = client.post("/api/auth/register", json={"email": email, "password": "verysecure123"})
    if response.status_code == 409:
        response = client.post("/api/auth/login", json={"email": email, "password": "verysecure123"})
    assert response.status_code in (200, 201)
    return response.json()["access_token"]

def test_review_syntax_and_history():
    token = token_for("syntax@example.com")
    headers = {"Authorization": f"Bearer {token}"}
    r = client.post("/api/reviews", headers=headers, json={"title":"bad syntax","code":"def broken(:\\n pass"})
    assert r.status_code == 200
    assert r.json()["findings"][0]["rule_id"] == "PY-SYNTAX"
    assert client.get("/api/reviews", headers=headers).status_code == 200

def test_detect_dynamic_execution():
    token = token_for("security@example.com")
    r = client.post("/api/reviews", headers={"Authorization":f"Bearer {token}"},
                    json={"title":"security","code":"eval(user_input)"})
    assert r.status_code == 200
    assert any(f["rule_id"] == "PY-DYNAMIC-EXEC" for f in r.json()["findings"])
