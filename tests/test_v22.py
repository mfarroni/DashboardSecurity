import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import init_db
from app.services.notifier import notifier

client = TestClient(app)

@pytest.fixture(autouse=True)
def setup_db():
    init_db()

def get_admin_cookie():
    res = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    token = res.json().get("access_token")
    return {"session_token": token}

def test_reports_csv_export():
    cookies = get_admin_cookie()
    res = client.get("/api/reports/perimeter/csv", cookies=cookies)
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]

def test_misp_ioc_reports_csv_export():
    cookies = get_admin_cookie()
    res = client.get("/api/reports/misp-ioc/csv", cookies=cookies)
    assert res.status_code == 200
    assert "text/csv" in res.headers["content-type"]

def test_vulnerabilities_pdf_report():
    cookies = get_admin_cookie()
    res = client.get("/api/reports/vulnerabilities/pdf", cookies=cookies)
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]
    assert "Report Esecutivo Vulnerabilità Perimetro" in res.text

@pytest.mark.asyncio
async def test_notifier_service():
    res = await notifier.send_alert(
        title="Test Alert",
        message="Messaggio di test",
        severity="HIGH",
        channels=[]
    )
    assert isinstance(res, dict)
