import pytest
from unittest.mock import AsyncMock, patch
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import init_db, engine
from app.services.sync_worker import sync_worker
from app.services.correlation import search_fts_cves
from app.models.models import Asset

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    init_db()


@pytest.mark.asyncio
async def test_sync_worker_non_overlap():
    """Verifica che due esecuzioni contemporanee di sync_nvd attivino il lock non-overlap."""
    mock_fetch = AsyncMock(return_value={"vulnerabilities": [], "totalResults": 0})
    with patch("app.api.cve.nvd_client.fetch_recent", side_effect=mock_fetch):
        # Primo run sblocca
        res1 = await sync_worker.run_nvd_sync(days=1)
        assert res1["status"] in ["success", "completed"]

        # Simulate lock acquisito
        async with sync_worker._nvd_lock:
            res2 = await sync_worker.run_nvd_sync(days=1)
            assert res2["status"] == "skipped"
            assert "non-overlap" in res2["reason"]


def test_fts5_cve_search():
    """Verifica funzionamento lookup FTS5 per SQLite."""
    if "sqlite" in str(engine.url):
        asset = Asset(vendor="Apache", nome="HTTP Server", versione="2.4.50")
        cves = search_fts_cves(None, asset)
        assert isinstance(cves, list)


def test_cve_sync_nvd_api_endpoint():
    """TASK-10: Test endpoint /api/cve/sync/nvd con utente autenticato admin e mock NVD."""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    mock_nvd_data = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-99999",
                    "descriptions": [{"lang": "en", "value": "Test mock CVE description"}],
                    "published": "2024-09-01T00:00:00.000",
                    "lastModified": "2024-09-02T00:00:00.000"
                }
            }
        ],
        "totalResults": 1
    }

    with patch("app.api.cve.nvd_client.fetch_recent", AsyncMock(return_value=mock_nvd_data)):
        res = client.post("/api/cve/sync/nvd?days=1", cookies={"session_token": token})
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "success"
        assert data["imported"] == 1
