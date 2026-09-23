import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    """Health endpoint risponde"""
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_dashboard_page():
    """Pagina dashboard carica"""
    response = client.get("/")
    assert response.status_code == 200
    assert "Security Dashboard" in response.text


def test_api_docs():
    """OpenAPI docs disponibili"""
    response = client.get("/docs")
    assert response.status_code == 200


def test_settings_init():
    """Init default settings"""
    response = client.post("/api/settings/init-defaults")
    assert response.status_code == 200
    data = response.json()
    assert "created" in data


# Test models (require DB)
@pytest.mark.skip(reason="Richiede database - run con docker compose")
def test_asset_crud():
    """CRUD Asset base"""
    # Create
    response = client.post("/api/assets", json={
        "tipo": "software",
        "nome": "TestApp",
        "vendor": "TestVendor",
        "versione": "1.0.0"
    })
    assert response.status_code == 201
    asset = response.json()
    assert asset["nome"] == "TestApp"
    asset_id = asset["id"]
    
    # Read
    response = client.get(f"/api/assets/{asset_id}")
    assert response.status_code == 200
    
    # Update
    response = client.patch(f"/api/assets/{asset_id}", json={"versione": "2.0.0"})
    assert response.status_code == 200
    assert response.json()["versione"] == "2.0.0"
    
    # Delete
    response = client.delete(f"/api/assets/{asset_id}")
    assert response.status_code == 204


@pytest.mark.skip(reason="Richiede database - run con docker compose")
def test_cve_sync_nvd():
    """Sync NVD (richiede API key o rate limit pubblico)"""
    response = client.post("/api/cve/sync/nvd?days=1")
    assert response.status_code == 200
    data = response.json()
    assert "imported" in data
    assert "updated" in data
    assert "errors" in data