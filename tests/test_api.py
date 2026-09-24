import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import init_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    """Assicura l'inizializzazione del database SQLite prima dei test."""
    init_db()


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


def test_cve_detail_page_regression():
    """M0.1 Regression test: /cve/{cve_id} carica il template senza produrre TemplateNotFound"""
    response = client.get("/cve/1")
    assert response.status_code == 200
    assert "Dettaglio CVE" in response.text


def test_critical_vulns_partial_regression():
    """M0.2 Regression test: /api/dashboard/critical-vulns restituisce partial senza NameError"""
    response = client.get("/api/dashboard/critical-vulns")
    assert response.status_code == 200


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


@pytest.mark.skip(reason="Richiede connessione API NVD esterna / rate limit")
def test_cve_sync_nvd():
    """Sync NVD (richiede API key o rate limit pubblico)"""
    response = client.post("/api/cve/sync/nvd?days=1")
    assert response.status_code == 200
    data = response.json()
    assert "imported" in data
    assert "updated" in data
    assert "errors" in data