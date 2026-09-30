import pytest
from unittest.mock import AsyncMock, patch
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
    """Pagina dashboard carica con utente autenticato"""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    response = client.get("/", cookies={"session_token": token})
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
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    response = client.get("/cve/1", cookies={"session_token": token})
    assert response.status_code == 200
    assert "Dettaglio" in response.text


def test_critical_vulns_partial_regression():
    """M0.2 Regression test: /api/dashboard/critical-vulns restituisce partial senza NameError"""
    response = client.get("/api/dashboard/critical-vulns")
    assert response.status_code == 200


def test_overview_cards_partial():
    """Test partial HTML overview cards per dashboard"""
    response = client.get("/api/dashboard/overview-cards")
    assert response.status_code == 200
    assert "Asset Totali" in response.text


def test_asset_crud():
    """CRUD Asset base con utente autenticato admin"""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    cookies = {"session_token": token}

    # Create
    response = client.post("/api/assets", json={
        "tipo": "software",
        "nome": "TestApp",
        "vendor": "TestVendor",
        "versione": "1.0.0"
    }, cookies=cookies)
    assert response.status_code == 201
    asset = response.json()
    assert asset["nome"] == "TestApp"
    asset_id = asset["id"]
    
    # Read
    response = client.get(f"/api/assets/{asset_id}", cookies=cookies)
    assert response.status_code == 200
    
    # Update
    response = client.patch(f"/api/assets/{asset_id}", json={"versione": "2.0.0"}, cookies=cookies)
    assert response.status_code == 200
    assert response.json()["versione"] == "2.0.0"
    
    # Delete
    response = client.delete(f"/api/assets/{asset_id}", cookies=cookies)
    assert response.status_code == 204


def test_bulk_delete_assets():
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    cookies = res_login.cookies

    # Create 2 test assets
    a1 = client.post("/api/assets", json={"tipo": "software", "nome": "BulkApp1", "vendor": "BulkVendor1"}, cookies=cookies).json()
    a2 = client.post("/api/assets", json={"tipo": "software", "nome": "BulkApp2", "vendor": "BulkVendor2"}, cookies=cookies).json()

    # Bulk delete
    res = client.post("/api/assets/bulk-delete", json={"asset_ids": [a1["id"], a2["id"]]}, cookies=cookies)
    assert res.status_code == 200
    assert res.json()["deleted_count"] == 2

    # Verify deleted
    assert client.get(f"/api/assets/{a1['id']}", cookies=cookies).status_code == 404
    assert client.get(f"/api/assets/{a2['id']}", cookies=cookies).status_code == 404


def test_htmx_table_responses():
    """Verifica allineamento colonne HTMX per syslog, feed, vulnerabilita, perimetro"""
    r_syslog = client.get("/api/syslog", headers={"HX-Request": "true"})
    assert r_syslog.status_code == 200
    assert 'colspan="7"' in r_syslog.text or '</td>' in r_syslog.text

    r_cards = client.get("/api/dashboard/syslog-header-cards")
    assert r_cards.status_code == 200
    assert "Totale Log" in r_cards.text

    r_feed = client.get("/api/feed", headers={"HX-Request": "true"})
    assert r_feed.status_code == 200
    assert 'colspan="5"' in r_feed.text or '</td>' in r_feed.text

    r_vulns = client.get("/api/vulnerabilita", headers={"HX-Request": "true"})
    assert r_vulns.status_code == 200
    assert 'colspan="8"' in r_vulns.text or '</td>' in r_vulns.text

    r_perimetro = client.get("/api/perimetro", headers={"HX-Request": "true"})
    assert r_perimetro.status_code == 200
    assert 'colspan="6"' in r_perimetro.text or '</td>' in r_perimetro.text


def test_cve_sync_nvd():
    """Sync NVD offline con mock e utente autenticato admin"""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]

    mock_nvd_data = {"vulnerabilities": [], "totalResults": 0}
    with patch("app.services.sync_worker.nvd_client.fetch_recent", AsyncMock(return_value=mock_nvd_data)):
        response = client.post("/api/cve/sync/nvd?days=1", cookies={"session_token": token})
        assert response.status_code == 200
        data = response.json()
        assert "imported" in data
        assert "updated" in data
        assert "errors" in data


def test_admin_users_page():
    """TASK-M4: Verifico caricamento pagina amministrazione utenti /admin/users per admin"""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    token = res_login.json()["access_token"]
    response = client.get("/admin/users", cookies={"session_token": token})
    assert response.status_code == 200
    assert "Pannello Amministrazione" in response.text


import json

def test_provider_management_and_misp_ioc_ingestion():
    """Test completo per gestione Fornitori (Provider) e Ingestion/Deduplicazione IoC"""
    res_login = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert res_login.status_code == 200
    cookies = res_login.cookies

    # 1. Create Provider with scopes
    p_res = client.post("/api/providers", json={
        "code": "misp_test_provider",
        "name": "Test MISP Provider",
        "description": "Provider per test CTI",
        "scopes": ["MISP_IOC", "FEED_CTI"],
        "api_key": "test_api_key_123",
        "endpoint_url": "https://misp.example.com/api"
    }, cookies=cookies)
    assert p_res.status_code == 201
    p_data = p_res.json()
    assert p_data["code"] == "misp_test_provider"
    assert "MISP_IOC" in p_data["scopes"]

    # 2. List Providers
    list_res = client.get("/api/providers?scope=MISP_IOC", cookies=cookies)
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 1

    # 3. Async Multi-File Import IoCs
    misp_json_sample = json.dumps({
        "Event": {
            "info": "Test Campaign APT",
            "threat_level_id": "1",
            "Attribute": [
                {"type": "ip-dst", "value": "198.51.100.42", "comment": "C2 server"},
                {"type": "md5", "value": "e1170b8dd9919b33b50055e036511242", "comment": "Malware payload"}
            ]
        }
    }).encode("utf-8")

    files = [
        ("files", ("sample_misp.json", misp_json_sample, "application/json"))
    ]
    data = {"provider_name": "Test MISP Provider"}

    imp_res = client.post("/api/misp-ioc/import/async", files=files, data=data, cookies=cookies)
    assert imp_res.status_code == 200
    assert imp_res.json()["records_imported"] == 2

    # 4. Re-import same IoC to verify deduplication
    imp_res2 = client.post("/api/misp-ioc/import/async", files=files, data={"provider_name": "Second Source"}, cookies=cookies)
    assert imp_res2.status_code == 200

    # 5. Get IoC list & check HTMX response
    r_ioc = client.get("/api/misp-ioc", headers={"HX-Request": "true"}, cookies=cookies)
    assert r_ioc.status_code == 200
    assert "198.51.100.42" in r_ioc.text
    assert "e1170b8dd9919b33b50055e036511242" in r_ioc.text

    # 6. Test HTML page route
    r_page = client.get("/misp-ioc", cookies=cookies)
    assert r_page.status_code == 200
    assert "Threat Intelligence (MISP & IOC)" in r_page.text