import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.core.database import init_db, SessionLocal
from app.models.models import Asset, User

client = TestClient(app)


@pytest.fixture(autouse=True)
def setup_db():
    """Inizializza il database e gli utenti di default prima di ciascun test."""
    init_db()


def get_login_cookie(username: str, password: str = "admin123") -> dict:
    if username == "analyst":
        password = "analyst123"
    elif username == "readonly":
        password = "readonly123"
        
    response = client.post("/api/auth/login", json={"username": username, "password": password})
    assert response.status_code == 200
    token = response.json()["access_token"]
    return {"session_token": token}


def test_login_success():
    """Login con credenziali corrette restituisce 200 e il token"""
    response = client.post("/api/auth/login", json={"username": "admin", "password": "admin123"})
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["username"] == "admin"
    assert data["user"]["role"] == "admin"


def test_login_invalid_password():
    """Login con password errata restituisce 401"""
    response = client.post("/api/auth/login", json={"username": "admin", "password": "wrongpassword"})
    assert response.status_code == 401


def test_rbac_admin_capability():
    """Admin può creare ed eliminare asset"""
    cookies = get_login_cookie("admin")
    
    # Create asset
    res_create = client.post("/api/assets", json={
        "tipo": "software",
        "nome": "AdminApp",
        "vendor": "AdminVendor",
        "versione": "1.0.0"
    }, cookies=cookies)
    assert res_create.status_code == 201
    asset_id = res_create.json()["id"]

    # Delete asset (Admin allowed)
    res_delete = client.delete(f"/api/assets/{asset_id}", cookies=cookies)
    assert res_delete.status_code == 204


def test_rbac_analyst_capability():
    """Analyst può creare asset ma NON eliminare"""
    cookies = get_login_cookie("analyst")
    
    # Create asset (Analyst allowed)
    res_create = client.post("/api/assets", json={
        "tipo": "software",
        "nome": "AnalystApp",
        "vendor": "AnalystVendor",
        "versione": "1.0.0"
    }, cookies=cookies)
    assert res_create.status_code == 201
    asset_id = res_create.json()["id"]

    # Delete asset (Analyst forbidden -> 403)
    res_delete = client.delete(f"/api/assets/{asset_id}", cookies=cookies)
    assert res_delete.status_code == 403


def test_rbac_readonly_capability():
    """ReadOnly NON può creare o eliminare asset"""
    cookies = get_login_cookie("readonly")
    
    # Create asset (ReadOnly forbidden -> 403)
    res_create = client.post("/api/assets", json={
        "tipo": "software",
        "nome": "ReadOnlyApp",
        "vendor": "ReadOnlyVendor",
        "versione": "1.0.0"
    }, cookies=cookies)
    assert res_create.status_code == 403


def test_unauthenticated_protected_route():
    """Utente non autenticato tenta modifica -> 401"""
    anon_client = TestClient(app)
    res = anon_client.post("/api/assets", json={
        "tipo": "software",
        "nome": "AnonApp",
        "vendor": "AnonVendor"
    })
    assert res.status_code == 401


def test_max_upload_size_middleware():
    """Payload superiori a 50MB vengono bloccati dal middleware (413 Payload Too Large)"""
    headers = {"Content-Length": str(60 * 1024 * 1024)}  # 60MB
    res = client.post("/api/assets", headers=headers, json={})
    assert res.status_code == 413
    assert "eccede" in res.json()["detail"]
