import os
import sys

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "app"))
# The app refuses to start without a signing key; tests use a throwaway one
os.environ.setdefault("SECRET_KEY", "test-only-signing-key-" + "x" * 32)

from database import Base, get_db  # noqa: E402
from main import app  # noqa: E402

TEST_DB_URL = "sqlite:///./test_vulntracker.db"
engine = create_engine(TEST_DB_URL, connect_args={"check_same_thread": False})
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def override_get_db():
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()


app.dependency_overrides[get_db] = override_get_db
client = TestClient(app, raise_server_exceptions=False)


@pytest.fixture(autouse=True)
def reset_db():
    Base.metadata.create_all(bind=engine)
    yield
    Base.metadata.drop_all(bind=engine)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def register_and_login(username="alice", email="alice@example.com", password="password123"):
    client.post("/auth/register", json={"username": username, "email": email, "password": password})
    resp = client.post("/auth/login", json={"username": username, "password": password})
    return resp.json()["access_token"]


def auth_headers(token):
    return {"Authorization": f"Bearer {token}"}


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_health():
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_register_user():
    resp = client.post("/auth/register", json={
        "username": "bob",
        "email": "bob@example.com",
        "password": "secret",
    })
    assert resp.status_code == 201
    assert resp.json()["username"] == "bob"


def test_register_duplicate_username():
    payload = {"username": "bob", "email": "bob@example.com", "password": "secret"}
    client.post("/auth/register", json=payload)
    resp = client.post("/auth/register", json={**payload, "email": "bob2@example.com"})
    assert resp.status_code == 400


def test_login_success():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "pw"})
    assert resp.status_code == 200
    assert "access_token" in resp.json()


def test_login_wrong_password():
    client.post("/auth/register", json={"username": "alice", "email": "alice@example.com", "password": "pw"})
    resp = client.post("/auth/login", json={"username": "alice", "password": "wrong"})
    assert resp.status_code == 401


def test_create_scan():
    token = register_and_login()
    resp = client.post("/scans", json={
        "title": "Reflected XSS in search",
        "description": "User input is echoed without sanitisation",
        "severity": "high",
        "affected_component": "GET /search",
    }, headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["title"] == "Reflected XSS in search"


def test_list_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "Test finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans", headers=auth_headers(token))
    assert resp.status_code == 200
    assert len(resp.json()) == 1


def test_search_scans():
    token = register_and_login()
    client.post("/scans", json={
        "title": "SQL Injection via login",
        "severity": "critical",
        "affected_component": "POST /auth/login",
    }, headers=auth_headers(token))
    client.post("/scans", json={
        "title": "Unrelated finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token))
    resp = client.get("/scans/search?q=SQL", headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 1
    assert resp.json()["results"][0]["title"] == "SQL Injection via login"


def test_search_sql_injection_payload_is_inert():
    token = register_and_login()
    client.post("/scans", json={"title": "Mine", "severity": "low", "affected_component": "x"},
                headers=auth_headers(token))
    payload = "zz' UNION SELECT id,username,hashed_password,email,1,1,1,1,1 FROM users--"
    resp = client.get("/scans/search", params={"q": payload}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["count"] == 0
    # A quote must not break the query (previously a 500 with the SQL echoed back)
    resp = client.get("/scans/search", params={"q": "a'"}, headers=auth_headers(token))
    assert resp.status_code == 200


def test_search_only_returns_own_scans():
    alice = register_and_login()
    client.post("/scans", json={"title": "Alice secret finding", "severity": "high", "affected_component": "x"},
                headers=auth_headers(alice))
    bob = register_and_login("bob", "bob@example.com")
    resp = client.get("/scans/search", params={"q": "secret"}, headers=auth_headers(bob))
    assert resp.json()["count"] == 0


def test_search_wildcards_match_literally():
    token = register_and_login()
    client.post("/scans", json={"title": "Plain title", "severity": "low", "affected_component": "x"},
                headers=auth_headers(token))
    resp = client.get("/scans/search", params={"q": "%%"}, headers=auth_headers(token))
    assert resp.json()["count"] == 0


def test_update_scan_status():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Open redirect",
        "severity": "medium",
        "affected_component": "redirect handler",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.patch(f"/scans/{scan_id}", json={"status": "in_progress"}, headers=auth_headers(token))
    assert resp.status_code == 200
    assert resp.json()["status"] == "in_progress"


def test_delete_scan():
    token = register_and_login()
    scan_id = client.post("/scans", json={
        "title": "Stale finding",
        "severity": "low",
        "affected_component": "misc",
    }, headers=auth_headers(token)).json()["id"]

    resp = client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 204


# ---------------------------------------------------------------------------
# Shared report links
# ---------------------------------------------------------------------------

import hashlib  # noqa: E402
from datetime import timedelta  # noqa: E402
from urllib.parse import urlparse  # noqa: E402

import models  # noqa: E402


def create_scan_for(token, title="Shared finding"):
    return client.post("/scans", json={
        "title": title,
        "severity": "high",
        "affected_component": "billing-api",
        "remediation_notes": "internal: rotate creds on db-prod-01",
    }, headers=auth_headers(token)).json()["id"]


def share_path(share_url):
    return urlparse(share_url).path


def test_share_link_roundtrip():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.post(f"/scans/{scan_id}/share", headers=auth_headers(token))
    assert resp.status_code == 201
    body = resp.json()
    assert body["share_url"].startswith("http://localhost:8000/share/")
    assert body["password_protected"] is False

    shared = client.get(share_path(body["share_url"]))
    assert shared.status_code == 200
    assert shared.json()["title"] == "Shared finding"
    assert shared.headers["cache-control"] == "no-store"
    # Internal fields are not exposed publicly
    assert "owner_id" not in shared.json()
    assert "remediation_notes" not in shared.json()


def test_share_requires_auth():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.post(f"/scans/{scan_id}/share")
    assert resp.status_code in (401, 403)


def test_cannot_share_another_users_scan():
    alice = register_and_login()
    scan_id = create_scan_for(alice)
    mallory = register_and_login("mallory", "mallory@example.com")
    resp = client.post(f"/scans/{scan_id}/share", headers=auth_headers(mallory))
    assert resp.status_code == 404


def test_share_unknown_token_returns_404():
    resp = client.get("/share/not-a-real-token")
    assert resp.status_code == 404


def test_share_token_is_stored_hashed():
    token = register_and_login()
    scan_id = create_scan_for(token)
    share_url = client.post(f"/scans/{scan_id}/share", headers=auth_headers(token)).json()["share_url"]
    raw = share_url.rsplit("/", 1)[-1]
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        assert link.token_hash == hashlib.sha256(raw.encode()).hexdigest()
        assert raw not in link.token_hash
    finally:
        db.close()


def test_share_link_expires():
    token = register_and_login()
    scan_id = create_scan_for(token)
    share_url = client.post(f"/scans/{scan_id}/share", headers=auth_headers(token)).json()["share_url"]
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        link.expires_at = link.expires_at - timedelta(hours=25)
        db.commit()
    finally:
        db.close()
    assert client.get(share_path(share_url)).status_code == 404


def test_share_link_expiry_is_24_hours():
    token = register_and_login()
    scan_id = create_scan_for(token)
    client.post(f"/scans/{scan_id}/share", headers=auth_headers(token))
    db = TestingSessionLocal()
    try:
        link = db.query(models.ShareLink).one()
        ttl = link.expires_at - link.created_at
        assert timedelta(hours=23, minutes=59) < ttl <= timedelta(hours=24, minutes=1)
    finally:
        db.close()


def test_password_protected_share_link():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "auditor-pass-1"},
                       headers=auth_headers(token))
    assert resp.status_code == 201
    assert resp.json()["password_protected"] is True
    path = share_path(resp.json()["share_url"])

    assert client.get(path).status_code == 401
    assert client.get(path, params={"password": "wrong-password"}).status_code == 401
    ok = client.get(path, params={"password": "auditor-pass-1"})
    assert ok.status_code == 200
    assert ok.json()["id"] == scan_id


def test_share_password_lockout():
    token = register_and_login()
    scan_id = create_scan_for(token)
    path = share_path(client.post(f"/scans/{scan_id}/share", json={"password": "auditor-pass-1"},
                                  headers=auth_headers(token)).json()["share_url"])
    for _ in range(5):
        assert client.get(path, params={"password": "guess-guess"}).status_code == 401
    # Locked even with the correct password
    assert client.get(path, params={"password": "auditor-pass-1"}).status_code == 429


def test_share_password_too_short_rejected():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.post(f"/scans/{scan_id}/share", json={"password": "short"}, headers=auth_headers(token))
    assert resp.status_code == 422


def test_share_link_removed_with_scan():
    token = register_and_login()
    scan_id = create_scan_for(token)
    path = share_path(client.post(f"/scans/{scan_id}/share", headers=auth_headers(token)).json()["share_url"])
    client.delete(f"/scans/{scan_id}", headers=auth_headers(token))
    assert client.get(path).status_code == 404


# ---------------------------------------------------------------------------
# Authentication hardening
# ---------------------------------------------------------------------------

import base64  # noqa: E402
import json  # noqa: E402
import time  # noqa: E402


def _b64(d):
    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()


def test_unsigned_alg_none_token_rejected():
    register_and_login()
    forged = _b64({"alg": "none", "typ": "JWT"}) + "." + _b64({"sub": "alice", "exp": int(time.time()) + 600}) + "."
    resp = client.get("/scans", headers=auth_headers(forged))
    assert resp.status_code == 401


def test_token_signed_with_old_hardcoded_key_rejected():
    import jwt as pyjwt
    register_and_login()
    forged = pyjwt.encode({"sub": "alice", "exp": int(time.time()) + 600},
                          "v3ry-s3cr3t-jwt-k3y-do-not-share", algorithm="HS256")
    resp = client.get("/scans", headers=auth_headers(forged))
    assert resp.status_code == 401


def test_token_without_exp_rejected():
    import jwt as pyjwt
    from config import SECRET_KEY
    register_and_login()
    forged = pyjwt.encode({"sub": "alice"}, SECRET_KEY, algorithm="HS256")
    resp = client.get("/scans", headers=auth_headers(forged))
    assert resp.status_code == 401


# ---------------------------------------------------------------------------
# Authorisation
# ---------------------------------------------------------------------------

def test_get_scan_owner_can_read():
    token = register_and_login()
    scan_id = create_scan_for(token)
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(token))
    assert resp.status_code == 200


def test_get_scan_of_another_user_returns_404():
    alice = register_and_login()
    scan_id = create_scan_for(alice)
    mallory = register_and_login("mallory", "mallory@example.com")
    resp = client.get(f"/scans/{scan_id}", headers=auth_headers(mallory))
    assert resp.status_code == 404


# ---------------------------------------------------------------------------
# Logging and error handling
# ---------------------------------------------------------------------------

import logging  # noqa: E402


def test_login_never_logs_password(caplog):
    client.post("/auth/register", json={"username": "carol", "email": "carol@example.com",
                                        "password": "Correct-Horse-9"})
    with caplog.at_level(logging.DEBUG):
        client.post("/auth/login", json={"username": "carol", "password": "Correct-Horse-9"})
        client.post("/auth/login", json={"username": "carol", "password": "Wrong-Guess-123"})
    assert "Correct-Horse-9" not in caplog.text
    assert "Wrong-Guess-123" not in caplog.text


def test_unhandled_error_does_not_leak_internals():
    from main import app as main_app

    @main_app.get("/_test/boom")
    def boom():
        raise RuntimeError("secret internal detail")

    resp = client.get("/_test/boom")
    assert resp.status_code == 500
    body = resp.json()
    assert "traceback" not in body
    assert "secret internal detail" not in resp.text
    assert body["error_id"]
