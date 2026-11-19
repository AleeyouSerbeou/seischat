"""Production authentication, cross-site compatibility, and chat scenarios."""

from fastapi.testclient import TestClient
from app.core.config import get_settings


def test_production_csrf_token_issuance(client: TestClient) -> None:
    res = client.get("/api/auth/csrf")
    assert res.status_code == 200
    token = res.json()["csrf_token"]
    assert token is not None
    assert "." in token
    from app.security import is_valid_csrf_token
    assert is_valid_csrf_token(token, get_settings().secret_key)


def test_production_registration_and_login_with_cookies(client: TestClient) -> None:
    # 1. Acquire CSRF
    csrf_res = client.get("/api/auth/csrf")
    csrf_token = csrf_res.json()["csrf_token"]

    # 2. Register
    reg_res = client.post(
        "/api/auth/register",
        json={"username": "prod_user1", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reg_res.status_code == 201
    assert reg_res.json()["user"]["username"] == "prod_user1"

    # 3. Login
    login_res = client.post(
        "/api/auth/login",
        json={"username": "prod_user1", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert login_res.status_code == 200
    login_data = login_res.json()
    assert login_data["user"]["username"] == "prod_user1"
    assert "token" in login_data
    token = login_data["token"]
    assert len(token) > 0
    assert "seischat_session" in client.cookies

    # 4. Current user via cookie
    me_res = client.get("/api/auth/me")
    assert me_res.status_code == 200
    assert me_res.json()["user"]["username"] == "prod_user1"

    # 5. Message history via cookie
    msg_res = client.get("/api/messages")
    assert msg_res.status_code == 200
    assert isinstance(msg_res.json()["messages"], list)


def test_production_cross_site_safari_scenario_without_cookies(client: TestClient) -> None:
    """Simulates Safari/iOS where cross-site cookies are blocked by browser privacy/ITP."""
    # 1. Acquire CSRF token via JSON (browser blocks Set-Cookie)
    csrf_res = client.get("/api/auth/csrf")
    csrf_token = csrf_res.json()["csrf_token"]

    # Clear all cookies to simulate client browser blocking them
    client.cookies.clear()

    # 2. Register with only X-CSRF-Token header (valid HMAC, no cookie)
    reg_res = client.post(
        "/api/auth/register",
        json={"username": "safari_user", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reg_res.status_code == 201

    # 3. Login with only X-CSRF-Token header
    login_res = client.post(
        "/api/auth/login",
        json={"username": "safari_user", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert login_res.status_code == 200
    token = login_res.json()["token"]
    assert token

    # Clear cookies again to simulate browser dropping Set-Cookie
    client.cookies.clear()

    # 4. Current user via Authorization: Bearer
    me_res = client.get(
        "/api/auth/me",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert me_res.status_code == 200
    assert me_res.json()["user"]["username"] == "safari_user"

    # 5. Message history via Authorization: Bearer
    msg_res = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert msg_res.status_code == 200

    # 6. WebSocket authentication via ?token= query param
    with client.websocket_connect(f"/ws/chat?token={token}") as ws:
        # Connected successfully! Receive online_users broadcast
        event1 = ws.receive_json()
        assert event1["event"] == "online_users"

        # Send a message
        ws.send_json({"event": "send_message", "payload": {"content": "Hello from Safari"}})
        msg_event = ws.receive_json()
        assert msg_event["event"] == "new_message"
        assert msg_event["payload"]["content"] == "Hello from Safari"
        msg_id = msg_event["payload"]["id"]

    # 7. Delete message via Authorization: Bearer + X-CSRF-Token (no cookies)
    csrf_res2 = client.get("/api/auth/csrf")
    csrf_token2 = csrf_res2.json()["csrf_token"]
    client.cookies.clear()

    del_res = client.delete(
        f"/api/messages/{msg_id}",
        headers={
            "Authorization": f"Bearer {token}",
            "X-CSRF-Token": csrf_token2,
        },
    )
    assert del_res.status_code == 204


def test_cors_configuration(client: TestClient) -> None:
    """Test CORS preflight and headers for production and local origins."""
    for origin in [
        "https://seischat-web.onrender.com",
        "https://seischat-web.onrender.com/",
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ]:
        res = client.options(
            "/api/auth/login",
            headers={
                "Origin": origin,
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "Content-Type,X-CSRF-Token,Authorization",
            },
        )
        assert res.status_code == 200
        assert res.headers.get("access-control-allow-origin") == origin
        assert res.headers.get("access-control-allow-credentials") == "true"


def test_production_secret_key_validation() -> None:
    """Settings must refuse insecure secret keys when app_environment is production."""
    import pytest
    from pydantic import ValidationError
    from app.core.config import Settings

    # Insecure default in production must raise ValidationError
    with pytest.raises(ValidationError):
        Settings(
            app_environment="production",
            secret_key="seischat-secret-key-change-in-production",
        )

    # Short key in production must raise ValidationError
    with pytest.raises(ValidationError):
        Settings(
            app_environment="production",
            secret_key="too-short-secret",
        )

    # Safe random 32+ char key in production must succeed
    safe_settings = Settings(
        app_environment="production",
        secret_key="a" * 32,
    )
    assert safe_settings.secret_key == "a" * 32


def test_csrf_tampered_and_expired_tokens(client: TestClient) -> None:
    """Ensure tampered or expired CSRF tokens are rejected."""
    from app.security import is_valid_csrf_token, new_csrf_token

    valid = new_csrf_token()
    assert is_valid_csrf_token(valid)

    # Tampered signature
    parts = valid.split(".")
    tampered = f"{parts[0]}.{parts[1]}.badsignature000000000000000000"
    assert not is_valid_csrf_token(tampered)

    # Expired token (simulate token from 2 hours ago)
    expired = f"{int(parts[0]) - 7200}.{parts[1]}.{parts[2]}"
    assert not is_valid_csrf_token(expired)


def test_cors_blocks_unauthorized_origin(client: TestClient) -> None:
    """Ensure CORS preflight does not grant access to unauthorized origins."""
    res = client.options(
        "/api/auth/login",
        headers={
            "Origin": "https://malicious-site.example.com",
            "Access-Control-Request-Method": "POST",
            "Access-Control-Request-Headers": "Content-Type,X-CSRF-Token",
        },
    )
    assert res.headers.get("access-control-allow-origin") is None
