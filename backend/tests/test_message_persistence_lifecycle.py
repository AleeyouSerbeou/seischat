"""Test message persistence across logout and re-login lifecycles."""

from fastapi.testclient import TestClient
from app.database.connection import SessionLocal
from app.models import Message, User
from sqlalchemy import select


def test_messages_persist_across_logout_and_relogin(client: TestClient) -> None:
    # 1. Acquire CSRF
    csrf_res = client.get("/api/auth/csrf")
    csrf_token = csrf_res.json()["csrf_token"]

    # 2. Register User A
    reg_a = client.post(
        "/api/auth/register",
        json={"username": "user_persist_a", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert reg_a.status_code == 201

    # 3. Login User A
    login_a = client.post(
        "/api/auth/login",
        json={"username": "user_persist_a", "password": "password123"},
        headers={"X-CSRF-Token": csrf_token},
    )
    assert login_a.status_code == 200
    token_a = login_a.json()["token"]

    # 4. User A sends a message via WebSocket
    with client.websocket_connect(f"/ws/chat?token={token_a}") as ws_a:
        # consume online_users event
        ws_a.receive_json()
        ws_a.send_json({
            "event": "send_message",
            "payload": {"content": "Persistent message from User A"}
        })
        msg_event = ws_a.receive_json()
        assert msg_event["event"] == "new_message"
        assert msg_event["payload"]["content"] == "Persistent message from User A"
        saved_msg_id = msg_event["payload"]["id"]

    # 5. Confirm the message is actually saved in PostgreSQL
    with SessionLocal() as db:
        db_msg = db.scalar(select(Message).where(Message.content == "Persistent message from User A"))
        assert db_msg is not None
        assert str(db_msg.id) == saved_msg_id

    # 6. User A logs out
    csrf_res = client.get("/api/auth/csrf")
    logout_res = client.post(
        "/api/auth/logout",
        headers={
            "Authorization": f"Bearer {token_a}",
            "X-CSRF-Token": csrf_res.json()["csrf_token"],
        },
    )
    assert logout_res.status_code == 204

    # Confirm message STILL exists in PostgreSQL after logout
    with SessionLocal() as db:
        db_msg_after_logout = db.scalar(select(Message).where(Message.content == "Persistent message from User A"))
        assert db_msg_after_logout is not None
        assert str(db_msg_after_logout.id) == saved_msg_id

    # 7. User A logs in again (new session)
    csrf_res = client.get("/api/auth/csrf")
    login_a2 = client.post(
        "/api/auth/login",
        json={"username": "user_persist_a", "password": "password123"},
        headers={"X-CSRF-Token": csrf_res.json()["csrf_token"]},
    )
    assert login_a2.status_code == 200
    token_a2 = login_a2.json()["token"]
    assert token_a2 != token_a  # Fresh session token

    # 8. User A retrieves message history via GET /api/messages (using Bearer token or cookies)
    history_res = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {token_a2}"},
    )
    assert history_res.status_code == 200
    messages = history_res.json()["messages"]
    matching = [m for m in messages if m["id"] == saved_msg_id]
    assert len(matching) == 1
    assert matching[0]["content"] == "Persistent message from User A"
    assert matching[0]["user"]["username"] == "user_persist_a"

    # 9. Register & Login User B to verify shared chatroom history
    csrf_res = client.get("/api/auth/csrf")
    client.post(
        "/api/auth/register",
        json={"username": "user_persist_b", "password": "password123"},
        headers={"X-CSRF-Token": csrf_res.json()["csrf_token"]},
    )
    login_b = client.post(
        "/api/auth/login",
        json={"username": "user_persist_b", "password": "password123"},
        headers={"X-CSRF-Token": csrf_res.json()["csrf_token"]},
    )
    token_b = login_b.json()["token"]

    # User B retrieves history — MUST see User A's message
    history_b = client.get(
        "/api/messages",
        headers={"Authorization": f"Bearer {token_b}"},
    )
    assert history_b.status_code == 200
    b_messages = history_b.json()["messages"]
    matching_b = [m for m in b_messages if m["id"] == saved_msg_id]
    assert len(matching_b) == 1
    assert matching_b[0]["content"] == "Persistent message from User A"
