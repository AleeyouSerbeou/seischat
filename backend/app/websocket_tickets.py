"""In-memory, single-use, short-lived WebSocket ticket manager."""

import hashlib
import secrets
from datetime import datetime, timezone
from uuid import UUID


class WebSocketTicketManager:
    """Manages short-lived (30s), single-use tickets for WebSocket authentication."""

    def __init__(self, ttl_seconds: int = 30) -> None:
        self.ttl_seconds = ttl_seconds
        self._tickets: dict[str, tuple[UUID, float]] = {}

    def create_ticket(self, user_id: UUID) -> str:
        self._purge_expired()
        raw_ticket = secrets.token_urlsafe(32)
        ticket_hash = hashlib.sha256(raw_ticket.encode()).hexdigest()
        expires_at = datetime.now(timezone.utc).timestamp() + self.ttl_seconds
        self._tickets[ticket_hash] = (user_id, expires_at)
        return raw_ticket

    def consume_ticket(self, raw_ticket: str) -> UUID | None:
        self._purge_expired()
        if not raw_ticket:
            return None
        ticket_hash = hashlib.sha256(raw_ticket.encode()).hexdigest()
        entry = self._tickets.pop(ticket_hash, None)
        if not entry:
            return None
        user_id, expires_at = entry
        if datetime.now(timezone.utc).timestamp() > expires_at:
            return None
        return user_id

    def _purge_expired(self) -> None:
        now = datetime.now(timezone.utc).timestamp()
        expired = [k for k, (_, exp) in self._tickets.items() if exp < now]
        for k in expired:
            self._tickets.pop(k, None)


ws_ticket_manager = WebSocketTicketManager()
