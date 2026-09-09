from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class StoredSession:
    session_id: str
    token_hash: bytes
    authenticated_user: str | None
    created_at: float
    last_seen: float
    expires_at: float
    metadata_json: str
    subscriptions_json: str
    last_application_sequence: int

