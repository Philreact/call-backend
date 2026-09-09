from qapp_backend.reticulum.sessions import SessionManager
from qapp_backend.storage.database import Database


class FakeConnection:
    def __init__(self):
        self.closed = False
        self.reason = None

    def close(self, reason):
        self.closed = True
        self.reason = reason


def manager(config):
    database = Database(config.database_path)
    database.open()
    return SessionManager(database, 10, 3), database


def test_valid_invalid_expired_and_rotated_resume(config):
    sessions, database = manager(config)
    old = FakeConnection()
    created, token = sessions.create(old, now=10)
    new = FakeConnection()
    resumed, new_token = sessions.resume(created.session_id, token, new, now=11)
    assert resumed is created and new_token and old.closed
    assert sessions.resume(created.session_id, token, FakeConnection(), now=12) == (None, None)
    assert sessions.resume(created.session_id, new_token, FakeConnection(), now=99) == (None, None)
    database.close()


def test_session_persists_without_plaintext_token(config):
    sessions, database = manager(config)
    created, token = sessions.create(now=10)
    database.close()
    reopened = Database(config.database_path)
    reopened.open()
    loaded = SessionManager(reopened, 10)
    loaded.load(now=11)
    assert loaded.get(created.session_id).token_matches(token)
    assert token.encode() not in config.database_path.read_bytes()
    reopened.close()


def test_provisional_session_is_not_persisted_until_promoted(config):
    sessions, database = manager(config)
    created, _ = sessions.create(now=10, provisional=True)
    assert created.provisional
    assert database._connection().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 0

    sessions.promote(created, "Q-user", now=11)

    assert not created.provisional
    assert created.authenticated_user == "Q-user"
    assert created.expires_at == 21
    assert database._connection().execute("SELECT COUNT(*) FROM sessions").fetchone()[0] == 1
    database.close()
