import pytest

from qapp_backend.private_transport.authorization import (
    AttachRejected,
    AttachTokenAuthority,
    BootstrapRateLimited,
)


class Connection:
    closed = False


class Session:
    session_id = "session-a"
    provisional = False
    expires_at = 10_000
    authenticated_user = "Q-user"
    metadata = {
        "qapp_identity": ["qapp-ui-call", "APP"],
        "qapp_connection_id": "logical-a",
    }
    connection = Connection()


def authority(**overrides):
    values = {
        "ttl": 30,
        "per_session_per_minute": 4,
        "per_user_per_minute": 8,
        "max_unused_per_session": 4,
        "max_unused_global": 10,
    }
    values.update(overrides)
    return AttachTokenAuthority(**values)


def issue(store, **overrides):
    values = {
        "logical_session_id": "session-a",
        "logical_connection_id": "logical-a",
        "authenticated_user": "Q-user",
        "qapp_identity": ("qapp-ui-call", "APP"),
        "purpose": "game",
        "owner_binding_hash": "a" * 64,
        "nonce": "n" * 32,
        "now": 100,
    }
    values.update(overrides)
    return store.issue(**values)


def consume(store, token, session=Session(), **overrides):
    values = {
        "logical_session_id": "session-a",
        "purpose": "game",
        "owner_binding_hash": "a" * 64,
        "nonce": "n" * 32,
        "session_lookup": lambda _session_id: session,
        "now": 101,
    }
    values.update(overrides)
    return store.consume(token, **values)


def test_tokens_are_high_entropy_hashed_and_single_use():
    store = authority()
    first, grant = issue(store)
    second, _ = issue(store)
    assert len(first) >= 43
    assert first != second
    assert first.encode() not in grant.token_hash
    assert consume(store, first)[0] is grant
    with pytest.raises(AttachRejected):
        consume(store, first)


@pytest.mark.parametrize(
    "field,value",
    [
        ("logical_session_id", "session-b"),
        ("purpose", "realtime"),
        ("owner_binding_hash", "b" * 64),
        ("nonce", "x" * 32),
    ],
)
def test_token_is_consumed_when_an_attach_binding_is_wrong(field, value):
    store = authority()
    token, _ = issue(store)
    with pytest.raises(AttachRejected):
        consume(store, token, **{field: value})
    with pytest.raises(AttachRejected):
        consume(store, token)


def test_expiry_session_identity_and_disconnect_fail_closed():
    store = authority(ttl=5)
    expired, _ = issue(store)
    with pytest.raises(AttachRejected):
        consume(store, expired, now=106)

    wrong_app, _ = issue(store, now=200)
    session = Session()
    session.metadata = {**Session.metadata, "qapp_identity": ["other", "APP"]}
    with pytest.raises(AttachRejected):
        consume(store, wrong_app, session=session, now=201)

    disconnected, _ = issue(store, now=300)
    session = Session()
    session.connection = Connection()
    session.connection.closed = True
    with pytest.raises(AttachRejected):
        consume(store, disconnected, session=session, now=301)


def test_session_invalidation_and_rate_limits_remove_unused_credentials():
    store = authority(per_session_per_minute=2)
    issue(store)
    issue(store)
    with pytest.raises(BootstrapRateLimited):
        issue(store)
    assert store.outstanding("session-a", now=101) == 2
    store.invalidate_session("session-a")
    assert store.outstanding("session-a") == 0


def test_released_token_is_no_longer_accepted_by_this_authority():
    store = authority()
    token, _grant = issue(store)
    store.release(token)
    assert store.outstanding("session-a") == 0
    with pytest.raises(AttachRejected):
        consume(store, token)


def test_authenticated_user_rate_limit_spans_logical_sessions():
    store = authority(per_user_per_minute=2)
    issue(store, logical_session_id="session-a")
    issue(store, logical_session_id="session-b")
    with pytest.raises(BootstrapRateLimited):
        issue(store, logical_session_id="session-c")
