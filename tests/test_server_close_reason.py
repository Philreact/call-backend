from types import SimpleNamespace

from qapp_backend.reticulum.server import QAppServer


def link(reason, *, initiator=False):
    return SimpleNamespace(
        TIMEOUT=1,
        INITIATOR_CLOSED=2,
        DESTINATION_CLOSED=3,
        teardown_reason=reason,
        initiator=initiator,
    )


def test_reticulum_close_reasons_distinguish_timeout_remote_and_local():
    assert QAppServer._reticulum_close_reason(link(1)) == "reticulum_timeout"
    assert QAppServer._reticulum_close_reason(link(2)) == "remote_reticulum_close"
    assert QAppServer._reticulum_close_reason(link(3)) == "local_reticulum_close"
    assert QAppServer._reticulum_close_reason(link(2, initiator=True)) == "local_reticulum_close"
    assert QAppServer._reticulum_close_reason(link(3, initiator=True)) == "remote_reticulum_close"
    assert QAppServer._reticulum_close_reason(link(None)) == "reticulum_link_closed"
