import json
import logging

from qapp_backend.logging import JsonFormatter


def test_json_formatter_includes_connection_close_reason():
    record = logging.LogRecord(
        "test", logging.INFO, __file__, 1,
        "physical connection closed", (), None,
    )
    record.event = "link_closed"
    record.connection_id = "connection-one"
    record.reason = "idle_timeout"

    payload = json.loads(JsonFormatter().format(record))

    assert payload["event"] == "link_closed"
    assert payload["connection_id"] == "connection-one"
    assert payload["reason"] == "idle_timeout"
