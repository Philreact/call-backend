from pathlib import Path

import pytest

from qapp_backend.config import Config


@pytest.fixture
def config(tmp_path: Path) -> Config:
    return Config(
        rns_config_dir=tmp_path / "rns",
        data_dir=tmp_path / "backend",
        identity_path=tmp_path / "backend" / "identity",
        database_path=tmp_path / "backend" / "db.sqlite3",
        call_media_grants_path=tmp_path / "backend" / "call-media-grants",
        call_media_revocations_path=tmp_path / "backend" / "call-media-revocations",
        ack_timeout=60,
        allowed_qapps=(("qapp-ui-call", "APP"),),
    )
