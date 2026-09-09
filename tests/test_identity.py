import stat

import RNS

from qapp_backend.reticulum.server import QAppServer


def test_identity_survives_reload_with_restrictive_permissions(config):
    config.identity_path.parent.mkdir(parents=True)
    first = QAppServer._load_or_create_identity(RNS, config.identity_path)
    first_public = first.get_public_key()
    second = QAppServer._load_or_create_identity(RNS, config.identity_path)
    assert second.get_public_key() == first_public
    assert stat.S_IMODE(config.identity_path.stat().st_mode) == 0o600
