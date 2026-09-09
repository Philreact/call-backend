from dataclasses import replace

import pytest

from qapp_backend.auth.group_access import (
    GroupAccessDenied,
    GroupAccessPolicy,
    GroupAccessUnavailable,
)


ADDRESS = "Q" + "a" * 33


def test_public_policy_never_contacts_core():
    policy = GroupAccessPolicy(
        "public", (), (), lambda *_args: pytest.fail("Core was contacted")
    )
    assert policy.authorize(ADDRESS, now=10) == 10


def test_membership_in_any_allowed_group_is_accepted_and_cached():
    calls = []

    def request(base, group_id, address, timeout):
        calls.append((base, group_id, address, timeout))
        return group_id == 1144

    policy = GroupAccessPolicy("groups", (7, 1144), ("https://core.example",), request)
    assert policy.authorize(ADDRESS, now=100) == 100
    assert policy.authorize(ADDRESS, now=110) == 100
    assert len(calls) == 2


def test_confirmed_non_member_is_denied():
    policy = GroupAccessPolicy("groups", (1144,), ("https://core.example",), lambda *_: False)
    with pytest.raises(GroupAccessDenied):
        policy.authorize(ADDRESS, now=100)


def test_unknown_group_result_fails_closed_instead_of_becoming_a_denial():
    def request(_base, group_id, _address, _timeout):
        if group_id == 1144:
            raise GroupAccessUnavailable("offline")
        return False

    policy = GroupAccessPolicy("groups", (7, 1144), ("https://core.example",), request)
    with pytest.raises(GroupAccessUnavailable):
        policy.authorize(ADDRESS, now=100)


def test_unavailable_core_falls_back_and_is_temporarily_deprioritized():
    calls = []

    def request(base, _group_id, _address, _timeout):
        calls.append(base)
        if base == "https://offline.example":
            raise GroupAccessUnavailable("offline")
        return True

    policy = GroupAccessPolicy(
        "groups", (1144,),
        ("https://offline.example", "https://working.example"), request,
    )
    assert policy.authorize(ADDRESS, now=100) == 100
    assert calls == ["https://offline.example", "https://working.example"]
    policy.authorize("Q" + "b" * 33, now=200)
    assert calls[-1] == "https://working.example"


@pytest.mark.parametrize(
    "changes",
    [
        {"access_mode": "groups", "allowed_group_ids": ()},
        {"access_mode": "groups", "allowed_group_ids": (1144,), "core_url_bases": ()},
        {"access_mode": "public", "allowed_group_ids": (1144,)},
        {"access_mode": "groups", "allowed_group_ids": (1144, 1144), "core_url_bases": ("https://core.example",)},
        {"access_mode": "groups", "allowed_group_ids": (1144,), "core_url_bases": ("http://remote.example",)},
    ],
)
def test_invalid_group_access_configuration_is_rejected(config, changes):
    with pytest.raises(ValueError):
        replace(config, **changes).validate()


def test_group_access_configuration_accepts_local_core_and_thirty_minute_lease(config):
    replace(
        config,
        access_mode="groups",
        allowed_group_ids=(1144,),
        core_url_bases=("http://host.docker.internal:12391",),
        access_revalidate_interval=1800,
        access_outage_grace=3600,
    ).validate()
