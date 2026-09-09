from __future__ import annotations

import hashlib
import json
import threading
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Any, Callable


MAX_CORE_RESPONSE_BYTES = 16 * 1024
CORE_REQUEST_TIMEOUT_SECONDS = 2.0
CORE_CHECK_DEADLINE_SECONDS = 6.0
CORE_FAILURE_COOLDOWN_SECONDS = 30.0
MEMBERSHIP_CACHE_SECONDS = 30.0


class GroupAccessDenied(Exception):
    """The Core authoritatively reported that an address is not allowed."""


class GroupAccessUnavailable(Exception):
    """No configured Core could authoritatively answer the membership check."""


@dataclass(frozen=True, slots=True)
class MembershipResult:
    allowed: bool
    checked_at: float


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *_args: Any, **_kwargs: Any) -> None:
        return None


def _request_membership(
    base: str, group_id: int, address: str, timeout: float
) -> bool:
    body = json.dumps([address], separators=(",", ":")).encode("utf-8")
    request = urllib.request.Request(
        f"{base.rstrip('/')}/groups/members/{group_id}/validate",
        data=body,
        headers={"Accept": "application/json", "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.build_opener(_NoRedirect).open(
            request, timeout=timeout
        ) as response:
            if response.status != 200:
                raise GroupAccessUnavailable("Core membership request failed")
            raw = response.read(MAX_CORE_RESPONSE_BYTES + 1)
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise GroupAccessUnavailable("Core membership request failed") from exc
    if len(raw) > MAX_CORE_RESPONSE_BYTES:
        raise GroupAccessUnavailable("Core membership response is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise GroupAccessUnavailable("Core membership response is invalid") from exc
    if not isinstance(value, list) or len(value) != 1 or not isinstance(value[0], dict):
        raise GroupAccessUnavailable("Core membership response is invalid")
    result = value[0]
    if result.get("address") != address or not isinstance(result.get("isMember"), bool):
        raise GroupAccessUnavailable("Core membership response is invalid")
    if "isAdmin" in result and not isinstance(result["isAdmin"], bool):
        raise GroupAccessUnavailable("Core membership response is invalid")
    return result["isMember"]


class GroupAccessPolicy:
    """Bounded, fail-closed membership checks for proven Qortal addresses."""

    def __init__(
        self,
        mode: str,
        group_ids: tuple[int, ...],
        core_url_bases: tuple[str, ...],
        requester: Callable[[str, int, str, float], bool] = _request_membership,
    ) -> None:
        self.mode = mode
        self.group_ids = tuple(group_ids)
        self.core_url_bases = tuple(base.rstrip("/") for base in core_url_bases)
        self.requester = requester
        revision_input = json.dumps(
            {"mode": mode, "groups": sorted(group_ids)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self.revision = hashlib.sha256(revision_input).hexdigest()
        self._cache: dict[str, MembershipResult] = {}
        self._pending: dict[str, threading.Event] = {}
        self._core_failed_until: dict[str, float] = {}
        self._lock = threading.Lock()
        self._request_slots = threading.BoundedSemaphore(16)

    def authorize(self, address: str, now: float | None = None) -> float:
        checked_at = time.time() if now is None else now
        if self.mode == "public":
            return checked_at
        while True:
            with self._lock:
                cached = self._cache.get(address)
                if cached and checked_at - cached.checked_at < MEMBERSHIP_CACHE_SECONDS:
                    if cached.allowed:
                        return cached.checked_at
                    raise GroupAccessDenied("Qortal address is not in an allowed group")
                pending = self._pending.get(address)
                if pending is None:
                    pending = threading.Event()
                    self._pending[address] = pending
                    break
            if not pending.wait(8.0):
                raise GroupAccessUnavailable("membership check timed out")

        result: MembershipResult | None = None
        try:
            allowed = self._check_groups(address)
            result = MembershipResult(allowed, checked_at)
            with self._lock:
                self._cache[address] = result
        finally:
            with self._lock:
                finished = self._pending.pop(address, None)
                if finished is not None:
                    finished.set()
        if result is None:
            raise GroupAccessUnavailable("membership could not be checked")
        if not result.allowed:
            raise GroupAccessDenied("Qortal address is not in an allowed group")
        return result.checked_at

    def _check_groups(self, address: str) -> bool:
        workers = min(4, len(self.group_ids))
        with ThreadPoolExecutor(max_workers=workers) as executor:
            futures = [
                executor.submit(self._check_one_group, address, group_id)
                for group_id in self.group_ids
            ]
            unavailable = False
            for future in as_completed(futures):
                try:
                    if future.result():
                        for other in futures:
                            other.cancel()
                        return True
                except GroupAccessUnavailable:
                    unavailable = True
        if unavailable:
            raise GroupAccessUnavailable("membership could not be checked")
        return False

    def _check_one_group(self, address: str, group_id: int) -> bool:
        last_error: Exception | None = None
        deadline = time.monotonic() + CORE_CHECK_DEADLINE_SECONDS
        with self._lock:
            bases = tuple(
                base
                for base in self.core_url_bases
                if self._core_failed_until.get(base, 0) <= time.monotonic()
            )
        if not bases:
            bases = self.core_url_bases
        for base in bases:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            if not self._request_slots.acquire(timeout=0.25):
                last_error = GroupAccessUnavailable("membership capacity reached")
                continue
            try:
                result = self.requester(
                    base, group_id, address,
                    min(CORE_REQUEST_TIMEOUT_SECONDS, remaining),
                )
                with self._lock:
                    self._core_failed_until.pop(base, None)
                return result
            except GroupAccessUnavailable as exc:
                last_error = exc
                with self._lock:
                    self._core_failed_until[base] = (
                        time.monotonic() + CORE_FAILURE_COOLDOWN_SECONDS
                    )
            except Exception as exc:
                last_error = GroupAccessUnavailable("Core membership request failed")
                last_error.__cause__ = exc
                with self._lock:
                    self._core_failed_until[base] = (
                        time.monotonic() + CORE_FAILURE_COOLDOWN_SECONDS
                    )
            finally:
                self._request_slots.release()
        raise GroupAccessUnavailable("membership could not be checked") from last_error
