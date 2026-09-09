from __future__ import annotations

import hashlib
import json
import re
import secrets
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass
from collections.abc import Iterable
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

# Public Hub/Q-App identity-proof contract.
AUTH_PROTOCOL = "qortal-qapp-auth-v1"
ADDRESS_VERSION = 58
CHALLENGE_TTL_SECONDS = 60
_BASE58_ALPHABET = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
_DESTINATION_RE = re.compile(r"^[0-9a-f]{32}$")
_SERVICE_RE = re.compile(r"^[A-Z0-9_]{1,32}$")

QAppIdentity = tuple[str, str]


def normalize_qapp_identity(name: Any, service: Any) -> QAppIdentity:
    if not isinstance(name, str) or not isinstance(service, str):
        raise ValueError("Q-App identity fields must be strings")
    normalized_name = name.strip().lower()
    normalized_service = service.strip().upper()
    if not normalized_name or len(normalized_name) > 128:
        raise ValueError("Q-App name is invalid")
    if not _SERVICE_RE.fullmatch(normalized_service):
        raise ValueError("Q-App service is invalid")
    return normalized_name, normalized_service


def base58_encode(value: bytes) -> str:
    zeroes = len(value) - len(value.lstrip(b"\0"))
    number = int.from_bytes(value, "big")
    encoded = bytearray()
    while number:
        number, remainder = divmod(number, 58)
        encoded.append(_BASE58_ALPHABET[remainder])
    return (_BASE58_ALPHABET[:1] * zeroes + bytes(reversed(encoded))).decode("ascii")


def base58_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise ValueError("invalid Base58 value")
    number = 0
    for character in value.encode("ascii"):
        index = _BASE58_ALPHABET.find(bytes((character,)))
        if index < 0:
            raise ValueError("invalid Base58 value")
        number = number * 58 + index
    decoded = number.to_bytes((number.bit_length() + 7) // 8, "big") if number else b""
    zeroes = len(value) - len(value.lstrip("1"))
    return b"\0" * zeroes + decoded


def qortal_address(public_key: bytes) -> str:
    if len(public_key) != 32:
        raise ValueError("Qortal public key must be 32 bytes")
    digest = hashlib.new("ripemd160", hashlib.sha256(public_key).digest()).digest()
    versioned = bytes((ADDRESS_VERSION,)) + digest
    checksum = hashlib.sha256(hashlib.sha256(versioned).digest()).digest()[:4]
    return base58_encode(versioned + checksum)


def is_qortal_address(value: Any) -> bool:
    try:
        decoded = base58_decode(value)
    except (TypeError, ValueError, UnicodeError):
        return False
    if len(decoded) != 25 or decoded[0] != ADDRESS_VERSION:
        return False
    checksum = hashlib.sha256(hashlib.sha256(decoded[:21]).digest()).digest()[:4]
    return secrets.compare_digest(decoded[21:], checksum)


def canonical_proof(fields: dict[str, Any]) -> bytes:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=False, sort_keys=True).encode("utf-8")


@dataclass(frozen=True, slots=True)
class Challenge:
    challenge_id: str
    nonce: str
    backend_destination: str
    expires_at: int

    def public(self) -> dict[str, Any]:
        return {
            "protocol": AUTH_PROTOCOL,
            "challengeId": self.challenge_id,
            "nonce": self.nonce,
            "backendDestination": self.backend_destination,
            "expiresAt": self.expires_at,
        }


class QortalIdentityVerifier:
    def __init__(
        self,
        allowed_qapps: Iterable[QAppIdentity] = (),
        max_outstanding_challenges: int = 512,
        enforce_qapp_allowlist: bool = True,
    ) -> None:
        if max_outstanding_challenges <= 0:
            raise ValueError("max_outstanding_challenges must be positive")
        self._challenges: OrderedDict[str, Challenge] = OrderedDict()
        self._lock = threading.RLock()
        self._max_outstanding_challenges = max_outstanding_challenges
        self._enforce_qapp_allowlist = enforce_qapp_allowlist
        self._allowed_qapps = frozenset(
            normalize_qapp_identity(name, service)
            for name, service in allowed_qapps
        )

    def is_qapp_allowed(self, identity: Any) -> bool:
        try:
            name, service = identity
            normalized = normalize_qapp_identity(name, service)
        except (TypeError, ValueError):
            return False
        return (
            normalized == tuple(identity)
            and (
                not self._enforce_qapp_allowlist
                or normalized in self._allowed_qapps
            )
        )

    def issue(self, backend_destination: str, now: float | None = None) -> dict[str, Any]:
        if not _DESTINATION_RE.fullmatch(backend_destination):
            raise ValueError("backend destination is unavailable")
        timestamp = time.time() if now is None else now
        challenge = Challenge(
            secrets.token_urlsafe(18), secrets.token_urlsafe(32), backend_destination,
            int((timestamp + CHALLENGE_TTL_SECONDS) * 1000),
        )
        with self._lock:
            expired = [
                key for key, value in self._challenges.items()
                if value.expires_at < int(timestamp * 1000)
            ]
            for key in expired:
                self._challenges.pop(key, None)
            while len(self._challenges) >= self._max_outstanding_challenges:
                self._challenges.popitem(last=False)
            self._challenges[challenge.challenge_id] = challenge
        return challenge.public()

    def verify(self, proof: Any, now: float | None = None) -> tuple[str, str, QAppIdentity]:
        if not isinstance(proof, dict):
            raise ValueError("identity proof must be an object")
        timestamp_ms = int((time.time() if now is None else now) * 1000)
        challenge_id = proof.get("challengeId")
        if not isinstance(challenge_id, str):
            raise ValueError("identity proof is missing its challenge")
        with self._lock:
            challenge = self._challenges.pop(challenge_id, None)
        if challenge is None or timestamp_ms > challenge.expires_at:
            raise ValueError("identity challenge is invalid or expired")
        expected = challenge.public()
        for key, value in expected.items():
            if proof.get(key) != value:
                raise ValueError("identity proof does not match its challenge")
        address = proof.get("address")
        public_key_text = proof.get("publicKey")
        signature_text = proof.get("signature")
        if not all(isinstance(value, str) for value in (address, public_key_text, signature_text)):
            raise ValueError("identity proof is incomplete")
        qapp_identity = normalize_qapp_identity(
            proof.get("qappName"), proof.get("qappService"),
        )
        if (
            qapp_identity != (
                proof.get("qappName"), proof.get("qappService"),
            ) or (
                self._enforce_qapp_allowlist
                and qapp_identity not in self._allowed_qapps
            )
        ):
            raise ValueError("Q-App is not authorized for this backend")
        public_key = base58_decode(public_key_text)
        if qortal_address(public_key) != address:
            raise ValueError("public key does not match Qortal address")
        signed_fields = {
            **expected,
            "address": address,
            "publicKey": public_key_text,
            "qappName": qapp_identity[0],
            "qappService": qapp_identity[1],
        }
        try:
            Ed25519PublicKey.from_public_bytes(public_key).verify(
                base58_decode(signature_text), canonical_proof(signed_fields),
            )
        except (InvalidSignature, ValueError) as exc:
            raise ValueError("invalid Qortal identity signature") from exc
        return address, public_key_text, qapp_identity
