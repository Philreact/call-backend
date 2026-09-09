from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from qapp_backend.auth.qortal_identity import (
    QortalIdentityVerifier, base58_encode, canonical_proof, qortal_address,
)


def proof_for(
    verifier: QortalIdentityVerifier, destination: str, private_key: Ed25519PrivateKey,
    qapp=("qapp-ui-call", "APP"),
):
    challenge = verifier.issue(destination, now=100)
    public_key = private_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    fields = {
        **challenge,
        "address": qortal_address(public_key),
        "publicKey": base58_encode(public_key),
        "qappName": qapp[0],
        "qappService": qapp[1],
    }
    return {**fields, "signature": base58_encode(private_key.sign(canonical_proof(fields)))}


def test_signed_qortal_identity_is_verified_and_single_use():
    verifier = QortalIdentityVerifier((("qapp-ui-call", "APP"),))
    proof = proof_for(verifier, "ab" * 16, Ed25519PrivateKey.generate())

    address, public_key, qapp = verifier.verify(proof, now=101)
    assert address == proof["address"]
    assert public_key == proof["publicKey"]
    assert qapp == ("qapp-ui-call", "APP")
    with pytest.raises(ValueError, match="invalid or expired"):
        verifier.verify(proof, now=101)


def test_claimed_address_and_signature_cannot_be_forged():
    verifier = QortalIdentityVerifier((("qapp-ui-call", "APP"),))
    proof = proof_for(verifier, "cd" * 16, Ed25519PrivateKey.generate())
    proof["address"] = qortal_address(
        Ed25519PrivateKey.generate().public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw,
        )
    )
    with pytest.raises(ValueError, match="does not match"):
        verifier.verify(proof, now=101)

    proof = proof_for(verifier, "cd" * 16, Ed25519PrivateKey.generate())
    proof["signature"] = base58_encode(b"\0" * 64)
    with pytest.raises(ValueError, match="invalid Qortal identity signature"):
        verifier.verify(proof, now=101)


def test_expired_challenge_is_rejected():
    verifier = QortalIdentityVerifier((("qapp-ui-call", "APP"),))
    proof = proof_for(verifier, "ef" * 16, Ed25519PrivateKey.generate())
    with pytest.raises(ValueError, match="invalid or expired"):
        verifier.verify(proof, now=161)


def test_outstanding_challenges_have_a_hard_memory_bound():
    verifier = QortalIdentityVerifier(
        (("qapp-ui-call", "APP"),),
        max_outstanding_challenges=2,
    )
    first = verifier.issue("ef" * 16, now=100)
    second = verifier.issue("ef" * 16, now=100)
    third = verifier.issue("ef" * 16, now=100)

    assert tuple(verifier._challenges) == (
        second["challengeId"],
        third["challengeId"],
    )
    assert first["challengeId"] not in verifier._challenges


def test_qapp_must_be_allowed_and_is_covered_by_signature():
    verifier = QortalIdentityVerifier((
        ("qapp-ui-call", "APP"),
        ("other-app", "APP"),
    ))
    proof = proof_for(verifier, "12" * 16, Ed25519PrivateKey.generate())
    proof["qappName"] = "other-app"
    with pytest.raises(ValueError, match="invalid Qortal identity signature"):
        verifier.verify(proof, now=101)

    verifier = QortalIdentityVerifier((("qapp-ui-call", "APP"),))
    proof = proof_for(
        verifier, "12" * 16, Ed25519PrivateKey.generate(),
        qapp=("other-app", "APP"),
    )
    with pytest.raises(ValueError, match="not authorized"):
        verifier.verify(proof, now=101)


def test_qapp_allowlist_can_be_disabled_explicitly_for_local_testing():
    verifier = QortalIdentityVerifier(
        (),
        enforce_qapp_allowlist=False,
    )
    proof = proof_for(
        verifier,
        "34" * 16,
        Ed25519PrivateKey.generate(),
        qapp=("unlisted-test-app", "APP"),
    )

    _address, _public_key, qapp = verifier.verify(proof, now=101)

    assert qapp == ("unlisted-test-app", "APP")
    assert verifier.is_qapp_allowed(["unlisted-test-app", "APP"])
