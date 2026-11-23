# SPDX-License-Identifier: BSD-3-Clause
"""The carried signature profiles of ``composed/v1``, verified.

``draft-mih-zhang-agent-disclosure-bundle-03``, "Carried Signature Profiles":
three opt-in profiles in which a verifier checks the signature of a refusal or
an artifact response that a ``composed/v1`` member carries. Pass
:func:`verify_carried_refusal` and :func:`verify_carried_response` as
:class:`~agent_action_capsule.composed.ComposedOptions` ``refusal_signature``
and ``response_signature``; without them every carried signature stays
signature-unverified.

Each function returns one of the ``REFUSAL_SIGNATURE_*`` states of
:mod:`agent_action_capsule.composed`. The state covers the signature alone: no
check of a signed value (a timestamp's format, a digest's form, a registered
reason) enters it, and it does not compare the key with the member's
responder. Ed25519 is strict (:mod:`._ed25519_strict`): a small-order key or R
never verifies. Needs the ``cryptography`` package (the ``envelope`` extra);
without it a check that reaches the equation raises :class:`ImportError`
rather than report a signature as not verifying.
"""
from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from ._ed25519_strict import verify_strict
from .canonical import jcs

THREE_MEMBER_REFUSAL = "three-member-refusal/v1"
WHOLE_REFUSAL = "whole-refusal/v1"
DIGEST_BOUND_ARTIFACT_RESPONSE = "digest-bound-artifact-response/v1"

#: The ``type`` the verifier supplies to a digest-bound artifact response's
#: signing input; it is never read from the carried object.
ARTIFACT_RESPONSE_TYPE = "evidence-artifact-response/v1"

_VERIFIED = "verified"
_INVALID = "invalid"
_UNVERIFIED = "signature_unverified"

_KEY = re.compile(r"[0-9a-f]{64}")
_SIG = re.compile(r"[0-9a-f]{128}")

_REFUSAL_SIGNED = ("issued_at", "reason", "request_digest")
_RESPONSE_SIGNED = ("request_digest", "anchor", "artifact_kind", "artifact_digest", "issued_at")


def refusal_profile(refusal: Mapping[str, Any]) -> str | None:
    """The profile a carried refusal is read in: one that carries ``sig`` and
    no ``signature`` is in :data:`THREE_MEMBER_REFUSAL`, unless it also
    carries ``policy_digest`` (an evidence-interop/2 refusal may sign it), in
    which case it is in none of these profiles (``None``); every other refusal
    is in :data:`WHOLE_REFUSAL`. Presence decides; a ``null`` member is
    present."""
    if "sig" in refusal and "signature" not in refusal:
        return None if "policy_digest" in refusal else THREE_MEMBER_REFUSAL
    return WHOLE_REFUSAL


def response_profile(response: Mapping[str, Any]) -> str | None:
    """:data:`DIGEST_BOUND_ARTIFACT_RESPONSE` for a carried response that
    does not carry ``responder``; ``None`` for one that does, which is in none
    of these profiles."""
    return None if "responder" in response else DIGEST_BOUND_ARTIFACT_RESPONSE


def _verifies(key: Any, sig: Any, message: bytes) -> bool:
    if not isinstance(key, str) or not isinstance(sig, str) or not _KEY.fullmatch(key) or not _SIG.fullmatch(sig):
        return False
    return verify_strict(bytes.fromhex(key), message, bytes.fromhex(sig))


def _strings(value: Mapping[str, Any], names: tuple[str, ...]) -> dict[str, str] | None:
    picked = {name: value.get(name) for name in names}
    if not all(name in value and isinstance(picked[name], str) for name in names):
        return None
    return picked  # type: ignore[return-value]


def three_member_refusal_signing_input(refusal: Mapping[str, Any]) -> bytes | None:
    """UTF-8 JCS of ``{issued_at, reason, request_digest}``, or ``None`` when
    one of them is absent or not a string."""
    signed = _strings(refusal, _REFUSAL_SIGNED)
    if signed is None:
        return None
    try:
        return jcs(signed)
    except ValueError:  # a string JCS cannot serialize, such as an unpaired surrogate
        return None


def verify_three_member_refusal(refusal: Mapping[str, Any]) -> str:
    """The refusal's ``sig`` under its ``key_id`` in
    :data:`THREE_MEMBER_REFUSAL`. A refusal in this profile carries ``sig``,
    so it is never signature-unverified."""
    message = three_member_refusal_signing_input(refusal)
    if message is None:
        return _INVALID
    return _VERIFIED if _verifies(refusal.get("key_id"), refusal.get("sig"), message) else _INVALID


def verify_whole_refusal(refusal: Mapping[str, Any]) -> str:
    """The refusal's ``signature`` under its ``key_id`` over the JCS of the
    refusal without ``signature``, in :data:`WHOLE_REFUSAL`."""
    if "key_id" not in refusal and "signature" not in refusal:
        return _UNVERIFIED
    try:
        message = jcs({name: member for name, member in refusal.items() if name != "signature"})
    except (TypeError, ValueError):
        return _INVALID
    return _VERIFIED if _verifies(refusal.get("key_id"), refusal.get("signature"), message) else _INVALID


def verify_carried_refusal(refusal: Mapping[str, Any]) -> str:
    """A carried refusal's signature in the profile :func:`refusal_profile`
    reads it in."""
    profile = refusal_profile(refusal)
    if profile is None:
        return _UNVERIFIED
    if profile == THREE_MEMBER_REFUSAL:
        return verify_three_member_refusal(refusal)
    return verify_whole_refusal(refusal)


def artifact_response_signing_input(
    request_digest: str, anchor: str, artifact_kind: str, artifact_digest: str, issued_at: str
) -> bytes:
    """The signing input of :data:`DIGEST_BOUND_ARTIFACT_RESPONSE`: UTF-8 JCS
    of the five members plus ``type`` :data:`ARTIFACT_RESPONSE_TYPE`."""
    return jcs({
        "type": ARTIFACT_RESPONSE_TYPE, "request_digest": request_digest, "anchor": anchor,
        "artifact_kind": artifact_kind, "artifact_digest": artifact_digest, "issued_at": issued_at,
    })


def verify_digest_bound_artifact_response(response: Mapping[str, Any]) -> str:
    """A carried response's ``sig`` under its ``key_id`` in
    :data:`DIGEST_BOUND_ARTIFACT_RESPONSE`. A response that carries
    ``responder`` is in none of these profiles and is signature-unverified, as
    is one that carries neither ``key_id`` nor ``sig``."""
    if response_profile(response) is None:
        return _UNVERIFIED
    if "key_id" not in response and "sig" not in response:
        return _UNVERIFIED
    signed = _strings(response, _RESPONSE_SIGNED)
    if signed is None:
        return _INVALID
    try:
        message = artifact_response_signing_input(**signed)
    except ValueError:  # a string JCS cannot serialize, such as an unpaired surrogate
        return _INVALID
    return _VERIFIED if _verifies(response.get("key_id"), response.get("sig"), message) else _INVALID


#: The response hook: every carried response this module can check.
verify_carried_response = verify_digest_bound_artifact_response
