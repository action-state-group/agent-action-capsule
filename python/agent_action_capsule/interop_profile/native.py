# SPDX-License-Identifier: BSD-3-Clause
"""Native checks for foreign signed objects carried in an Artifact (profile §5.1, §7.2).

A foreign object is checked over its octets as its own protocol delivered them, never parsed and
re-serialized (§5.1, the as-transmitted rule). Each checker is keyed by the object's media type
and names its method in the report. Only one is built in: JWS compact serialization with EdDSA,
the form the conformance vectors carry. A caller adds others through
``InteropVerifier(native_checkers=...)``; an object whose media type has no checker is reported
``NOT_CHECKED`` (unsupported method, §7.1).
"""
from __future__ import annotations

from typing import Any, Callable

from ._common import (
    FAIL,
    INCONCLUSIVE,
    PASS,
    PropertyReport,
    TrustPolicy,
    b64url_decode,
    ed25519_verify,
    is_key_id,
    parse_json,
)

__all__ = ["NativeChecker", "check_jws_eddsa", "default_native_checkers"]

# (the object as carried, the trust policy, the evaluation time) -> the native_check report
NativeChecker = Callable[[Any, TrustPolicy, str], PropertyReport]

_JWS_METHOD = "JWS compact serialization (RFC 7515), EdDSA (RFC 8037), under the key its kid names"


def check_jws_eddsa(obj: Any, trust: TrustPolicy, evaluation_time: str) -> PropertyReport:
    """Verify a JWS compact serialization signed with EdDSA over Ed25519.

    The signing input is the ASCII of ``header.payload`` exactly as carried (RFC 7515 §5.2), so
    the payload is never re-encoded. ``kid`` names the raw public key in the §5.2 hex form, and the
    trust policy must accept it as a key for foreign objects at the evaluation time: the JWS
    carries no signing time, so this is an as-of-evaluation check (FR-31).
    """
    def report(status: str, detail: str | None = None) -> PropertyReport:
        return PropertyReport("native_check", status, _JWS_METHOD, detail)

    if not isinstance(obj, str) or obj.count(".") != 2:
        return report(FAIL, "not a JWS compact serialization")
    header_b64, payload_b64, sig_b64 = obj.split(".")
    header_raw, signature = b64url_decode(header_b64), b64url_decode(sig_b64)
    if header_raw is None or signature is None or b64url_decode(payload_b64) is None:
        return report(FAIL, "a segment is not base64url")
    header = parse_json(header_raw)
    if header is None or not header.well_formed or not isinstance(header.value, dict):
        return report(FAIL, "the protected header is not a well-formed JSON object")
    h = header.value
    if h.get("alg") != "EdDSA":
        return report(FAIL, f"alg is {h.get('alg')!r}, not EdDSA")
    if "crit" in h:
        return report(FAIL, "crit is present and no extension is understood (RFC 7515 §4.1.11)")
    kid = h.get("kid")
    if not is_key_id(kid):
        return report(FAIL, "kid is not a raw Ed25519 public key in hex (§5.2)")
    status = trust.accepts_foreign_key(kid, evaluation_time)
    if status == FAIL:
        return report(FAIL, "the trust policy does not accept the key kid names")
    if status == INCONCLUSIVE:
        return report(INCONCLUSIVE, "the trust policy cannot resolve the key's status")
    ok = ed25519_verify(bytes.fromhex(kid), signature, f"{header_b64}.{payload_b64}".encode("ascii"))
    return report(PASS) if ok else report(FAIL, "the signature does not verify")


def default_native_checkers() -> dict[str, NativeChecker]:
    return {"application/jose": check_jws_eddsa}
