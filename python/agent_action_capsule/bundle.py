# SPDX-License-Identifier: BSD-3-Clause
"""Deprecated: the Evidence Bundle codec has moved to ``capsule-emit``.

``agent-action-capsule`` is now spec + registry only ([evidence-bundle-codec-
to-capsule-emit]); the codec (``bundle_digest``, ``verify_bundle``, the
fragment codec) lives in ``capsule_emit.evidence_bundle``, byte-for-byte the
same logic this module used to hold (it was ported, not reforked — see that
module's docstring). This module re-exports the same names so existing
importers (``from agent_action_capsule.bundle import bundle_digest`` etc.,
including this package's own ``__init__.py``) keep working during the
transition; each callable warns once it is actually invoked, the same
deprecated-alias pattern already used by ``agent_action_capsule.anchor()``.

Import from ``capsule_emit.evidence_bundle`` directly in new code. This shim
requires the ``capsule-emit`` package to be installed -- it is intentionally
NOT added to this package's own dependencies (kept stdlib-only per
``pyproject.toml``); a caller who never touches the deprecated bundle API
never needs ``capsule-emit`` installed at all.
"""
from __future__ import annotations

import warnings
from typing import Any

__all__ = [
    "ClaimResult",
    "DisclosureResult",
    "ExtensionResult",
    "CountersignatureResult",
    "ProducerSelfReport",
    "BundleVerificationResult",
    "bundle_digest",
    "encode_fragment",
    "decode_fragment",
    "verify_bundle",
]

_DEPRECATION_MESSAGE = (
    "agent_action_capsule.bundle is deprecated; agent-action-capsule is now "
    "spec + registry only. Import from capsule_emit.evidence_bundle instead "
    "(requires the `capsule-emit` package to be installed)."
)


def _evidence_bundle():
    try:
        import capsule_emit.evidence_bundle as module
    except ImportError as exc:
        raise ImportError(
            "agent_action_capsule.bundle is a deprecated shim over "
            "capsule_emit.evidence_bundle, which is not installed. Install "
            "the `capsule-emit` package to use the Evidence Bundle codec."
        ) from exc
    return module


def _warn(name: str) -> None:
    warnings.warn(
        f"agent_action_capsule.bundle.{name}() is deprecated; use "
        f"capsule_emit.evidence_bundle.{name}() instead. {_DEPRECATION_MESSAGE}",
        DeprecationWarning,
        stacklevel=3,
    )


def bundle_digest(bundle: Any) -> str:
    """Deprecated alias for :func:`capsule_emit.evidence_bundle.bundle_digest`."""
    _warn("bundle_digest")
    return _evidence_bundle().bundle_digest(bundle)


def verify_bundle(bundle: Any) -> BundleVerificationResult:
    """Deprecated alias for :func:`capsule_emit.evidence_bundle.verify_bundle`."""
    _warn("verify_bundle")
    return _evidence_bundle().verify_bundle(bundle)


def encode_fragment(bundle: Any) -> str:
    """Deprecated alias for :func:`capsule_emit.evidence_bundle.encode_fragment`."""
    _warn("encode_fragment")
    return _evidence_bundle().encode_fragment(bundle)


def decode_fragment(fragment: str) -> Any:
    """Deprecated alias for :func:`capsule_emit.evidence_bundle.decode_fragment`."""
    _warn("decode_fragment")
    return _evidence_bundle().decode_fragment(fragment)


def __getattr__(name: str) -> Any:
    """Lazily re-export the result dataclasses without requiring capsule-emit
    at import time -- only touched when a caller actually references one
    (e.g. ``from agent_action_capsule.bundle import BundleVerificationResult``,
    which this package's own ``__init__.py`` does eagerly at import time, so
    this must not raise merely because capsule-emit happens to be absent from
    an environment that never uses the Evidence Bundle codec)."""
    if name in (
        "ClaimResult",
        "DisclosureResult",
        "ExtensionResult",
        "CountersignatureResult",
        "ProducerSelfReport",
        "BundleVerificationResult",
    ):
        try:
            return getattr(_evidence_bundle(), name)
        except ImportError:
            # capsule-emit is absent: hand back a stand-in class whose
            # instantiation (not mere reference) fails with a clear message,
            # so `from agent_action_capsule.bundle import BundleVerificationResult`
            # continues to succeed for a caller that only wants the name as a
            # type hint / isinstance target and never touches the codec.
            class _Unavailable:
                def __init__(self, *args, **kwargs):
                    raise ImportError(
                        f"agent_action_capsule.bundle.{name} requires the "
                        "`capsule-emit` package, which is not installed."
                    )

            _Unavailable.__name__ = name
            _Unavailable.__qualname__ = name
            return _Unavailable
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
