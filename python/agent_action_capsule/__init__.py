# SPDX-License-Identifier: BSD-3-Clause
"""Reference implementation of draft-mih-scitt-agent-action-capsule.

Class 1 verifier (§6) + the typed producer carriers (§5) + the high-level
emit/anchor surface (rungs 1+2+6) + emit-tier framework adapters. Substrate
verification (COSE_Sign1 signature, registration, Receipts) is the SCITT/COSE
substrate's, by reference, and is not implemented here. Class 2 / manifest-aware
verification is out of scope.
"""
import warnings

from .anchor import DEFAULT_ANCHOR_ENDPOINT
from .anchor import anchor as anchor_capsule
from .canonical import (
    FloatInDigestError,
    UnsafeIntegerError,
    compute_capsule_id,
    jcs,
    json_digest,
    normalize,
)
from .contracts import (
    AssuranceBlock,
    Chain,
    ConstraintRecord,
    Disposition,
    EffectRecord,
    ExpiryPolicy,
    InvariantError,
    ModelAttestation,
    derive_effect_mode,
)
from .emit import DEFAULT_FORMAT_VERSION, DEFAULT_SPEC_VERSION, FORMAT_VERSION, SPEC_VERSION, emit
from .parse import Capsule, parse_capsule
from .registries import REGISTRY_NAMES, load_registries
from .verify import Finding, VerificationResult, verify, verify_store

__version__ = "0.1.0"


def anchor(*args, **kwargs):
    """Deprecated alias for :func:`anchor_capsule`.

    ``agent_action_capsule.anchor`` (this function) collides with the
    ``agent_action_capsule.anchor`` submodule on attribute access — importing
    this name overwrites the submodule binding that Python's package import
    machinery sets, so ``import agent_action_capsule.anchor as m`` resolves to
    whichever one was bound most recently. Use :func:`anchor_capsule` instead;
    this alias will be removed in a future release, at which point
    ``agent_action_capsule.anchor`` will unambiguously refer to the submodule.
    """
    warnings.warn(
        "agent_action_capsule.anchor() is deprecated and will be removed in a "
        "future release; use agent_action_capsule.anchor_capsule() instead. "
        "(The `anchor` name also refers to the agent_action_capsule.anchor "
        "submodule, which this deprecated alias currently shadows.)",
        DeprecationWarning,
        stacklevel=2,
    )
    return anchor_capsule(*args, **kwargs)


__all__ = [
    "__version__",
    # rung 1: emit
    "emit",
    "DEFAULT_SPEC_VERSION",
    "DEFAULT_FORMAT_VERSION",
    # Aliases used by the emit-tier adapter surface.
    "SPEC_VERSION",
    "FORMAT_VERSION",
    # rung 6: anchor client
    "anchor_capsule",
    "anchor",  # deprecated alias for anchor_capsule; see its docstring
    "DEFAULT_ANCHOR_ENDPOINT",
    # verification
    "verify",
    "verify_store",
    "VerificationResult",
    "Finding",
    # producer / typed
    "Capsule",
    "parse_capsule",
    "Disposition",
    "EffectRecord",
    "AssuranceBlock",
    "Chain",
    "ConstraintRecord",
    "ExpiryPolicy",
    "ModelAttestation",
    "InvariantError",
    "derive_effect_mode",
    # canonicalization
    "compute_capsule_id",
    "json_digest",
    "jcs",
    "normalize",
    "FloatInDigestError",
    "UnsafeIntegerError",
    # registries
    "load_registries",
    "REGISTRY_NAMES",
]
