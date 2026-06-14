# SPDX-License-Identifier: BSD-3-Clause
"""Reference implementation of draft-mih-scitt-agent-action-capsule.

Class 1 verifier (§6) + the typed producer carriers (§5). Substrate verification
(COSE_Sign1 signature, registration, Receipts) is the SCITT/COSE substrate's, by
reference, and is not implemented here. Class 2 / manifest-aware verification is
out of scope.
"""
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
    derive_effect_mode,
)
from .parse import Capsule, parse_capsule
from .registries import REGISTRY_NAMES, load_registries
from .verify import Finding, VerificationResult, verify, verify_store

__version__ = "0.0.1"

__all__ = [
    "__version__",
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
