# SPDX-License-Identifier: BSD-3-Clause
"""Reference implementation of draft-mih-scitt-agent-action-capsule.

Class 1 verifier (§6) + the typed producer carriers (§5) + the high-level
emit/anchor surface (rungs 1+2+6). Substrate verification (COSE_Sign1
signature, registration, Receipts) is the SCITT/COSE substrate's, by
reference, and is not implemented here. Class 2 / manifest-aware verification
is out of scope.
"""
from .anchor import DEFAULT_ANCHOR_ENDPOINT, anchor
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
from .emit import DEFAULT_FORMAT_VERSION, DEFAULT_SPEC_VERSION, emit
from .parse import Capsule, parse_capsule
from .registries import REGISTRY_NAMES, load_registries
from .verify import Finding, VerificationResult, verify, verify_store

__version__ = "0.1.0"

__all__ = [
    "__version__",
    # rung 1: emit
    "emit",
    "DEFAULT_SPEC_VERSION",
    "DEFAULT_FORMAT_VERSION",
    # rung 6: anchor client
    "anchor",
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
