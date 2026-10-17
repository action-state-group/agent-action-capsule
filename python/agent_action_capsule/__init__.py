# SPDX-License-Identifier: BSD-3-Clause
"""Reference implementation of draft-mih-scitt-agent-action-capsule.

Class 1 verifier (§6) + the typed producer carriers (§5) with their sealing
boundary ``Capsule.seal()`` + the anchor client (rung 6). Producing capsules
as an agent acts (``emit()`` and the framework adapters) is capsule-emit's job;
this package removed its own in 0.10.0. Substrate verification (COSE_Sign1
signature, registration, Receipts) is the SCITT/COSE substrate's, by reference,
and is not implemented here. Class 2 / manifest-aware verification is out of
scope.
"""
import warnings
from importlib.metadata import PackageNotFoundError as _PackageNotFoundError
from importlib.metadata import version as _metadata_version

from .anchor import DEFAULT_ANCHOR_ENDPOINT
from .anchor import anchor as anchor_capsule
from .bundle import (
    BundleVerificationResult,
    ClaimResult,
    DisclosureResult,
    ExtensionResult,
    bundle_digest,
    decode_fragment,
    encode_fragment,
    verify_bundle,
)
from .canonical import (
    FloatInDigestError,
    UnsafeIntegerError,
    compute_capsule_id,
    jcs,
    json_digest,
)
from .contracts import (
    AssuranceBlock,
    Chain,
    ConstraintRecord,
    Disposition,
    EffectRecord,
    ExpiryPolicy,
    InvariantError,
    LogCoordinates,
    ModelAttestation,
    ReferenceEntry,
    derive_effect_mode,
)
from .disclosure_envelope import (
    DISCLOSURE_ELIGIBLE_FIELDS,
    DisclosureEnvelopeResult,
    DisclosureFinding,
    build_disclosure_envelope,
    verify_disclosure_envelope,
)
from .parse import Capsule, parse_capsule
from .registries import REGISTRY_NAMES, load_registries
from .verify import Finding, VerificationResult, verify, verify_store
from .versions import (
    ACCEPTED_SPEC_VERSIONS,
    DEFAULT_FORMAT_VERSION,
    DEFAULT_SPEC_VERSION,
    FORMAT_VERSION,
    SPEC_VERSION,
)

# pyproject.toml is the one version source (Release · Prepare bumps only it);
# read it from the installed distribution instead of repeating it here.
try:
    __version__ = _metadata_version("agent-action-capsule")
except _PackageNotFoundError:  # imported from a source tree that is not installed
    __version__ = "0+unknown"


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
    # versions (agent_action_capsule.versions)
    "DEFAULT_SPEC_VERSION",
    "DEFAULT_FORMAT_VERSION",
    "ACCEPTED_SPEC_VERSIONS",
    # Aliases kept for the former emit-tier adapter surface.
    "SPEC_VERSION",
    "FORMAT_VERSION",
    # rung 6: anchor client
    "anchor_capsule",
    "anchor",  # deprecated alias for anchor_capsule; see its docstring
    "DEFAULT_ANCHOR_ENDPOINT",
    # evidence bundle
    "encode_fragment",
    "decode_fragment",
    "bundle_digest",
    "verify_bundle",
    "BundleVerificationResult",
    "ClaimResult",
    "DisclosureResult",
    "ExtensionResult",
    # verification
    "verify",
    "verify_store",
    "VerificationResult",
    "Finding",
    # disclosure envelope
    "build_disclosure_envelope",
    "verify_disclosure_envelope",
    "DisclosureEnvelopeResult",
    "DisclosureFinding",
    "DISCLOSURE_ELIGIBLE_FIELDS",
    # producer / typed
    "Capsule",
    "parse_capsule",
    "Disposition",
    "EffectRecord",
    "AssuranceBlock",
    "Chain",
    "ConstraintRecord",
    "ExpiryPolicy",
    "LogCoordinates",
    "ReferenceEntry",
    "ModelAttestation",
    "InvariantError",
    "derive_effect_mode",
    # canonicalization
    "compute_capsule_id",
    "json_digest",
    "jcs",
    "FloatInDigestError",
    "UnsafeIntegerError",
    # registries
    "load_registries",
    "REGISTRY_NAMES",
]
