# SPDX-License-Identifier: BSD-3-Clause
"""Reference verifier for the Minimum Evidence Interoperability Profile, ``evidence-interop/0``
(``spec/interop-profile-v0.md``) and ``evidence-interop/1`` (``spec/interop-profile-v1.md``). Each
exchange is checked under the identifier it names; v1 differs in its refusal reasons (§9.1, §8.1).

- :class:`InteropVerifier` checks evidence-request exchanges: per-property statuses with the
  method used (§7), ``caller_invariance`` across every envelope held, ``native_check`` of a
  carried foreign object, and the §8 mapping to Evidence Result claims.
- :func:`evaluate_acceptance` reports the acceptance properties and finding (§11.1).
- :func:`evaluate_lifecycle` reports lifecycle statements and what a verifier shows (§11.2).
- :mod:`.carriage` finds and classifies replies carried over A2A and MCP, and checks manifests
  (§11.4).

Offline by construction (NFR-7): nothing here opens a connection or reads the clock. An online
check is ``NOT_CHECKED`` unless the caller supplies a resolver. Every "as of" time is an input
(FR-31).
"""
from ._common import (
    FAIL,
    INCONCLUSIVE,
    NOT_CHECKED,
    NOT_PRESENT,
    PASS,
    PROFILE_ID,
    PROFILE_IDS,
    PROFILE_V1,
    STATUSES,
    PropertyReport,
    TrustPolicy,
    VerificationPolicy,
)
from .acceptance import AcceptanceResult, evaluate_acceptance, read_fixture_execution_record
from .exchange import (
    Exchange,
    ExchangeResult,
    ForeignObject,
    InteropVerifier,
    Message,
    ReplyResult,
    RequirementResult,
    VerificationResult,
)
from .lifecycle import HeldRecord, LifecycleResult, evaluate_lifecycle

__all__ = [
    "PROFILE_ID", "PROFILE_V1", "PROFILE_IDS", "PASS", "FAIL", "NOT_PRESENT", "NOT_CHECKED", "INCONCLUSIVE", "STATUSES",
    "PropertyReport", "TrustPolicy", "VerificationPolicy",
    "InteropVerifier", "Exchange", "Message", "ForeignObject", "ReplyResult", "RequirementResult",
    "ExchangeResult", "VerificationResult",
    "evaluate_acceptance", "AcceptanceResult", "read_fixture_execution_record",
    "evaluate_lifecycle", "HeldRecord", "LifecycleResult",
]
