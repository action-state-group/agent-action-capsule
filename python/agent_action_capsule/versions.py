# SPDX-License-Identifier: BSD-3-Clause
"""Specification and serialization versions this package seals and accepts.

A producer conforming to draft -05 emits -05; a verifier accepts -04 and -05,
the revisions that define format 4 (draft -05, "Identity and parties").
``spec_version`` never selects a digest or verification algorithm, and an
unrecognized value is never by itself a rejection, so ``verify()`` never
branches on it.
"""

__all__ = [
    "DEFAULT_SPEC_VERSION",
    "DEFAULT_FORMAT_VERSION",
    "ACCEPTED_SPEC_VERSIONS",
    "SPEC_VERSION",
    "FORMAT_VERSION",
]

DEFAULT_SPEC_VERSION = "draft-mih-scitt-agent-action-capsule-05"
ACCEPTED_SPEC_VERSIONS = (
    "draft-mih-scitt-agent-action-capsule-04",
    DEFAULT_SPEC_VERSION,
)
DEFAULT_FORMAT_VERSION = "4"

# Aliases kept for callers of the former emit-tier adapter surface.
SPEC_VERSION = DEFAULT_SPEC_VERSION
FORMAT_VERSION = DEFAULT_FORMAT_VERSION
