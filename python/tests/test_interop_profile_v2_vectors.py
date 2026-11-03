# SPDX-License-Identifier: BSD-3-Clause
"""The evidence-interop/2 conformance vectors, checked from their inputs alone.

v2 changes the refusal's signing input (v2 §6.3, P-69) and the identifier, nothing else the
evaluator of ``test_interop_profile_v0_vectors.py`` derives. So this module runs that evaluator
again, as a separate module instance with ``_PROFILE_VERSION`` 2, against
``vectors/interop-profile-v2/``, ``vectors/interop-profile-v2-requirement-facts/`` and
``spec/interop-profile-v2.md``, and collects its tests here.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "interop_profile_vectors_v2", Path(__file__).with_name("test_interop_profile_v0_vectors.py"))
assert _spec is not None and _spec.loader is not None
_v2 = importlib.util.module_from_spec(_spec)
_v2._PROFILE_VERSION = 2  # read by the module before anything else
_spec.loader.exec_module(_v2)

globals().update({name: value for name, value in vars(_v2).items() if name.startswith("test_")})
