# SPDX-License-Identifier: BSD-3-Clause
"""The evidence-interop/1 conformance vectors, checked from their inputs alone.

v1 changes the §9.1 vocabulary, the §8.1 rows that map it and the ER pin, nothing the evaluator
of ``test_interop_profile_v0_vectors.py`` derives otherwise. So this module runs that evaluator
again, as a separate module instance with ``_PROFILE_VERSION`` 1, against
``vectors/interop-profile-v1/``, ``vectors/interop-profile-v1-requirement-facts/`` and
``spec/interop-profile-v1.md``, and collects its tests here.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "interop_profile_vectors_v1", Path(__file__).with_name("test_interop_profile_v0_vectors.py"))
assert _spec is not None and _spec.loader is not None
_v1 = importlib.util.module_from_spec(_spec)
_v1._PROFILE_VERSION = 1  # read by the module before anything else
_spec.loader.exec_module(_v1)

globals().update({name: value for name, value in vars(_v1).items() if name.startswith("test_")})
