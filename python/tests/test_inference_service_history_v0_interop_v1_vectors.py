# SPDX-License-Identifier: BSD-3-Clause
"""The Inference-Service History Profile vectors under evidence-interop/1
(``vectors/inference-service-history-v0-interop-v1/``), checked from their inputs alone.

The cases and their checks are those of ``test_inference_service_history_v0_vectors.py``; this
module runs that module again, as a separate instance with ``_PROFILE_VERSION`` 1, and collects
its tests here.
"""
from __future__ import annotations

import importlib.util
from pathlib import Path

_spec = importlib.util.spec_from_file_location(
    "inference_service_history_vectors_interop_v1",
    Path(__file__).with_name("test_inference_service_history_v0_vectors.py"))
assert _spec is not None and _spec.loader is not None
_v1 = importlib.util.module_from_spec(_spec)
_v1._PROFILE_VERSION = 1  # read by the module before anything else
_spec.loader.exec_module(_v1)

globals().update({name: value for name, value in vars(_v1).items() if name.startswith("test_")})
