# SPDX-License-Identifier: BSD-3-Clause
"""Regression test for the agent_action_capsule.anchor name collision.

`agent_action_capsule.anchor` (the convenience function, historically the
top-level export) and `agent_action_capsule.anchor` (the submodule) collided
under Python's attribute-wins semantics. The fix: `anchor_capsule` is the
canonical export; `anchor` is kept as a deprecated, warning alias for one
release so `from agent_action_capsule import anchor; anchor(...)` callers
don't break silently.
"""
import warnings

import agent_action_capsule as aac


def test_anchor_capsule_is_the_real_function():
    from agent_action_capsule.anchor import anchor as submodule_anchor

    assert aac.anchor_capsule is submodule_anchor


def test_deprecated_anchor_alias_warns_and_delegates():
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        aac.anchor("a" * 64, endpoint="http://127.0.0.1:1", timeout=0.01)

    deprecations = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert len(deprecations) == 1
    assert "anchor_capsule" in str(deprecations[0].message)


def test_deprecated_anchor_alias_still_exported():
    assert "anchor" in aac.__all__
    assert "anchor_capsule" in aac.__all__
