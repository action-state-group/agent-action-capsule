# SPDX-License-Identifier: BSD-3-Clause
from agent_action_capsule import DISCLOSURE_ELIGIBLE_FIELDS, __version__


def test_disclosure_eligibility_table_is_complete():
    assert DISCLOSURE_ELIGIBLE_FIELDS == {
        "agent_input": "model_attestation.compute_attestation.agent_input_digest",
        "agent_output": "model_attestation.compute_attestation.agent_output_digest",
    }


def test_runtime_version_matches_package_metadata():
    assert __version__ == "0.3.0"
