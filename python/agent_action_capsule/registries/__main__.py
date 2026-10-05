# SPDX-License-Identifier: BSD-3-Clause
"""``python -m agent_action_capsule.registries check-vendored FILE [--ref REF] [--registry PATH] [--json]``."""
import sys

from .vendored import main

if __name__ == "__main__":
    sys.exit(main())
