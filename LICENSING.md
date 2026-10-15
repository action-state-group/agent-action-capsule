> **Licensing note:** the code in this repository is BSD-3-Clause (see LICENSE),
> except the Apache-2.0 paths listed in section 3. The specification text under
> `spec/` is governed by BCP 78/79. See LICENSING.md for the full statement.

This repository contains an IETF Internet-Draft and related material. Two
licensing regimes apply, by content type.

================================================================================
1. SPECIFICATION TEXT
   (the Internet-Draft "draft-mih-scitt-agent-action-capsule" under spec/,
   its built .xml/.txt artifacts, and spec/REGISTRY.md and spec/section-map.md)
================================================================================

Copyright (c) 2026 IETF Trust and the persons identified as authors of the
document. All rights reserved.

This document is subject to BCP 78 and the IETF Trust's Legal Provisions
Relating to IETF Documents (https://trustee.ietf.org/license-info) in effect on
the date of submission of this document. Please review these documents
carefully, as they describe your rights and restrictions with respect to this
document. Code Components extracted from this document must include Revised BSD
License text as described in Section 4.e of the Trust Legal Provisions and are
provided without warranty as described in the Revised BSD License.

Contributions to the specification text in this repository are made under, and
are governed by, BCP 78 ("Rights Contributors Provide to the IETF Trust") and
BCP 79 ("Intellectual Property Rights in IETF Technology"). See CONTRIBUTING.md.

================================================================================
2. CODE AND OTHER NON-DRAFT MATERIAL
   (the contents of python/, test-vector generators, build scripts such as
   spec/Makefile, and repository tooling)
================================================================================

Copyright (c) 2026 Action State Group, Inc.
SPDX-License-Identifier: BSD-3-Clause

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation
   and/or other materials provided with the distribution.

3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software
   without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

================================================================================
3. APACHE-2.0 CODE
   (code brought in from other Action State Group repositories under its
   original license; nothing was relicensed)
================================================================================

The following paths are licensed under the Apache License, Version 2.0 (see
LICENSE-APACHE-2.0), not under section 2. Each source file carries
`SPDX-License-Identifier: Apache-2.0`, and that header is authoritative for any
file not listed here.

- rust/evidence-request/ (the `evidence-request` crate, with its own LICENSE
  and NOTICE). Its scitt-cose receipt vectors under
  rust/evidence-request/tests/vectors/scitt-proof-array/ keep their Apache-2.0
  notice.
- python/agent_action_capsule/evidence_request.py and
  python/tests/test_evidence_request.py.
- The shared repository tooling .github/release.py, .github/test_release.py,
  .github/leak_lint.py, .github/test_leak_lint.py and
  .github/workflows/leak-lint.yml.

The conformance vectors those implementations read (vectors/evidence-request/)
remain BSD-3-Clause under section 2.
