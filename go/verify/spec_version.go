// SPDX-License-Identifier: BSD-3-Clause

package verify

// CurrentSpecVersion is the spec_version a producer conforming to draft -05
// emits ("Identity and parties").
const CurrentSpecVersion = "draft-mih-scitt-agent-action-capsule-05"

// AcceptedSpecVersions are the spec_version values a verifier MUST accept: the
// revisions that define format 4. spec_version never selects a digest or
// verification algorithm, and an unrecognized value is never by itself a
// reason to reject, so Verify never branches on it.
var AcceptedSpecVersions = []string{
	"draft-mih-scitt-agent-action-capsule-04",
	CurrentSpecVersion,
}
