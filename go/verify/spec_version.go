// SPDX-License-Identifier: BSD-3-Clause

package verify

// CurrentSpecVersion is the spec_version a producer emits: the newest
// published value (draft -05, "Identity and parties").
const CurrentSpecVersion = "draft-mih-scitt-agent-action-capsule-05"

// PublishedSpecVersions lists every published spec_version value. A verifier
// accepts all of them: spec_version selects no digest or verification
// algorithm, so Verify never branches on it and a Capsule carrying an earlier
// revision's value verifies unchanged.
var PublishedSpecVersions = []string{
	"draft-mih-scitt-agent-action-capsule-00",
	"draft-mih-scitt-agent-action-capsule-01",
	"draft-mih-scitt-agent-action-capsule-02",
	"draft-mih-scitt-agent-action-capsule-03",
	"draft-mih-scitt-agent-action-capsule-04",
	CurrentSpecVersion,
}
