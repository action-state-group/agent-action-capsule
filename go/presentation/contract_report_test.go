// SPDX-License-Identifier: BSD-3-Clause
package presentation

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// contract-report/v1 (spec/contract-report-v1.md) is engaged only by a closed
// empty object; every other block is declined. The shared descriptor vectors
// cover the same cases over real bundles.
func TestContractReportEngaged(t *testing.T) {
	cases := []struct {
		name  string
		block interface{}
		want  bool
	}{
		{"empty object", map[string]interface{}{}, true},
		{"a member", map[string]interface{}{"wording_sha256": "00"}, false},
		{"an enabled flag", map[string]interface{}{"enabled": true}, false},
		{"an x- member", map[string]interface{}{"x-note": "text"}, false},
		{"an array", []interface{}{}, false},
		{"null", nil, false},
		{"a string", "contract-report", false},
		{"a number", float64(1), false},
		{"true", true, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			assert.Equal(t, c.want, contractReportEngaged(c.block))
		})
	}
	assert.Contains(t, extensionReaders, "contract-report/v1")
}
