// SPDX-License-Identifier: BSD-3-Clause
// Command cross_language is the stdin/stdout adapter for the CI interlock.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/verify"
)

func main() {
	if len(os.Args) != 2 || (os.Args[1] != "seal" && os.Args[1] != "verify") {
		fmt.Fprintln(os.Stderr, "usage: cross_language seal|verify")
		os.Exit(2)
	}
	decoder := json.NewDecoder(os.Stdin)
	decoder.UseNumber()
	var capsule map[string]interface{}
	if err := decoder.Decode(&capsule); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if os.Args[1] == "seal" {
		id, err := canonical.ComputeCapsuleID(capsule)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		capsule["capsule_id"] = id
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetEscapeHTML(false)
		if err := encoder.Encode(capsule); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	result := verify.Verify(capsule, nil, nil)
	if !result.OK {
		for _, finding := range result.Findings {
			fmt.Fprintln(os.Stderr, finding.Code)
		}
		os.Exit(1)
	}
	if result.CapsuleID != nil {
		fmt.Println(*result.CapsuleID)
	}
}
