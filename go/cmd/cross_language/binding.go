// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/controllerbinding"
	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

// bindingMembers are the members of the binding mode's stdin, one JSON
// object, each with whether it is required. binding is the
// binding record as transmitted, as text; revocations and credential are
// what was received beside it; at is the times T; key is the key the binding
// must name, such as a node's advertised evidence key.
var bindingMembers = map[string]bool{"binding": true, "revocations": false, "credential": false, "at": true, "key": false}

var bindingTime = regexp.MustCompile(`^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$`)

// bindingOutput is the binding mode's stdout: the controllerbinding report,
// the key asked about, and whether the binding applies.
type bindingOutput struct {
	controllerbinding.Report
	Key     string `json:"key,omitempty"`
	Applies bool   `json:"applies"`
}

// binding verifies one Controller Binding v0 record (spec/controller-binding-v0.md)
// and prints the report as JSON. Exit 0 means the binding applies: form,
// signatures and window PASS at every T, revocation not FAIL, and the record
// names key when key is given. It is not a trust verdict: a binding that
// applies to a pair makes the pair redundant, not corroborating (CB §7 item
// 4), and it never says who controls either key. Exit 1 means it does not
// apply because a property is FAIL or the record does not name key; 3 means
// it does not apply because its method is not implemented (signatures
// NOT_CHECKED); 2 is bad input. The credential never decides the code
// (CB §6.2), and with no credential verifier here it is NOT_CHECKED, or
// NOT_PRESENT when none was given.
func binding(in io.Reader, out, errOut io.Writer) int {
	raw, err := io.ReadAll(in)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	record, ts, key, opts, err := readBindingInput(raw)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	report := controllerbinding.Verify(record, ts, opts)
	result := bindingOutput{Report: report, Key: key, Applies: report.Applies() && (key == "" || report.Binds(key))}
	encoded, err := json.Marshal(result)
	if err != nil {
		fmt.Fprintln(errOut, err)
		return 2
	}
	fmt.Fprintln(out, string(encoded))
	if result.Applies {
		return 0
	}
	if key != "" && !report.Binds(key) {
		return 1
	}
	for _, p := range []string{controllerbinding.PropertyForm, controllerbinding.PropertySignatures,
		controllerbinding.PropertyWindow, controllerbinding.PropertyRevocation} {
		if report.Properties[p] == evidencerequest.StatusFail {
			return 1
		}
	}
	return 3
}

func readBindingInput(raw []byte) ([]byte, []time.Time, string, controllerbinding.Options, error) {
	var opts controllerbinding.Options
	// The verifier's strict reader: one value, no duplicate member, and no
	// invalid UTF-8 or lone surrogate that encoding/json would repair.
	value, err := evidencerequest.DecodeJSON(raw)
	if err != nil {
		return nil, nil, "", opts, err
	}
	input, ok := value.(map[string]any)
	if !ok {
		return nil, nil, "", opts, fmt.Errorf("stdin is not a JSON object")
	}
	for name := range input {
		if _, known := bindingMembers[name]; !known {
			return nil, nil, "", opts, fmt.Errorf("unknown member %q", name)
		}
	}
	for name, required := range bindingMembers {
		if _, present := input[name]; required && !present {
			return nil, nil, "", opts, fmt.Errorf("missing member %q", name)
		}
	}
	record, ok := input["binding"].(string)
	if !ok {
		return nil, nil, "", opts, fmt.Errorf("binding is not the record's text")
	}
	if revocations, present := input["revocations"]; present {
		list, ok := revocations.([]any)
		if !ok {
			return nil, nil, "", opts, fmt.Errorf("revocations is not an array")
		}
		for _, item := range list {
			text, ok := item.(string)
			if !ok {
				return nil, nil, "", opts, fmt.Errorf("a revocation is not a statement's text")
			}
			opts.Revocations = append(opts.Revocations, []byte(text))
		}
	}
	if credential, present := input["credential"]; present {
		text, ok := credential.(string)
		if !ok {
			return nil, nil, "", opts, fmt.Errorf("credential is not the credential's text")
		}
		opts.Credential = []byte(text)
	}
	list, ok := input["at"].([]any)
	if !ok || len(list) == 0 {
		return nil, nil, "", opts, fmt.Errorf("at is not a non-empty array of times")
	}
	var ts []time.Time
	for _, item := range list {
		text, ok := item.(string)
		if !ok || !bindingTime.MatchString(text) {
			return nil, nil, "", opts, fmt.Errorf("at holds %v, not a time YYYY-MM-DDTHH:MM:SSZ", item)
		}
		t, err := time.Parse(time.RFC3339, text)
		if err != nil {
			return nil, nil, "", opts, err
		}
		ts = append(ts, t)
	}
	var key string
	if k, present := input["key"]; present {
		key, ok = k.(string)
		if !ok || !evidencerequest.IsDigest(key) {
			return nil, nil, "", opts, fmt.Errorf("key is not 64 lowercase hex characters")
		}
	}
	return []byte(record), ts, key, opts, nil
}
