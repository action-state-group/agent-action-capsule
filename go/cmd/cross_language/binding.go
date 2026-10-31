// SPDX-License-Identifier: BSD-3-Clause
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/action-state-group/agent-action-capsule/go/controllerbinding"
	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

// bindingMembers are the members of the binding mode's stdin, one JSON
// object, each with whether it is required. binding is the
// binding record as transmitted, as text; revocations and credential are
// what was received beside it; revocation_list is a revocation list a using
// profile declared complete (CB §5.1); at is the times T; key is the key the
// binding must name, such as a node's advertised evidence key.
var bindingMembers = map[string]bool{"binding": true, "revocations": false, "revocation_list": false,
	"credential": false, "at": true, "key": false}

// revocationListMembers are the members of revocation_list, each with whether
// it is required: declaration is the declaration's JSON object (CB §5.1), list
// is the list's octets as transmitted, as text, and evaluated_at is the
// evaluation time E, the current time when absent.
var revocationListMembers = map[string]bool{"declaration": true, "list": true, "evaluated_at": false}

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
// NOT_CHECKED); 2 is bad input, or a report that could not be written. The
// credential never decides the code (CB §6.2), and with no credential verifier here it is NOT_CHECKED, or
// NOT_PRESENT when none was given. A declared revocation list
// never changes the code unless a statement in it applies: revocation PASS
// and NOT_CHECKED both leave the binding applying (CB §9.4).
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
	if _, err := fmt.Fprintln(out, string(encoded)); err != nil {
		fmt.Fprintln(errOut, err)
		return 2 // no report reached the caller, so no verdict did either
	}
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
	if rl, present := input["revocation_list"]; present {
		list, err := readRevocationList(rl)
		if err != nil {
			return nil, nil, "", opts, err
		}
		opts.RevocationList = list
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
		text, _ := item.(string)
		t, ok := evidencerequest.ParseProfileTime(text)
		if !ok {
			return nil, nil, "", opts, fmt.Errorf("at holds %v, not a time YYYY-MM-DDTHH:MM:SSZ", item)
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

// readRevocationList reads the revocation_list member. A declaration that is
// not in its form is bad input here, since the caller is the using profile
// that wrote it; the verifier's own rule is that it does not count.
func readRevocationList(value any) (*controllerbinding.RevocationList, error) {
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("revocation_list is not a JSON object")
	}
	for name := range m {
		if _, known := revocationListMembers[name]; !known {
			return nil, fmt.Errorf("unknown revocation_list member %q", name)
		}
	}
	for name, required := range revocationListMembers {
		if _, present := m[name]; required && !present {
			return nil, fmt.Errorf("missing revocation_list member %q", name)
		}
	}
	encoded, err := evidencerequest.EncodeJCS(m["declaration"])
	if err != nil {
		return nil, fmt.Errorf("declaration: %w", err)
	}
	declaration, err := controllerbinding.ParseDeclaration(encoded)
	if err != nil {
		return nil, fmt.Errorf("declaration: %w", err)
	}
	text, ok := m["list"].(string)
	if !ok {
		return nil, fmt.Errorf("list is not the revocation list's text")
	}
	evaluated := time.Now().UTC().Truncate(time.Second)
	if at, present := m["evaluated_at"]; present {
		s, _ := at.(string)
		if evaluated, ok = evidencerequest.ParseProfileTime(s); !ok {
			return nil, fmt.Errorf("evaluated_at holds %v, not a time YYYY-MM-DDTHH:MM:SSZ", at)
		}
	}
	return &controllerbinding.RevocationList{Declaration: declaration, List: []byte(text), EvaluatedAt: evaluated}, nil
}
