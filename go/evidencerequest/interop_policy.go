// SPDX-License-Identifier: Apache-2.0

package evidencerequest

import (
	"fmt"
	"slices"
	"time"
)

// LogKey is a key the relying party accepts for a log's checkpoints:
// the CWT iss and sub it signs under, and the raw Ed25519 key in hex.
type LogKey struct {
	Iss, Sub, Kid string
}

// KeyWindow is a key's validity window; a zero bound is open.
type KeyWindow struct {
	NotBefore, NotAfter time.Time
}

// TrustPolicy is the relying party's trust roots for exchanges (profile
// §6.2.1, §7.2). Its shape is the exchange part of the trust_policy pin of
// the conformance vectors. A key absent from every list is not accepted,
// and the policy never decides that a key is current now: that is the
// online responder_key_current check.
type TrustPolicy struct {
	ResponderKeys []string
	LogKeys       []LogKey
	ForeignKeys   []string
	// KeyValidity bounds when a key is accepted; a key outside its window
	// is not accepted at that instant.
	KeyValidity map[string]KeyWindow
}

// TrustPolicyFromPin reads the trust_policy pin of the conformance vectors
// (its exchange members; the acceptance and lifecycle members are not read).
func TrustPolicyFromPin(pin map[string]any) (TrustPolicy, error) {
	var t TrustPolicy
	texts := func(name string) ([]string, error) {
		raw, _ := pin[name].([]any)
		out := make([]string, 0, len(raw))
		for _, item := range raw {
			s, ok := item.(string)
			if !ok {
				return nil, fmt.Errorf("%w: trust policy %s holds a non-text key", ErrInvalid, name)
			}
			out = append(out, s)
		}
		return out, nil
	}
	var err error
	if t.ResponderKeys, err = texts("responder_keys"); err != nil {
		return t, err
	}
	if t.ForeignKeys, err = texts("foreign_keys"); err != nil {
		return t, err
	}
	logKeys, _ := pin["log_keys"].([]any)
	for _, raw := range logKeys {
		entry, _ := raw.(map[string]any)
		iss, ok1 := entry["iss"].(string)
		sub, ok2 := entry["sub"].(string)
		kid, ok3 := entry["kid"].(string)
		if !ok1 || !ok2 || !ok3 {
			return t, fmt.Errorf("%w: trust policy log key is not {iss, sub, kid}", ErrInvalid)
		}
		t.LogKeys = append(t.LogKeys, LogKey{Iss: iss, Sub: sub, Kid: kid})
	}
	if windows, ok := pin["key_validity"].(map[string]any); ok {
		t.KeyValidity = map[string]KeyWindow{}
		for key, raw := range windows {
			entry, _ := raw.(map[string]any)
			var w KeyWindow
			for name, bound := range map[string]*time.Time{"not_before": &w.NotBefore, "not_after": &w.NotAfter} {
				if v, present := entry[name]; present && v != nil {
					at, ok := parseInstant(v)
					if !ok {
						return t, fmt.Errorf("%w: key validity window is not RFC 3339: %v", ErrInvalid, entry)
					}
					*bound = at
				}
			}
			t.KeyValidity[key] = w
		}
	}
	return t, nil
}

// validAt is PASS when key has no window or at falls in it, FAIL when at
// falls outside, and INCONCLUSIVE when the key has a window and at is not
// a time (§7.1).
func (t TrustPolicy) validAt(key string, at any) string {
	w, ok := t.KeyValidity[key]
	if !ok {
		return StatusPass
	}
	moment, ok := parseInstant(at)
	if !ok {
		return StatusInconclusive
	}
	if !w.NotBefore.IsZero() && moment.Before(w.NotBefore) {
		return StatusFail
	}
	if !w.NotAfter.IsZero() && moment.After(w.NotAfter) {
		return StatusFail
	}
	return StatusPass
}

func (t TrustPolicy) accepts(listed bool, key string, at any) string {
	if !listed {
		return StatusFail
	}
	return t.validAt(key, at)
}

// AcceptsResponder is responder_trust for a key, as of at (§7.2).
func (t TrustPolicy) AcceptsResponder(key any, at any) string {
	s, ok := key.(string)
	return t.accepts(ok && slices.Contains(t.ResponderKeys, s), s, at)
}

func (t TrustPolicy) acceptsLogKey(iss, sub any, kid string, at any) string {
	i, ok1 := iss.(string)
	s, ok2 := sub.(string)
	return t.accepts(ok1 && ok2 && slices.Contains(t.LogKeys, LogKey{Iss: i, Sub: s, Kid: kid}), kid, at)
}

func (t TrustPolicy) acceptsForeignKey(key any, at any) string {
	s, ok := key.(string)
	return t.accepts(ok && slices.Contains(t.ForeignKeys, s), s, at)
}

// KeyStatusResolver answers the as-of-now status of a key
// (responder_key_current, §7.2) with a §7.1 status and a method. It is
// called only when the verification policy is online; the verifier never
// performs that lookup itself.
type KeyStatusResolver func(key, evaluationTime string) (status, method string)

// VerificationPolicy is what the verifier implements and whether it may
// go online (§3.3, §6.2). Its shape is the verification_policy pin of the
// conformance vectors.
type VerificationPolicy struct {
	Online              bool
	ProfilesImplemented []string
	KindsImplemented    []string
	KeyStatus           KeyStatusResolver
}

// VerificationPolicyFromPin reads the verification_policy pin; absent lists
// default to both profile identifiers and the three CLL kinds.
func VerificationPolicyFromPin(pin map[string]any) VerificationPolicy {
	v := VerificationPolicy{ProfilesImplemented: slices.Clone(Profiles), KindsImplemented: slices.Clone(CLLKinds)}
	v.Online, _ = pin["online"].(bool)
	for name, list := range map[string]*[]string{"profiles_implemented": &v.ProfilesImplemented, "kinds_implemented": &v.KindsImplemented} {
		raw, present := pin[name].([]any)
		if !present {
			continue
		}
		*list = nil
		for _, item := range raw {
			if s, ok := item.(string); ok {
				*list = append(*list, s)
			}
		}
	}
	return v
}
