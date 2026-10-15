// SPDX-License-Identifier: BSD-3-Clause

// Command evidencerequest_interlock is the Go stdin/stdout adapter for
// scripts/evidence-request-interlock.sh. Each command reads one JSON
// document and writes one compact, key-sorted JSON document, so its output
// compares byte for byte with the Python and Rust adapters.
//
//	classify: [{id, binding, request_hex}] -> [{id, reason, request_digest, well_formed}]
//	refuse:   {seed_hex, issued_at, cases: [{id, request_hex, reason}]} -> [{id, refusal}]
//	verify:   {public_key_hex, items: [{id, request_digest, refusal}]} -> [{id, reason}]
//
// verify exits 1, listing each failure on stderr, if any refusal does not
// authenticate.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/evidencerequest"
)

type seedSigner struct{ key ed25519.PrivateKey }

func (s seedSigner) Sign(_ context.Context, message []byte) ([]byte, error) {
	return ed25519.Sign(s.key, message), nil
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: evidencerequest_interlock classify|refuse|verify")
		os.Exit(2)
	}
	var out any
	var err error
	switch os.Args[1] {
	case "classify":
		var cases []struct {
			ID         string `json:"id"`
			Binding    string `json:"binding"`
			RequestHex string `json:"request_hex"`
		}
		if err = json.NewDecoder(os.Stdin).Decode(&cases); err == nil {
			out, err = classify(cases)
		}
	case "refuse":
		var doc struct {
			SeedHex  string `json:"seed_hex"`
			IssuedAt string `json:"issued_at"`
			Cases    []struct {
				ID         string `json:"id"`
				RequestHex string `json:"request_hex"`
				Reason     string `json:"reason"`
			} `json:"cases"`
		}
		if err = json.NewDecoder(os.Stdin).Decode(&doc); err == nil {
			out, err = refuse(doc.SeedHex, doc.IssuedAt, doc.Cases)
		}
	case "verify":
		var doc struct {
			PublicKeyHex string `json:"public_key_hex"`
			Items        []struct {
				ID            string          `json:"id"`
				RequestDigest string          `json:"request_digest"`
				Refusal       json.RawMessage `json:"refusal"`
			} `json:"items"`
		}
		if err = json.NewDecoder(os.Stdin).Decode(&doc); err == nil {
			var failures []string
			verified := []map[string]any{}
			for _, item := range doc.Items {
				reason, e := verifyDraft(item.Refusal, doc.PublicKeyHex, item.RequestDigest)
				if e != nil {
					failures = append(failures, item.ID+": "+e.Error())
					continue
				}
				verified = append(verified, map[string]any{"id": item.ID, "reason": reason})
			}
			if len(failures) > 0 {
				err = errors.New(strings.Join(failures, "\n"))
			}
			out = verified
		}
	default:
		err = fmt.Errorf("unknown command %q", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(out); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// verifyDraft authenticates a refusal under the request draft's rule, the one
// the Python and Rust adapters apply: the raw object conforms (CheckRefusal:
// signature, registered reason, digest, any RFC 3339 UTC issued_at), names
// the responder's key and the request's digest. Refusal.VerifyFor is not
// used: it also requires the interop profile's seconds-only issued_at.
func verifyDraft(raw json.RawMessage, responderKey, requestDigest string) (string, error) {
	check := evidencerequest.CheckRefusal(evidencerequest.Message{Octets: raw, MediaType: evidencerequest.MediaTypeJSON})
	if !check.Conformant {
		return "", errors.New("not a conforming refusal")
	}
	var fields map[string]any
	if err := json.Unmarshal(raw, &fields); err != nil {
		return "", err
	}
	if fields["key_id"] != responderKey {
		return "", errors.New("not signed by the responder key")
	}
	if fields["request_digest"] != requestDigest {
		return "", errors.New("names a different request digest")
	}
	reason, _ := fields["reason"].(string)
	return reason, nil
}

func classify(cases []struct {
	ID         string `json:"id"`
	Binding    string `json:"binding"`
	RequestHex string `json:"request_hex"`
}) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(cases))
	for _, c := range cases {
		octets, err := hex.DecodeString(c.RequestHex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		media := map[string]string{"json": evidencerequest.MediaTypeJSON, "cbor": evidencerequest.MediaTypeCBOR}[c.Binding]
		if media == "" {
			return nil, fmt.Errorf("%s: unknown binding %q", c.ID, c.Binding)
		}
		check := evidencerequest.ParseRequest(evidencerequest.Message{Octets: octets, MediaType: media})
		var reason any
		if check.Reason != "" {
			reason = check.Reason
		}
		out = append(out, map[string]any{
			"id":             c.ID,
			"request_digest": evidencerequest.Digest(octets),
			"well_formed":    check.Reason == "",
			"reason":         reason,
		})
	}
	return out, nil
}

func refuse(seedHex, issuedAt string, cases []struct {
	ID         string `json:"id"`
	RequestHex string `json:"request_hex"`
	Reason     string `json:"reason"`
}) ([]map[string]any, error) {
	seed, err := hex.DecodeString(seedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed_hex must be 32 bytes of hex")
	}
	key := ed25519.NewKeyFromSeed(seed)
	signer := seedSigner{key}
	keyID := hex.EncodeToString(key.Public().(ed25519.PublicKey))
	out := make([]map[string]any, 0, len(cases))
	for _, c := range cases {
		octets, err := hex.DecodeString(c.RequestHex)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		refusal, err := evidencerequest.Refusal{
			RequestDigest: evidencerequest.Digest(octets),
			Reason:        c.Reason,
			IssuedAt:      issuedAt,
			KeyID:         keyID,
		}.Sign(context.Background(), signer)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		if !refusal.Conforming() {
			return nil, fmt.Errorf("%s: refusal does not conform", c.ID)
		}
		out = append(out, map[string]any{"id": c.ID, "refusal": refusal.Value()})
	}
	return out, nil
}
