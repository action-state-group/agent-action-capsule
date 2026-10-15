// SPDX-License-Identifier: BSD-3-Clause

// Command evidencerequest_interlock is the Go stdin/stdout adapter for
// scripts/evidence-request-interlock.sh. Each command reads one JSON
// document and writes one compact, key-sorted JSON document, so its output
// compares byte for byte with the Python and Rust adapters.
//
//	classify: [{id, binding, request_hex}] -> [{id, reason, request_digest, well_formed}]
//	refuse:   {seed_hex, issued_at, cases: [{id, request_hex, reason}]} -> [{id, refusal}]
//	verify:   {public_key_hex, items: [{id, request_digest, refusal}]} -> [{id, reason}]
//	envelope: {seed_hex, issued_at, cases: [{id, binding, request_hex, subject, anchor_digest,
//	          artifact_hex, derivation?, freshness?, verification: [{kind, hex}]}]} -> [{id, reply_hex}]
//	check-envelope: [{id, binding, reply_hex}] -> [{id}]
//	check-cll: [{id, kind: "inclusion", peaks_hex, entry_hex, proof_hex} |
//	          {id, kind: "consistency", old_peaks_hex, peaks_hex, proof_hex}] -> [{id, verified}]
//
// verify and check-envelope exit 1, listing each failure on stderr, if any
// refusal does not authenticate or any envelope does not verify. check-cll
// never fails on a proof: it reports whether each one verifies.
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
		fmt.Fprintln(os.Stderr, "usage: evidencerequest_interlock classify|refuse|verify|envelope|check-envelope|check-cll")
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
	case "envelope":
		var doc envelopeDoc
		if err = json.NewDecoder(os.Stdin).Decode(&doc); err == nil {
			out, err = envelopes(doc)
		}
	case "check-envelope":
		var replies []struct {
			ID       string `json:"id"`
			Binding  string `json:"binding"`
			ReplyHex string `json:"reply_hex"`
		}
		if err = json.NewDecoder(os.Stdin).Decode(&replies); err == nil {
			checked := []map[string]any{}
			var failures []string
			for _, r := range replies {
				if e := checkEnvelope(r.Binding, r.ReplyHex); e != nil {
					failures = append(failures, r.ID+": "+e.Error())
					continue
				}
				checked = append(checked, map[string]any{"id": r.ID})
			}
			if len(failures) > 0 {
				err = errors.New(strings.Join(failures, "\n"))
			}
			out = checked
		}
	case "check-cll":
		var proofs []cllProof
		if err = json.NewDecoder(os.Stdin).Decode(&proofs); err == nil {
			out, err = checkCLL(proofs)
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

type envelopeDoc struct {
	SeedHex  string `json:"seed_hex"`
	IssuedAt string `json:"issued_at"`
	Cases    []struct {
		ID           string          `json:"id"`
		Binding      string          `json:"binding"`
		RequestHex   string          `json:"request_hex"`
		Subject      json.RawMessage `json:"subject"`
		AnchorDigest string          `json:"anchor_digest"`
		ArtifactHex  string          `json:"artifact_hex"`
		Derivation   string          `json:"derivation"`
		Freshness    json.RawMessage `json:"freshness"`
		Verification []struct {
			Kind string `json:"kind"`
			Hex  string `json:"hex"`
		} `json:"verification"`
	} `json:"cases"`
}

func mediaType(binding string) (string, error) {
	switch binding {
	case "json":
		return evidencerequest.MediaTypeJSON, nil
	case "cbor":
		return evidencerequest.MediaTypeCBOR, nil
	}
	return "", fmt.Errorf("unknown binding %q", binding)
}

// envelopes builds and signs the profile envelope (interop profile §6.2) for
// each case and returns the reply octets.
func envelopes(doc envelopeDoc) ([]map[string]any, error) {
	seed, err := hex.DecodeString(doc.SeedHex)
	if err != nil || len(seed) != ed25519.SeedSize {
		return nil, errors.New("seed_hex must be 32 bytes of hex")
	}
	key := ed25519.NewKeyFromSeed(seed)
	signer := seedSigner{key}
	out := make([]map[string]any, 0, len(doc.Cases))
	for _, c := range doc.Cases {
		media, err := mediaType(c.Binding)
		if err != nil {
			return nil, err
		}
		request, err1 := hex.DecodeString(c.RequestHex)
		artifact, err2 := hex.DecodeString(c.ArtifactHex)
		model, err3 := evidencerequest.DecodeJSON(c.Subject)
		if err := errors.Join(err1, err2, err3); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		subject, ok := evidencerequest.ParseSubject(model)
		if !ok {
			return nil, fmt.Errorf("%s: subject is not a request draft subject", c.ID)
		}
		anchor := evidencerequest.Anchor{Digest: c.AnchorDigest}
		if len(c.Freshness) > 0 {
			var size uint64
			var when string
			switch {
			case json.Unmarshal(c.Freshness, &size) == nil:
				anchor.FreshnessSize = &size
			case json.Unmarshal(c.Freshness, &when) == nil:
				anchor.FreshnessTime = when
			default:
				return nil, fmt.Errorf("%s: freshness is neither a size nor a time", c.ID)
			}
		}
		envelope := evidencerequest.Envelope{
			Profile:        evidencerequest.ProfileID,
			RequestDigest:  evidencerequest.Digest(request),
			Subject:        subject,
			Derivation:     c.Derivation,
			Anchor:         anchor,
			ArtifactDigest: evidencerequest.Digest(artifact),
			Responder:      hex.EncodeToString(key.Public().(ed25519.PublicKey)),
			IssuedAt:       doc.IssuedAt,
			Artifact:       artifact,
		}
		for _, v := range c.Verification {
			octets, err := hex.DecodeString(v.Hex)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", c.ID, err)
			}
			envelope.Verification = append(envelope.Verification, evidencerequest.VerificationEntry{Kind: v.Kind, Digest: evidencerequest.Digest(octets)})
			envelope.VerificationContent = append(envelope.VerificationContent, octets)
		}
		if envelope, err = envelope.Sign(context.Background(), signer); err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		reply, err := evidencerequest.EncodeReply(media, &envelope, nil)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", c.ID, err)
		}
		out = append(out, map[string]any{"id": c.ID, "reply_hex": hex.EncodeToString(reply.Message.Octets)})
	}
	return out, nil
}

// checkEnvelope parses reply octets as an envelope and verifies it offline:
// the signature under its responder key, the artifact and every item of
// verification material against their signed digests.
func checkEnvelope(binding, replyHex string) error {
	media, err := mediaType(binding)
	if err != nil {
		return err
	}
	octets, err := hex.DecodeString(replyHex)
	if err != nil {
		return err
	}
	reply, err := evidencerequest.ParseReply(evidencerequest.Message{Octets: octets, MediaType: media})
	if err != nil {
		return err
	}
	if reply.Envelope == nil {
		return errors.New("the reply is not an envelope")
	}
	return reply.Envelope.Verify()
}

type cllProof struct {
	ID          string   `json:"id"`
	Kind        string   `json:"kind"`
	OldPeaksHex []string `json:"old_peaks_hex"`
	PeaksHex    []string `json:"peaks_hex"`
	EntryHex    string   `json:"entry_hex"`
	ProofHex    string   `json:"proof_hex"`
}

func hexList(items []string) ([][]byte, error) {
	out := make([][]byte, len(items))
	for i, item := range items {
		b, err := hex.DecodeString(item)
		if err != nil {
			return nil, err
		}
		out[i] = b
	}
	return out, nil
}

// checkCLL reports whether each item of Checkpointed Local Log material
// verifies against the peaks it is given (interop profile §6.2.1 steps 12
// and 13).
func checkCLL(proofs []cllProof) ([]map[string]any, error) {
	out := make([]map[string]any, 0, len(proofs))
	for _, p := range proofs {
		peaks, err1 := hexList(p.PeaksHex)
		oldPeaks, err2 := hexList(p.OldPeaksHex)
		entry, err3 := hex.DecodeString(p.EntryHex)
		proof, err4 := hex.DecodeString(p.ProofHex)
		if err := errors.Join(err1, err2, err3, err4); err != nil {
			return nil, fmt.Errorf("%s: %w", p.ID, err)
		}
		var verr error
		switch p.Kind {
		case "inclusion":
			verr = evidencerequest.VerifyCLLInclusion(peaks, entry, proof)
		case "consistency":
			verr = evidencerequest.VerifyCLLConsistency(oldPeaks, peaks, proof)
		default:
			return nil, fmt.Errorf("%s: unknown kind %q", p.ID, p.Kind)
		}
		out = append(out, map[string]any{"id": p.ID, "verified": verr == nil})
	}
	return out, nil
}
