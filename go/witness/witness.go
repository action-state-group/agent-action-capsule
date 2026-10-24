// SPDX-License-Identifier: BSD-3-Clause
// Package witness checks, offline, the witness receipts an Evidence Bundle's
// checkpoint carries. It is the Go port of the Python reference
// agent_action_capsule.witness and follows vectors/bundle/strict/README.md.
//
// A witness is a transparency service that took a log's signed checkpoint and
// returned a receipt a verifier can check offline. checkpoint.witnesses in an
// Evidence Bundle lists them as CLL WitnessRecord objects (ts_url,
// entry_hash, receipt_b64, leaf_index, tree_size, optional is_stub). The
// Bundle draft defines no witness member, so this check is an opt-in verifier
// extension (bundle.VerifyStrict): only a receipt that fails changes the
// verdict.
//
// No witness is trusted by default. The caller supplies a witness Directory
// (a witnesses.json: {"witnesses": [row, ...]}, or the row list). A receipt
// whose witness has no row, or whose row has no usable key, is not checked
// (withheld), never failed.
//
// Three bindings, named by the ts_url scheme:
//
//   - https://host (cll): a COSE Receipt (RFC 9162 inclusion) whose leaf is
//     entry_hash, which must equal SHA-256 of the checkpoint digest.
//   - rekor+https://host (rekor): a Sigstore Rekor dsse entry under the row's
//     ECDSA P-256 key, logging the checkpoint's COSE statement under the
//     checkpoint's own key.
//   - scrapi+https://host (scrapi): a SCITT COSE Receipt (RFC 9162) whose leaf
//     is SHA-256 of the checkpoint's COSE statement.
package witness

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// Bindings a witness URL names.
const (
	BindingCLL    = "cll"
	BindingRekor  = "rekor"
	BindingSCRAPI = "scrapi"
)

// The two receipt grades a witness may sign into its receipt's protected
// header (private-use label -65537): existence and time only, and MMR
// consistency checked. "countersigned-observed" is the pre-rename spelling of
// GradeObservedOnly and is read as it.
const (
	GradeObservedOnly = "observed-only"
	GradeMMRVerified  = "mmr-verified"
)

var grades = map[string]string{
	GradeObservedOnly:        GradeObservedOnly,
	"countersigned-observed": GradeObservedOnly,
	GradeMMRVerified:         GradeMMRVerified,
}

// Statuses of a receipt and of the witnesses result.
const (
	StatusPass     = "pass"
	StatusWithheld = "withheld"
	StatusFail     = "fail"
)

var recordFields = []string{"ts_url", "entry_hash", "receipt_b64", "leaf_index", "tree_size"}

// textFields are the WitnessRecord members that must be non-empty strings.
var textFields = []string{"ts_url", "entry_hash", "receipt_b64"}

// ReceiptResult is one receipt's outcome. Status is pass, withheld or fail.
// Reason is a human-readable explanation and is not part of the
// cross-language contract. Grade is the verified receipt grade, or nil.
type ReceiptResult struct {
	TSURL   string  `json:"ts_url"`
	Binding string  `json:"binding"`
	Status  string  `json:"status"`
	Reason  string  `json:"reason"`
	Grade   *string `json:"grade"`
}

// BindingOf returns the binding a witness URL names: rekor+... is rekor,
// scrapi+... is scrapi, and anything else is cll.
func BindingOf(url string) string {
	scheme, _, found := strings.Cut(url, "://")
	if !found {
		return BindingCLL
	}
	scheme = strings.ToLower(scheme)
	switch {
	case strings.HasPrefix(scheme, BindingRekor+"+"):
		return BindingRekor
	case strings.HasPrefix(scheme, BindingSCRAPI+"+"):
		return BindingSCRAPI
	}
	return BindingCLL
}

// EndpointOf returns the base URL with any binding prefix removed and no
// trailing slash.
func EndpointOf(url string) string {
	if BindingOf(url) != BindingCLL {
		_, url, _ = strings.Cut(url, "+")
	}
	return strings.TrimRight(url, "/")
}

// Directory is a parsed witness directory: its rows, each kept as the JSON
// object it was read from, so every member is read exactly as the Python
// reference reads it.
type Directory struct {
	rows []interface{}
}

// ParseDirectory reads a witness directory file: {"witnesses": [rows]} or a
// bare array of rows. Numbers are kept as json.Number.
func ParseDirectory(data []byte) (Directory, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return Directory{}, fmt.Errorf("witness directory is not JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		return Directory{}, errors.New("witness directory has trailing data")
	}
	switch value.(type) {
	case map[string]interface{}, []interface{}:
		return DirectoryFromValue(value), nil
	}
	return Directory{}, errors.New("witness directory must be an object or an array")
}

// DirectoryFromValue reads an already-decoded directory: an object whose
// witnesses member is the row list, or the row list itself. Anything else is
// an empty directory, which trusts no witness.
func DirectoryFromValue(value interface{}) Directory {
	switch value := value.(type) {
	case map[string]interface{}:
		rows, _ := value["witnesses"].([]interface{})
		return Directory{rows: rows}
	case []interface{}:
		return Directory{rows: value}
	}
	return Directory{}
}

// Row is one witness directory row.
type Row struct {
	// Name, Endpoint and Binding are the row's members when they are strings;
	// Binding is cll when the member is absent.
	Name, Endpoint, Binding string
	raw                     map[string]interface{}
}

// RowFor returns the directory row a receipt's witness URL belongs to: the
// same binding (a row without binding is cll) and the same endpoint, trailing
// slash ignored. ok is false when no row matches.
func (d Directory) RowFor(tsURL string) (Row, bool) {
	binding, endpoint := BindingOf(tsURL), EndpointOf(tsURL)
	for _, raw := range d.rows {
		row, isObject := raw.(map[string]interface{})
		if !isObject {
			continue
		}
		rowBinding := interface{}(BindingCLL)
		if value, present := row["binding"]; present {
			rowBinding = value
		}
		rowEndpoint := interface{}("")
		if value, present := row["endpoint"]; present {
			rowEndpoint = value
		}
		text, isString := rowEndpoint.(string)
		if rowBinding == binding && isString && strings.TrimRight(text, "/") == endpoint {
			name, _ := row["name"].(string)
			return Row{Name: name, Endpoint: text, Binding: binding, raw: row}, true
		}
	}
	return Row{}, false
}

// RowFor is Directory.RowFor.
func RowFor(directory Directory, tsURL string) (Row, bool) {
	return directory.RowFor(tsURL)
}

// Keys returns every key the row lists, in key_ids order: the public_keys
// entry the key id names, by the SHA-256 of its DER or, for an Ed25519 key,
// by its raw key in hex; otherwise the key id read as a raw Ed25519 key, even
// one that is not a valid curve point (nothing verifies under it). A
// public_keys entry counts only when it is canonical standard base64 of a DER
// SubjectPublicKeyInfo holding an Ed25519 or ECDSA P-256 key; any other is
// skipped. The row is unusable (an error) when
// key_ids or public_keys is present but not a list, when a key id is not 64
// lowercase hex characters, or, in a rekor row, where a key id is an RFC 6962
// log ID, when one names no public_keys entry. Keys are ed25519.PublicKey or
// *ecdsa.PublicKey (P-256).
func (r Row) Keys() ([]crypto.PublicKey, error) {
	entries, entriesOK := listMember(r.raw, "public_keys")
	ids, idsOK := listMember(r.raw, "key_ids")
	if !entriesOK || !idsOK {
		return nil, fmt.Errorf("row %q: key_ids and public_keys must be lists", r.Name)
	}
	byID := map[string]crypto.PublicKey{}
	for _, entry := range entries {
		text, isString := entry.(string)
		if !isString {
			continue
		}
		der, err := decodeStdBase64(text)
		if err != nil {
			continue
		}
		key, err := parsePublicKey(der)
		if err != nil {
			continue
		}
		sum := sha256.Sum256(der)
		byID[hex.EncodeToString(sum[:])] = key
		if raw, isEd25519 := key.(ed25519.PublicKey); isEd25519 {
			byID[hex.EncodeToString(raw)] = key
		}
	}
	keys := make([]crypto.PublicKey, 0, len(ids))
	for _, rawID := range ids {
		id, isString := rawID.(string)
		if !isString || !hex64.MatchString(id) {
			return nil, fmt.Errorf("row %q: a key id is not 64 lowercase hex characters", r.Name)
		}
		if key, listed := byID[id]; listed {
			keys = append(keys, key)
			continue
		}
		if r.raw["binding"] == BindingRekor {
			return nil, fmt.Errorf("rekor row %q: no public key for log ID %.16s...", r.Name, id)
		}
		raw, _ := hex.DecodeString(id)
		keys = append(keys, ed25519.PublicKey(raw))
	}
	return keys, nil
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// errNotADirectoryKey is a public_keys entry that does not count.
var errNotADirectoryKey = errors.New("not an Ed25519 or ECDSA P-256 public key")

// parsePublicKey reads a directory public_keys entry, a DER
// SubjectPublicKeyInfo. Only an Ed25519 key or an ECDSA P-256 key counts
// (x509 has already checked the point is on the curve); every other key,
// such as RSA, X25519, P-384, secp256k1 or an unknown algorithm, is
// errNotADirectoryKey.
func parsePublicKey(der []byte) (crypto.PublicKey, error) {
	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, errNotADirectoryKey
	}
	switch key := key.(type) {
	case ed25519.PublicKey:
		return key, nil
	case *ecdsa.PublicKey:
		if key.Curve == elliptic.P256() {
			return key, nil
		}
	}
	return nil, errNotADirectoryKey
}

// listMember reads a row's list member: absent is no entries, a list is its
// entries, and anything else (null included) is not a list.
func listMember(row map[string]interface{}, name string) ([]interface{}, bool) {
	value, present := row[name]
	if !present {
		return nil, true
	}
	list, isList := value.([]interface{})
	return list, isList
}

// strictStdBase64 is standard base64 with padding and nothing else; the
// regular expression rules out the line breaks base64.StdEncoding skips.
var strictStdBase64 = regexp.MustCompile(`^[A-Za-z0-9+/]*={0,2}$`)

// decodeStdBase64 reads standard base64 with padding in its one canonical
// spelling: the bytes must re-encode to text, so non-zero trailing bits are
// refused.
func decodeStdBase64(text string) ([]byte, error) {
	if !strictStdBase64.MatchString(text) {
		return nil, errors.New("not strict standard base64")
	}
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, err
	}
	if base64.StdEncoding.EncodeToString(raw) != text {
		return nil, errors.New("non-canonical base64")
	}
	return raw, nil
}

func isRecord(entry interface{}) (map[string]interface{}, bool) {
	record, isObject := entry.(map[string]interface{})
	if !isObject {
		return nil, false
	}
	for _, name := range recordFields {
		if _, present := record[name]; !present {
			return nil, false
		}
	}
	// ts_url, entry_hash and receipt_b64 are non-empty strings, and
	// receipt_b64 is canonical standard base64: an entry that is not a receipt
	// is malformed, never merely not checked.
	for _, name := range textFields {
		if text, isString := record[name].(string); !isString || text == "" {
			return nil, false
		}
	}
	if _, err := decodeStdBase64(record["receipt_b64"].(string)); err != nil {
		return nil, false
	}
	return record, true
}

// VerifyReceipts checks every receipt in receipts (a Bundle's
// checkpoint.witnesses) against the signed checkpoint (nil when it did not
// verify) and its COSE bytes, under the keys of directory. The zero Directory
// trusts no witness.
//
// status is fail when an entry is malformed or a receipt does not verify,
// else pass when one verifies, else withheld. Malformed entries' findings
// come first, then one finding per receipt that did not pass.
func VerifyReceipts(receipts interface{}, signed *SignedCheckpoint, checkpointCOSE []byte, directory Directory) (string, []string, []ReceiptResult) {
	entries, isList := receipts.([]interface{})
	if !isList || len(entries) == 0 {
		return StatusWithheld, []string{"witness_receipt_absent"}, nil
	}
	if signed == nil || checkpointCOSE == nil {
		return StatusWithheld, []string{"checkpoint_unverified"}, nil
	}
	var findings []string
	for index, entry := range entries {
		if _, ok := isRecord(entry); !ok {
			findings = append(findings, fmt.Sprintf("witness_receipt_malformed:%d", index))
		}
	}
	malformed := len(findings) != 0
	results := make([]ReceiptResult, 0, len(entries))
	sawPass, sawFail := false, false
	for _, entry := range entries {
		record, ok := isRecord(entry)
		if !ok {
			continue
		}
		result := checkRecord(*signed, record, checkpointCOSE, directory)
		switch result.Status {
		case StatusPass:
			sawPass = true
		case StatusWithheld:
			findings = append(findings, "witness_unverified:"+result.TSURL)
		default:
			sawFail = true
			findings = append(findings, "witness_receipt_invalid:"+result.TSURL)
		}
		results = append(results, result)
	}
	switch {
	case malformed || sawFail:
		return StatusFail, findings, results
	case sawPass:
		return StatusPass, findings, results
	}
	return StatusWithheld, findings, results
}

// checkRecord is one well-formed WitnessRecord: withheld when it is a stub,
// has no directory row, or its row has no usable key; pass under the first
// key it verifies under; fail otherwise.
func checkRecord(signed SignedCheckpoint, record map[string]interface{}, checkpointCOSE []byte, directory Directory) ReceiptResult {
	tsURL := record["ts_url"].(string)
	result := ReceiptResult{TSURL: tsURL, Binding: BindingOf(tsURL), Status: StatusWithheld}
	if stub, _ := record["is_stub"].(bool); stub {
		result.Reason = "stub receipt (never reached a witness)"
		return result
	}
	row, found := directory.RowFor(tsURL)
	if !found {
		result.Reason = "not checked: no directory row for this witness"
		return result
	}
	keys, err := row.Keys()
	if err != nil {
		result.Reason = fmt.Sprintf("not checked: unusable key in directory row (%v)", err)
		return result
	}
	if len(keys) == 0 {
		result.Reason = "not checked: no key in the directory row for this witness"
		return result
	}
	for _, key := range keys {
		ok, reason, grade := VerifyReceipt(signed, record, key, checkpointCOSE)
		result.Reason = reason
		if ok {
			result.Status, result.Grade = StatusPass, grade
			return result
		}
	}
	result.Status = StatusFail
	return result
}

// VerifyReceipt checks one receipt (a WitnessRecord object) under one key,
// for the checkpoint whose signed fields are signed and whose COSE statement
// is checkpointCOSE. The binding comes from record's ts_url. It returns
// whether it verified, a reason, and the receipt grade when it verified.
// It never panics on a malformed receipt.
func VerifyReceipt(signed SignedCheckpoint, record map[string]interface{}, key crypto.PublicKey, checkpointCOSE []byte) (bool, string, *string) {
	tsURL, _ := record["ts_url"].(string)
	switch BindingOf(tsURL) {
	case BindingCLL:
		return verifyCLL(signed, record, key)
	case BindingRekor:
		encoded, isString := record["receipt_b64"].(string)
		if !isString {
			return false, "unreadable receipt: receipt_b64 is not a string", nil
		}
		raw, err := decodeStdBase64(encoded)
		if err != nil {
			return false, "unreadable receipt: " + err.Error(), nil
		}
		entry, err := decodeJSON(raw)
		if err != nil {
			return false, "unreadable receipt: " + err.Error(), nil
		}
		if err := VerifyRekorEntry(entry, checkpointCOSE, signed.KeyID, key); err != nil {
			return false, err.Error(), nil
		}
		grade := GradeObservedOnly
		return true, "ok", &grade
	}
	encoded, isString := record["receipt_b64"].(string)
	if !isString {
		return false, "unreadable receipt: receipt_b64 is not a string", nil
	}
	raw, err := decodeStdBase64(encoded)
	if err != nil {
		return false, "unreadable receipt: " + err.Error(), nil
	}
	leaf := sha256.Sum256(checkpointCOSE)
	checked, err := VerifyCOSEReceipt(raw, leaf[:], key)
	if err != nil {
		return false, "receipt does not verify for this checkpoint under the pinned key: " + err.Error(), nil
	}
	// A SCRAPI receipt with no grade label, or an unknown one, is observed-only.
	grade := GradeObservedOnly
	if checked.Grade != nil {
		grade = *checked.Grade
	}
	return true, "ok", &grade
}

// verifyCLL is a CLL witness stamp under one key: bound to this checkpoint
// (entry_hash), then the COSE Receipt verifies over that leaf.
func verifyCLL(signed SignedCheckpoint, record map[string]interface{}, key crypto.PublicKey) (bool, string, *string) {
	digest := CheckpointDigest(signed)
	expected := sha256.Sum256(digest[:])
	entryHash, _ := record["entry_hash"].(string)
	if entryHash != hex.EncodeToString(expected[:]) {
		return false, "witness.entry_hash does not match this checkpoint's digest -- stamp is not bound to this checkpoint", nil
	}
	encoded, isString := record["receipt_b64"].(string)
	if !isString {
		return false, "receipt_b64 is not a string", nil
	}
	raw, err := decodeStdBase64(encoded)
	if err != nil {
		return false, "receipt_b64 is not valid base64: " + err.Error(), nil
	}
	checked, err := VerifyCOSEReceipt(raw, expected[:], key)
	if err != nil {
		return false, err.Error(), nil
	}
	if checked.Grade == nil {
		return true, "ok (receipt carries no grade label)", nil
	}
	return true, "ok", checked.Grade
}

// decodeJSON reads one JSON value with json.Number numbers and no trailing
// data.
func decodeJSON(data []byte) (interface{}, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing data after JSON value")
	}
	return value, nil
}
