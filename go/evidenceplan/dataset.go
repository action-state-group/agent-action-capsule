// SPDX-License-Identifier: BSD-3-Clause

// Package evidenceplan is the Go gate for a dataset plan and its dataset
// (spec/evidence-plan-ir-v0.md sections 5.1 and 6.2). Run selects a dataset
// plan's rows from a book's committed record headers, and CheckDataset
// refuses a dataset that is not that selection. The Python reference is
// schemas/evidence_dataset.py; both run vectors/evidence-dataset/ and refuse
// each negative with the same Reason.
package evidenceplan

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"strings"
	"sync"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
	"github.com/action-state-group/agent-action-capsule/go/internal/ecmaregexp"
	"github.com/action-state-group/agent-action-capsule/go/internal/rfc3339"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

// The schema is schemas/evidence-plan-ir-v0.json of this repository, copied
// because go:embed cannot reach outside the module; TestSchemaIsTheRepositorys
// holds the copy byte-equal to it.
//
//go:embed evidence-plan-ir-v0.json
var schemaBytes []byte

const (
	// SchemaID is the schema's $id.
	SchemaID = "https://agentactioncapsule.org/schemas/evidence-plan-ir-v0.json"
	// DatasetVersion is a dataset document's dataset_version.
	DatasetVersion = "evidence-dataset-v0"

	OperatorPopulation = "traditional.population"
	OperatorWindow     = "traditional.window"
	OperatorFilter     = "traditional.filter"
)

// Reason names why a plan, dataset or record set was refused. The values are
// the Python reference's REASONS.
type Reason string

const (
	PlanInvalid     Reason = "plan-invalid"
	PlanShape       Reason = "plan-shape"
	DatasetInvalid  Reason = "dataset-invalid"
	PlanRefMismatch Reason = "plan-ref-mismatch"
	RecordsInvalid  Reason = "records-invalid"
	FieldMissing    Reason = "field-missing"
	FieldType       Reason = "field-type"
	RowsMismatch    Reason = "rows-mismatch"
)

// Error is a refusal.
type Error struct {
	Reason  Reason
	Message string
}

func (e *Error) Error() string { return string(e.Reason) + ": " + e.Message }

func refuse(reason Reason, format string, args ...interface{}) *Error {
	return &Error{Reason: reason, Message: fmt.Sprintf(format, args...)}
}

// Row is one dataset row: a committed record by the digest of its header.
type Row struct {
	Seq        uint64
	RecordType string
	Digest     string
}

// JSON is the row as a dataset document carries it.
func (r Row) JSON() map[string]interface{} {
	return map[string]interface{}{
		"seq":         json.Number(fmt.Sprint(r.Seq)),
		"record_type": r.RecordType,
		"digest_alg":  "SHA-256",
		"digest":      r.Digest,
	}
}

var compiled struct {
	sync.Once
	plan, dataset *jsonschema.Schema
	err           error
}

func schemas() (plan, dataset *jsonschema.Schema, err error) {
	compiled.Do(func() {
		doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
		if err != nil {
			compiled.err = err
			return
		}
		compiler := jsonschema.NewCompiler()
		compiler.UseRegexpEngine(ecmaregexp.Compile)
		if err = compiler.AddResource(SchemaID, doc); err != nil {
			compiled.err = err
			return
		}
		if compiled.plan, err = compiler.Compile(SchemaID + "#/$defs/EvidencePlan"); err != nil {
			compiled.err = err
			return
		}
		compiled.dataset, compiled.err = compiler.Compile(SchemaID + "#/$defs/Dataset")
	})
	return compiled.plan, compiled.dataset, compiled.err
}

// Decode reads one JSON text, its numbers kept as json.Number, refusing
// invalid UTF-8, unpaired surrogate escapes and trailing data.
func Decode(raw []byte) (interface{}, error) {
	if err := canonical.CheckJSONText(raw); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value interface{}
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing data after the JSON value")
	}
	return value, nil
}

func validate(schema *jsonschema.Schema, value interface{}, reason Reason) error {
	if err := schema.Validate(value); err != nil {
		var invalid *jsonschema.ValidationError
		if errors.As(err, &invalid) {
			return refuse(reason, "%s", invalid.Error())
		}
		return err
	}
	return nil
}

// digest is the JSON digest, or a refusal when the value has no canonical
// form (a float, or an integer outside +-(2^53 - 1)).
func digest(value interface{}, reason Reason, what string) (string, error) {
	d, err := canonical.JSONDigest(value)
	if err != nil {
		return "", refuse(reason, "%s has no canonical form: %v", what, err)
	}
	return d, nil
}

type node struct {
	id, operator string
	params       map[string]interface{}
}

// datasetNodes checks plan (as Decode returns it) is a dataset plan: the
// schema, then section 5.1's chain, ids, contract_ref and window days.
func datasetNodes(plan interface{}) ([]node, error) {
	planSchema, _, err := schemas()
	if err != nil {
		return nil, fmt.Errorf("compiling the Plan IR schema: %w", err)
	}
	if err := validate(planSchema, plan, PlanInvalid); err != nil {
		return nil, err
	}
	if _, err := digest(plan, PlanInvalid, "the plan"); err != nil {
		return nil, err
	}
	doc := plan.(map[string]interface{})
	header := doc["header"].(map[string]interface{})
	raw := doc["nodes"].([]interface{})
	nodes := make([]node, len(raw))
	seen := map[string]bool{}
	for i, item := range raw {
		object := item.(map[string]interface{})
		n := node{id: object["id"].(string), operator: object["operator"].(string)}
		n.params, _ = object["params"].(map[string]interface{})
		where := fmt.Sprintf("nodes[%d] (%s)", i, n.id)
		if seen[n.id] {
			return nil, refuse(PlanShape, "%s: node ids are unique within a plan", where)
		}
		seen[n.id] = true
		if object["contract_ref"] != header["contract_ref"] {
			return nil, refuse(PlanShape, "%s: contract_ref differs from the header's", where)
		}
		switch n.operator {
		case OperatorPopulation, OperatorWindow, OperatorFilter:
		default:
			return nil, refuse(PlanShape, "%s: %s is not a dataset operator", where, n.operator)
		}
		if (i == 0) != (n.operator == OperatorPopulation) {
			return nil, refuse(PlanShape, "%s: a dataset plan has one population node, first", where)
		}
		if i > 0 {
			reads := object["inputs"].([]interface{})[0].(map[string]interface{})["node_id"]
			if reads != nodes[i-1].id {
				return nil, refuse(PlanShape, "%s: reads %q, not the node before it", where, reads)
			}
		}
		if n.operator == OperatorWindow {
			from, okFrom := rfc3339.CalendarDate(n.params["from"].(string))
			to, okTo := rfc3339.CalendarDate(n.params["to"].(string))
			if !okFrom || !okTo {
				return nil, refuse(PlanInvalid, "%s: a window day does not exist", where)
			}
			if to < from {
				return nil, refuse(PlanInvalid, "%s: the window ends before it starts", where)
			}
		}
		nodes[i] = n
	}
	return nodes, nil
}

type record struct {
	seq        uint64
	recordType string
	header     map[string]interface{}
}

// seqOf reads a seq as Python's json module reads an int: no fraction and no
// exponent.
func seqOf(value interface{}) (uint64, bool) {
	n, ok := value.(json.Number)
	if !ok || canonical.IsFloat(n) {
		return 0, false
	}
	v, ok := new(big.Int).SetString(n.String(), 10)
	if !ok || v.Sign() < 0 || !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

func population(records interface{}, params map[string]interface{}) ([]record, error) {
	items, ok := records.([]interface{})
	if !ok {
		return nil, refuse(RecordsInvalid, "records are not a JSON array of objects")
	}
	book := params["book_id"].(string)
	through, _ := new(big.Rat).SetString(params["through_seq"].(json.Number).String())
	types := map[string]bool{}
	for _, t := range params["record_types"].([]interface{}) {
		types[t.(string)] = true
	}
	bySeq := map[uint64]record{}
	for i, item := range items {
		header, ok := item.(map[string]interface{})
		if !ok {
			return nil, refuse(RecordsInvalid, "records are not a JSON array of objects")
		}
		bookID, ok := header["book_id"].(string)
		if !ok {
			return nil, refuse(RecordsInvalid, "records[%d] has no string book_id", i)
		}
		if bookID != book {
			continue
		}
		seq, okSeq := seqOf(header["seq"])
		recordType, okType := header["record_type"].(string)
		if !okSeq || !okType {
			return nil, refuse(RecordsInvalid, "records[%d] has no non-negative integer seq and string record_type", i)
		}
		if _, dup := bySeq[seq]; dup {
			return nil, refuse(RecordsInvalid, "records[%d]: seq %d appears twice in book %q", i, seq, book)
		}
		bySeq[seq] = record{seq: seq, recordType: recordType, header: header}
	}
	seqs := make([]uint64, 0, len(bySeq))
	for seq := range bySeq {
		seqs = append(seqs, seq)
	}
	sort.Slice(seqs, func(i, j int) bool { return seqs[i] < seqs[j] })
	var out []record
	for _, seq := range seqs {
		r := bySeq[seq]
		if new(big.Rat).SetUint64(seq).Cmp(through) > 0 || !types[r.recordType] {
			continue
		}
		// Only a selected record is digested, so a record committed after
		// through_seq never changes the run.
		if _, err := digest(r.header, RecordsInvalid, fmt.Sprintf("record seq %d", seq)); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

func field(header map[string]interface{}, path string) (interface{}, bool) {
	var value interface{} = header
	for _, name := range strings.Split(path, ".") {
		object, ok := value.(map[string]interface{})
		if !ok {
			return nil, false
		}
		if value, ok = object[name]; !ok {
			return nil, false
		}
	}
	return value, true
}

func read(r record, path, where string) (interface{}, error) {
	value, ok := field(r.header, path)
	if !ok {
		return nil, refuse(FieldMissing, "%s: record seq %d has no %s", where, r.seq, path)
	}
	return value, nil
}

func inWindow(r record, params map[string]interface{}, where string) (bool, error) {
	path := params["field"].(string)
	value, err := read(r, path, where)
	if err != nil {
		return false, err
	}
	stamp, _ := value.(string)
	at, ok := rfc3339.UTCDate(stamp)
	if !ok {
		return false, refuse(FieldType, "%s: record seq %d %s is not an RFC 3339 date-time with an offset", where, r.seq, path)
	}
	from, _ := rfc3339.CalendarDate(params["from"].(string))
	to, _ := rfc3339.CalendarDate(params["to"].(string))
	return from <= at && at <= to, nil
}

func anySame(value interface{}, scalars interface{}) bool {
	for _, s := range scalars.([]interface{}) {
		if value == s {
			return true
		}
	}
	return false
}

func passes(r record, params map[string]interface{}, where string) (bool, error) {
	// Every predicate's field is read before any is applied, so a record
	// missing a later predicate's field is refused whatever the earlier ones
	// decide, and the order of where never changes the outcome.
	predicates := params["where"].([]interface{})
	values := make([]interface{}, len(predicates))
	for i, item := range predicates {
		path := item.(map[string]interface{})["field"].(string)
		value, err := read(r, path, where)
		if err != nil {
			return false, err
		}
		switch value.(type) {
		case string, bool:
		default:
			return false, refuse(FieldType, "%s: record seq %d %s is not a string or boolean", where, r.seq, path)
		}
		values[i] = value
	}
	for i, item := range predicates {
		predicate := item.(map[string]interface{})
		// Strings and booleans compare with their type, as == on
		// interface values does.
		var ok bool
		if want, has := predicate["equal"]; has {
			ok = values[i] == want
		} else if list, has := predicate["one_of"]; has {
			ok = anySame(values[i], list)
		} else {
			ok = !anySame(values[i], predicate["not_one_of"])
		}
		if !ok {
			return false, nil
		}
	}
	return true, nil
}

// Run selects a dataset plan's rows from records, a book's committed record
// headers as a bundle discloses them (each as Decode returns it). The rows
// are in log order.
func Run(plan interface{}, records interface{}) ([]Row, error) {
	nodes, err := datasetNodes(plan)
	if err != nil {
		return nil, err
	}
	selected, err := population(records, nodes[0].params)
	if err != nil {
		return nil, err
	}
	for i, n := range nodes[1:] {
		where := fmt.Sprintf("nodes[%d] (%s)", i+1, n.id)
		keep := passes
		if n.operator == OperatorWindow {
			keep = inWindow
		}
		var next []record
		for _, r := range selected {
			ok, err := keep(r, n.params, where)
			if err != nil {
				return nil, err
			}
			if ok {
				next = append(next, r)
			}
		}
		selected = next
	}
	rows := make([]Row, len(selected))
	for i, r := range selected {
		d, err := canonical.JSONDigest(r.header)
		if err != nil {
			return nil, err // population digested every header already
		}
		rows[i] = Row{Seq: r.seq, RecordType: r.recordType, Digest: d}
	}
	return rows, nil
}

// Build is the dataset document Run's rows make, its plan_ref the plan's
// digest. A Result's dataset_ref is the JSON digest of this document.
func Build(plan interface{}, records interface{}) (map[string]interface{}, error) {
	rows, err := Run(plan, records)
	if err != nil {
		return nil, err
	}
	planDigest, err := canonical.JSONDigest(plan)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, len(rows))
	for i, r := range rows {
		out[i] = r.JSON()
	}
	return map[string]interface{}{
		"dataset_version": DatasetVersion,
		"plan_ref":        map[string]interface{}{"digest_alg": "SHA-256", "digest": planDigest},
		"rows":            out,
	}, nil
}

// CheckDataset refuses dataset unless it is what plan selects from records.
func CheckDataset(plan, dataset, records interface{}) error {
	if _, err := datasetNodes(plan); err != nil {
		return err
	}
	_, datasetSchema, err := schemas()
	if err != nil {
		return fmt.Errorf("compiling the Plan IR schema: %w", err)
	}
	if err := validate(datasetSchema, dataset, DatasetInvalid); err != nil {
		return err
	}
	if _, err := digest(dataset, DatasetInvalid, "the dataset"); err != nil {
		return err
	}
	doc := dataset.(map[string]interface{})
	planDigest, err := canonical.JSONDigest(plan)
	if err != nil {
		return err
	}
	if doc["plan_ref"].(map[string]interface{})["digest"] != planDigest {
		return refuse(PlanRefMismatch, "dataset.plan_ref is not the digest of the plan")
	}
	want, err := Run(plan, records)
	if err != nil {
		return err
	}
	got := doc["rows"].([]interface{})
	same := len(got) == len(want)
	for i := 0; same && i < len(got); i++ {
		// The schema closed the row to these four members.
		row := got[i].(map[string]interface{})
		seq, _ := seqOf(row["seq"])
		same = seq == want[i].Seq && row["record_type"] == want[i].RecordType && row["digest"] == want[i].Digest
	}
	if !same {
		message := fmt.Sprintf("the dataset has %d row(s); the plan selects %d", len(got), len(want))
		if len(got) == len(want) {
			message += ", in another order or with other digests"
		}
		return refuse(RowsMismatch, "%s", message)
	}
	return nil
}
