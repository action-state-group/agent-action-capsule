// SPDX-License-Identifier: BSD-3-Clause
// Differential-testing shim: read one JSON object per line from stdin,
// print ComputeCapsuleID for each (or REFUSED:<type> on error).
// Uses only the AAC Go canonicalizer — an independent implementation.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/action-state-group/agent-action-capsule/go/canonical"
)

func decodeWithNumbers(data []byte) (map[string]interface{}, error) {
	d := json.NewDecoder(strings.NewReader(string(data)))
	d.UseNumber()
	var v map[string]interface{}
	if err := d.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

func main() {
	sc := bufio.NewScanner(os.Stdin)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		v, err := decodeWithNumbers(line)
		if err != nil {
			fmt.Println("PARSE_ERROR")
			continue
		}
		id, cerr := canonical.ComputeCapsuleID(v)
		if cerr != nil {
			fmt.Printf("REFUSED:%T\n", cerr)
			continue
		}
		fmt.Println(id)
	}
}
