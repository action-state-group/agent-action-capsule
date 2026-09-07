// SPDX-License-Identifier: BSD-3-Clause

package registries

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
)

// cpbSnapshot mirrors python/agent_action_capsule/data/cpb_provisional.json.
// Source commit and snapshot hash travel with the data. No network is used.
//
//go:embed data/cpb_provisional.json
var cpbSnapshot []byte

// ProvisionalValues returns registry -> value -> provisional artifact class.
// It mirrors Python check 8; this diagnostic metadata never grants trust.
// Callers own the returned map.
func ProvisionalValues() (map[string]map[string]string, error) {
	var snapshot struct {
		Types map[string]struct {
			Values map[string][]string `json:"capsule_field_values"`
		} `json:"provisional_artifact_types"`
	}
	if err := json.Unmarshal(cpbSnapshot, &snapshot); err != nil {
		return nil, fmt.Errorf("decode embedded CPB provisional registry: %w", err)
	}
	result := make(map[string]map[string]string)
	classes := make([]string, 0, len(snapshot.Types))
	for name := range snapshot.Types {
		classes = append(classes, name)
	}
	sort.Strings(classes)
	for _, class := range classes {
		for _, registry := range RegistryNames {
			for _, value := range snapshot.Types[class].Values[registry] {
				if result[registry] == nil {
					result[registry] = make(map[string]string)
				}
				if _, exists := result[registry][value]; !exists {
					result[registry][value] = class
				}
			}
		}
	}
	return result, nil
}
