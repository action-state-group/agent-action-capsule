// SPDX-License-Identifier: BSD-3-Clause
// Command generate copies the authoritative registry, and the registries.json
// generated from it, into the Go package for embedding.
package main

import (
	"fmt"
	"os"
)

func main() {
	copyFile("../../spec/REGISTRY.md", "data/REGISTRY.md")
	// Generated from spec/REGISTRY.md by python/scripts/generate_registries_json.py.
	copyFile("../../python/agent_action_capsule/data/registries.json", "data/registries.json")
}

func copyFile(source, destination string) {
	contents, err := os.ReadFile(source)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read %s: %v\n", source, err)
		os.Exit(1)
	}
	if err := os.WriteFile(destination, contents, 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write %s: %v\n", destination, err)
		os.Exit(1)
	}
}
