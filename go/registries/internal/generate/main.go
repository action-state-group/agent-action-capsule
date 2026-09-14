// SPDX-License-Identifier: BSD-3-Clause
// Command generate copies the authoritative registry into the Go package for embedding.
package main

import (
	"fmt"
	"os"
)

func main() {
	const source = "../../spec/REGISTRY.md"
	const destination = "data/REGISTRY.md"

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
