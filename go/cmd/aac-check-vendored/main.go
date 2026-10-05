// SPDX-License-Identifier: BSD-3-Clause

// Command aac-check-vendored checks that a vendored registry value-set file
// still equals the named section of spec/REGISTRY.md at a pinned
// agent-action-capsule ref. It is the Go equivalent of
// `python -m agent_action_capsule.registries check-vendored`.
//
//	go run github.com/action-state-group/agent-action-capsule/go/cmd/aac-check-vendored@v0.7.0 \
//	    [-ref REF] [-registry PATH] [-json] FILE...
//
// Without -registry the REGISTRY.md embedded in this module is used, and only
// when the pin names this module's version. A pass proves the copy equals the
// registry at the pinned ref, not that the pin is current.
//
// Exit 0 when every file matches, 1 when any does not, 2 on unreadable input.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/action-state-group/agent-action-capsule/go/registries"
)

func main() {
	ref := flag.String("ref", "", "the pinned agent-action-capsule ref or version (default: the file's source.registry_ref)")
	registryPath := flag.String("registry", "", "REGISTRY.md or registries.json at the pinned ref (default: the embedded copy, valid only when the pin is this module's version)")
	asJSON := flag.Bool("json", false, "machine-readable output")
	flag.Parse()
	if flag.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "usage: aac-check-vendored [-ref REF] [-registry PATH] [-json] FILE...")
		os.Exit(2)
	}

	registry := registries.EmbeddedRegistry()
	registryRef := registries.EmbeddedVersion()
	if *registryPath != "" {
		data, err := os.ReadFile(*registryPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		registry = data
	}

	type result struct {
		File string `json:"file"`
		*registries.VendoredCheck
		Detail []string `json:"detail"`
	}
	var results []result
	failed := false
	for _, name := range flag.Args() {
		data, err := os.ReadFile(name)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(2)
		}
		rr := registryRef
		if *registryPath != "" {
			// The caller asserts the supplied copy is at the pin.
			rr = pinOf(data, *ref)
		}
		c := registries.CheckVendored(data, registry, rr, *ref)
		failed = failed || !c.OK
		results = append(results, result{name, c, c.Detail})
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(results)
	} else {
		for _, r := range results {
			if r.OK {
				fmt.Printf("%s: ok (%s, REGISTRY.md section %s at %s)\n", r.File, *r.Registry, *r.Section, *r.Ref)
			}
			for _, d := range r.Detail {
				fmt.Printf("%s: FAIL: %s\n", r.File, d)
			}
		}
	}
	if failed {
		os.Exit(1)
	}
}

// pinOf is the pin a check will use: ref, else the file's source.registry_ref.
func pinOf(vendored []byte, ref string) string {
	if ref != "" {
		return ref
	}
	var f struct {
		Source struct {
			RegistryRef string `json:"registry_ref"`
		} `json:"source"`
	}
	_ = json.Unmarshal(vendored, &f)
	return f.Source.RegistryRef
}
