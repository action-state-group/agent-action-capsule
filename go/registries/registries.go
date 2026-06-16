// SPDX-License-Identifier: BSD-3-Clause
// Parse spec/REGISTRY.md for the six profile registries (§12).
// Seeded values are NOT hard-coded; they are parsed at load time from the
// interim registry of record (spec/REGISTRY.md) so the code and spec cannot drift.
package registries

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// RegistryNames is the ordered list of the six registry-governed vocabularies (§4).
// disposition.approver is deliberately absent: it is a closed enum (§5.4), not registry-governed.
var RegistryNames = []string{
	"verdict_class",
	"disposition.decision",
	"effect.type",
	"irreversibility_class",
	"effect_attestation",
	"chain.relation",
}

var (
	// ## N. `name`
	headerRE = regexp.MustCompile("^##\\s+\\d+\\.\\s+`([^`]+)`\\s*$")
	tickRE   = regexp.MustCompile("`([^`]+)`")
	// N. `token`
	olItemRE = regexp.MustCompile("^\\s*\\d+\\.\\s+`([^`]+)`\\s*$")
)

// FindRegistryMD locates spec/REGISTRY.md.
// Honors AAC_REGISTRY_PATH env var; otherwise walks up from CWD.
func FindRegistryMD() (string, error) {
	if override := os.Getenv("AAC_REGISTRY_PATH"); override != "" {
		return override, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", err
	}
	dir := cwd
	for {
		candidate := filepath.Join(dir, "spec", "REGISTRY.md")
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return "", fmt.Errorf("spec/REGISTRY.md not found walking up from %s; set AAC_REGISTRY_PATH", cwd)
}

// isAllDashColon returns true if s consists only of '-', ':', and ' '.
// Used to skip the |---|---| separator rows in Markdown tables.
func isAllDashColon(s string) bool {
	for _, c := range s {
		if c != '-' && c != ':' && c != ' ' {
			return false
		}
	}
	return true
}

// backtickFullMatch returns (token, true) if s is exactly `token` with no inner backticks.
func backtickFullMatch(s string) (string, bool) {
	if len(s) >= 2 && s[0] == '`' && s[len(s)-1] == '`' {
		inner := s[1 : len(s)-1]
		if !strings.ContainsRune(inner, '`') {
			return inner, true
		}
	}
	return "", false
}

// seededValuesInSection extracts vocabulary tokens from one registry section.
// Tokens come only from structured loci — table data rows, ordered-list items,
// and "Initial contents" lines — never from prose backticks.
func seededValuesInSection(lines []string) []string {
	var values []string
	seen := make(map[string]bool)

	add := func(tok string) {
		if !seen[tok] {
			seen[tok] = true
			values = append(values, tok)
		}
	}

	i := 0
	n := len(lines)
	for i < n {
		line := lines[i]
		stripped := strings.TrimSpace(line)

		// Markdown table data row: first cell is a backtick-quoted token.
		if strings.HasPrefix(stripped, "|") {
			inner := strings.Trim(stripped, "|")
			cells := strings.Split(inner, "|")
			if len(cells) > 0 {
				first := strings.TrimSpace(cells[0])
				if first != "" && first != "Value" && !isAllDashColon(first) {
					if tok, ok := backtickFullMatch(first); ok {
						add(tok)
					}
				}
			}
			i++
			continue
		}

		// Ordered-list item: "N. `token`"
		if m := olItemRE.FindStringSubmatch(line); m != nil {
			add(m[1])
			i++
			continue
		}

		// "Initial contents" — value list follows on this line (after the marker)
		// and may wrap across lines; collect until a blank line.
		if strings.Contains(stripped, "Initial contents") {
			firstLine := true
			for i < n && strings.TrimSpace(lines[i]) != "" {
				text := lines[i]
				if firstLine {
					idx := strings.Index(text, "Initial contents")
					text = text[idx:]
					firstLine = false
				}
				for _, m := range tickRE.FindAllStringSubmatch(text, -1) {
					add(m[1])
				}
				i++
			}
			continue
		}
		i++
	}
	return values
}

// Load parses spec/REGISTRY.md at path (empty → auto-locate) and returns
// {registry_name: set_of_seeded_values} for the six registries.
func Load(path string) (map[string]map[string]bool, error) {
	if path == "" {
		var err error
		path, err = FindRegistryMD()
		if err != nil {
			return nil, err
		}
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("opening REGISTRY.md: %w", err)
	}
	defer f.Close()

	var allLines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		allLines = append(allLines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading REGISTRY.md: %w", err)
	}

	// Partition lines into sections keyed by backtick-name in "## N. `name`".
	sections := make(map[string][]string)
	var current string
	for _, line := range allLines {
		if m := headerRE.FindStringSubmatch(line); m != nil {
			current = m[1]
			sections[current] = nil
		} else if current != "" {
			if strings.HasPrefix(line, "## ") {
				current = ""
			} else {
				sections[current] = append(sections[current], line)
			}
		}
	}

	out := make(map[string]map[string]bool)
	for _, name := range RegistryNames {
		sec, ok := sections[name]
		if !ok {
			return nil, fmt.Errorf("registry %q not found in REGISTRY.md", name)
		}
		vals := seededValuesInSection(sec)
		if len(vals) == 0 {
			return nil, fmt.Errorf("registry %q parsed with no seeded values", name)
		}
		m := make(map[string]bool, len(vals))
		for _, v := range vals {
			m[v] = true
		}
		out[name] = m
	}
	return out, nil
}
