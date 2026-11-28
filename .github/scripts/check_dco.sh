#!/usr/bin/env bash
# SPDX-License-Identifier: BSD-3-Clause
# check_dco.sh <base> <head>: every non-merge commit in base..head carries a
# DCO Signed-off-by line and no AI co-author trailer. dco.yml runs it on a
# pull request's range and scripts/check.sh on the branch's commits not yet
# on main. Merge commits are skipped (see dco.yml for why).
set -euo pipefail
if [ "$#" -ne 2 ]; then
  echo "usage: check_dco.sh <base> <head>" >&2
  exit 2
fi
# Resolve both ends first: an empty or unknown base would otherwise make the
# range empty and pass with nothing checked.
base="$(git rev-parse --verify --quiet "$1^{commit}")" || { echo "check_dco.sh: unknown base '$1'" >&2; exit 2; }
head="$(git rev-parse --verify --quiet "$2^{commit}")" || { echo "check_dco.sh: unknown head '$2'" >&2; exit 2; }
commits="$(git rev-list --no-merges "$base..$head")"

missing=()
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  msg=$(git log --format=%B -n 1 "$sha")
  if ! echo "$msg" | grep -qiE "^Signed-off-by: .+ <.+@.+>"; then
    missing+=("$(git log --format='%h %s' -n 1 "$sha")")
  fi
done <<< "$commits"
if [ ${#missing[@]} -gt 0 ]; then
  echo "ERROR: Missing DCO Signed-off-by on the following commits:"
  printf '  %s\n' "${missing[@]}"
  echo
  echo "Fix: git commit --amend -s  (for last commit)"
  echo "     git rebase --signoff HEAD~N  (for N commits)"
  exit 1
fi
echo "All commits signed off. ✓"

# Authorship here is human and DCO-signed. A co-author trailer naming an AI
# assistant misstates who is accountable for the commit, so any commit carrying
# one fails.
pattern='^Co-authored-by: .*(claude|anthropic|copilot|chatgpt|openai|codex|gemini|cursor)'
bad=()
while IFS= read -r sha; do
  [ -n "$sha" ] || continue
  if git log --format=%B -n 1 "$sha" | grep -qiE "$pattern"; then
    bad+=("$(git log --format='%h %s' -n 1 "$sha")")
  fi
done <<< "$commits"
if [ ${#bad[@]} -gt 0 ]; then
  echo "ERROR: AI co-author trailer on the following commits:"
  printf '  %s\n' "${bad[@]}"
  echo
  echo "Fix: remove the trailer (git commit --amend / git rebase -i) and force-push."
  exit 1
fi
echo "No AI co-author trailers. ✓"
