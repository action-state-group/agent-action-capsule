#!/usr/bin/env bash
# Unpack a bundle from build_offline_bundle.sh and run setup, all four vector
# runners and the break-one-byte step with the network denied.
#
#   scripts/verify_offline_bundle.sh BUNDLE.tar.gz
#
# Network denial: sandbox-exec on macOS, unshare -rn on Linux. The script
# refuses to run where it cannot deny the network, and first proves the denial
# works by failing a connection attempt.
set -euo pipefail

bundle=${1:?usage: $0 BUNDLE.tar.gz}
bundle=$(cd "$(dirname "$bundle")" && pwd)/$(basename "$bundle")
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
tar -C "$work" -xzf "$bundle"
root="$work/aac-offline-bundle"

case "$(uname -s)" in
  Darwin) offline() { sandbox-exec -p '(version 1)(allow default)(deny network*)' "$@"; } ;;
  Linux)  offline() { unshare -rn "$@"; } ;;
  *) echo "error: no network denial on $(uname -s)" >&2; exit 1 ;;
esac

if offline python3 -c 'import socket; socket.create_connection(("1.1.1.1", 53), 3)' 2>/dev/null; then
  echo "error: the network is still reachable under the denial; not a valid offline check" >&2
  exit 1
fi
echo "== network denied (connection attempt failed as required)"

offline "$root/setup-offline.sh"
snap="$root/agent-action-capsule"
status=0
for lang in python ts go rust; do
  echo "== $lang"
  offline python3 "$snap/scripts/run_vectors.py" "$lang" || status=1
  offline python3 "$snap/scripts/run_vectors.py" "$lang" --break-one-byte || status=1
done
if [ "$status" -eq 0 ]; then echo "== offline bundle OK"; else echo "== offline bundle FAILED"; fi
exit "$status"
