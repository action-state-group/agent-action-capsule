# /// script
# requires-python = ">=3.10"
# dependencies = ["web3>=7,<8", "cryptography>=42", "rfc8785==0.1.4"]
# ///
# SPDX-License-Identifier: BSD-3-Clause
"""Register an agent on an ERC-8004 Identity Registry with an evidence-commitment service entry, and
resolve one from its agentId to a verified commitment (spec/bindings/evidence-commitment-carriers-v0.md
§5.4 and §6).

    uv run erc8004_carrier.py register --key-file KEY.json --commitment-url URL [--agent-id N]
    uv run erc8004_carrier.py resolve --agent-id N

Base Sepolia (chain 84532) only, testnet gas only. It calls only the Identity Registry's register()
and setAgentURI(), never the Reputation or Validation Registry. KEY.json is {"address", "private_key"}
for a key that holds no real funds on any chain; the key is never printed.

``resolve`` prints each hop: agentId -> tokenURI -> registration file -> registrations check (V0) ->
the evidence-commitment entry (V0) -> the commitment octets and digest (V1) -> its signature (V2) ->
its staples (V3). It then hands the commitment to ``capsulectl verify --history`` when capsulectl is
on PATH, which checks each stapled history_card/1 and its checkpoint chain. V5 (key binding) needs a
signed answer from the node and is not shown here.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request
from pathlib import Path

import rfc8785
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat, load_der_public_key
from web3 import Web3

RPC = "https://sepolia.base.org"
CHAIN_ID = 84532
# erc-8004/erc-8004-contracts README, Base Sepolia.
REGISTRY = "0x8004A818BFB912233c491871b3d84c89A494BD9e"
AGENT_REGISTRY = f"eip155:{CHAIN_ID}:{REGISTRY}"
TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
PROFILES = {"evidence-commitment/0", "evidence-commitment/1"}
SHA_TAG = re.compile(r"sha256:[0-9a-f]{64}")
ABI = [
    {"type": "function", "name": "register", "inputs": [], "outputs": [{"name": "agentId", "type": "uint256"}],
     "stateMutability": "nonpayable"},
    {"type": "function", "name": "setAgentURI", "stateMutability": "nonpayable", "outputs": [],
     "inputs": [{"name": "agentId", "type": "uint256"}, {"name": "newURI", "type": "string"}]},
    {"type": "function", "name": "tokenURI", "stateMutability": "view", "outputs": [{"name": "", "type": "string"}],
     "inputs": [{"name": "tokenId", "type": "uint256"}]},
    {"type": "event", "name": "Registered", "anonymous": False,
     "inputs": [{"name": "agentId", "type": "uint256", "indexed": True},
                {"name": "agentURI", "type": "string", "indexed": False},
                {"name": "owner", "type": "address", "indexed": True}]},
]


def hop(name: str, value: object) -> None:
    print(f"{name}: {value if isinstance(value, str) else json.dumps(value, sort_keys=True)}")


def fetch(url: str) -> bytes:
    if not url.startswith("https:"):
        sys.exit(f"only https: endpoints are fetched here, not {url}")
    with urllib.request.urlopen(url, timeout=30) as r:
        return r.read()


def registry(w3: Web3):
    if w3.eth.chain_id != CHAIN_ID:
        sys.exit(f"{RPC} is chain {w3.eth.chain_id}, not Base Sepolia")
    return w3.eth.contract(address=REGISTRY, abi=ABI)


def send(w3: Web3, account, call) -> dict:
    tx = call.build_transaction({"from": account.address, "nonce": w3.eth.get_transaction_count(account.address),
                                 "chainId": CHAIN_ID})
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(account.sign_transaction(tx).raw_transaction), timeout=180)
    if receipt.status != 1:
        sys.exit(f"transaction {receipt.transactionHash.hex()} reverted")
    return receipt


def registration_file(agent_id: int, endpoint: str, digest: str) -> dict:
    """§5.4: the entry, and registrations[] naming this agent; no supportedTrust."""
    return {"type": TYPE, "name": "evidence-commitment demo node",
            "description": "A demo node of the evidence-network loop. Verify its commitment, not this file.",
            "image": "",
            "services": [{"name": "evidence-commitment", "endpoint": endpoint, "version": "evidence-commitment/1",
                          "digest": digest}],
            "registrations": [{"agentId": agent_id, "agentRegistry": AGENT_REGISTRY}]}


def data_uri(doc: dict) -> str:
    return "data:application/json;base64," + base64.b64encode(rfc8785.dumps(doc)).decode()


def cmd_register(args: argparse.Namespace) -> None:
    key = json.loads(Path(args.key_file).read_text())
    w3 = Web3(Web3.HTTPProvider(RPC))
    account = w3.eth.account.from_key(key["private_key"])
    contract = registry(w3)
    octets = fetch(args.commitment_url)
    digest = "sha256:" + hashlib.sha256(octets).hexdigest()
    hop("commitment", f"{args.commitment_url} {digest}")
    hop("owner", account.address)
    # register() first: the file's registrations[] names the agentId, which only the registry assigns.
    # With --agent-id, an agent registered by an earlier run whose setAgentURI failed is finished instead.
    agent_id = args.agent_id
    if agent_id is None:
        first = send(w3, account, contract.functions.register())
        (event,) = contract.events.Registered().process_receipt(first)
        agent_id = event.args.agentId
        hop("register tx", "0x" + first.transactionHash.hex().removeprefix("0x"))
    hop("agentId", str(agent_id))
    second = send(w3, account, contract.functions.setAgentURI(
        agent_id, data_uri(registration_file(agent_id, args.commitment_url, digest))))
    hop("setAgentURI tx", "0x" + second.transactionHash.hex().removeprefix("0x"))


def cmd_resolve(args: argparse.Namespace) -> None:
    contract = registry(Web3(Web3.HTTPProvider(RPC)))
    hop("agent", f"{AGENT_REGISTRY} agentId {args.agent_id}")
    uri = contract.functions.tokenURI(args.agent_id).call()
    if not uri:
        sys.exit("tokenURI is empty: the agent has no registration file yet (finish it with register --agent-id)")
    hop("tokenURI", uri if len(uri) < 120 else uri[:117] + "...")
    prefix = "data:application/json;base64,"
    file = json.loads(base64.b64decode(uri[len(prefix):]) if uri.startswith(prefix) else fetch(uri))
    hop("registration file", file)

    def same(r: dict) -> bool:
        aid, reg = r.get("agentId"), r.get("agentRegistry", "").split(":")
        mine = AGENT_REGISTRY.split(":")
        return (isinstance(aid, int) and not isinstance(aid, bool) and aid == args.agent_id and len(reg) == 3
                and reg[:2] == mine[:2] and reg[2].lower() == mine[2].lower())
    entries = [e for e in file.get("services", []) if e.get("name") == "evidence-commitment"]
    if not entries:
        sys.exit("no evidence-commitment entry: not a carrier entry (§5.4)")
    if not any(same(r) for r in file.get("registrations", [])):
        sys.exit("V0 erc8004_registration: registrations[] does not name this agent")
    hop("V0 registrations", "PASS")
    if (len(entries) != 1 or set(entries[0]) != {"name", "endpoint", "version", "digest"}
            or entries[0]["version"] not in PROFILES or not entries[0]["endpoint"].startswith(("https:", "nostr:"))
            or not SHA_TAG.fullmatch(entries[0]["digest"])):
        sys.exit("V0 erc8004_entry: the entry is not in §5.4's form")
    (entry,) = entries
    hop("V0 entry", "PASS")
    octets = fetch(entry["endpoint"])
    got = "sha256:" + hashlib.sha256(octets).hexdigest()
    hop("V1 octets", f"{entry['endpoint']} {got}" + ("" if got == entry["digest"] else " digest_mismatch"))
    try:
        c = json.loads(octets)
        if not isinstance(c, dict) or c.get("profile") not in PROFILES or not isinstance(c.get("sig"), dict):
            raise ValueError
    except ValueError:
        sys.exit("V2 commitment_form")
    try:
        key = load_der_public_key(base64.b64decode(c["spki"]))
        if (not isinstance(key, Ed25519PublicKey)
                or key.public_bytes(Encoding.Raw, PublicFormat.Raw).hex() != c["key_id"]):
            raise ValueError
    except (ValueError, KeyError, TypeError, UnsupportedAlgorithm):
        sys.exit("V2 key_id_spki")
    try:
        sig = c["sig"]["value"]
        key.verify(base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
                   rfc8785.dumps({k: v for k, v in c.items() if k != "sig"}))
    except (InvalidSignature, ValueError, KeyError, TypeError):
        sys.exit("V2 commitment_signature")
    hop("V2 signature", f"PASS key_id {c['key_id']} issued_at {c['issued_at']}")
    cards = c["history_cards"] if c["profile"] == "evidence-commitment/1" else [c["history_card"]]
    for s in [c["checkpoint"], *cards]:
        if hashlib.sha256(base64.b64decode(s["bytes"])).hexdigest() != s["sha256"]:
            sys.exit("V3 staple_digest")
    hop("V3 staples", f"PASS {[s.get('stream') for s in cards]}")
    capsulectl = shutil.which("capsulectl")
    if capsulectl is None:
        hop("history cards", "NOT_CHECKED: capsulectl is not on PATH")
        return
    with tempfile.NamedTemporaryFile(suffix=".json") as f:
        f.write(octets)
        f.flush()
        out = subprocess.run([capsulectl, "verify", "--history", f.name], check=False, capture_output=True,
                             text=True, stdin=subprocess.DEVNULL, timeout=120)
    print("capsulectl verify --history:")
    print(out.stdout + out.stderr)


def main() -> None:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    sub = parser.add_subparsers(required=True)
    reg = sub.add_parser("register")
    reg.add_argument("--key-file", required=True)
    reg.add_argument("--commitment-url", required=True)
    reg.add_argument("--agent-id", type=int, help="finish an agent an earlier run registered: only setAgentURI")
    reg.set_defaults(run=cmd_register)
    res = sub.add_parser("resolve")
    res.add_argument("--agent-id", type=int, required=True)
    res.set_defaults(run=cmd_resolve)
    args = parser.parse_args()
    args.run(args)


if __name__ == "__main__":
    main()
