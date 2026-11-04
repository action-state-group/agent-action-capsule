# /// script
# requires-python = ">=3.10"
# dependencies = ["web3>=7,<8", "agent-action-capsule[envelope]==0.15.0", "jsonschema>=4,<5", "py-solc-x>=2,<3"]
# ///
# SPDX-License-Identifier: BSD-3-Clause
"""Run ERC-8183 jobs under the adapter profile spec/adapters/erc-8183-v0.md, and resolve a job to its seven checks.

    uv run erc8183_job.py build
    uv run erc8183_job.py deploy --key-file CLIENT.json
    uv run erc8183_job.py send-gas --key-file CLIENT.json --to ADDRESS --wei N
    uv run erc8183_job.py open --key-file CLIENT.json --provider-key-file PROVIDER.json --evaluator ADDRESS \
        --expires-in SECONDS --budget N
    uv run erc8183_job.py seal --profile NAME --action-id ID --developer NAME --payload FILE --out RECORD.json
    uv run erc8183_job.py judge --job N --deliverable RECORD.json --model-id MODEL --out REPORT.json
    uv run erc8183_job.py submit --key-file PROVIDER.json --job N --capsule RECORD.json
    uv run erc8183_job.py complete --key-file EVALUATOR.json --job N --capsule RECORD.json
    uv run erc8183_job.py reject --key-file EVALUATOR.json --job N --capsule RECORD.json
    uv run erc8183_job.py claim-refund --key-file CLIENT.json --job N
    uv run erc8183_job.py resolve --contract ADDRESS --job N --from-block B --records DIR
    uv run erc8183_job.py check-vectors

Base Sepolia (chain 84532) only, testnet gas only. A key file is {"address", "private_key"} for a key that holds
nothing on any chain; a key is never printed. The chain steps record each transaction in run/run.json.

``resolve`` needs the chain: an RPC failure exits with an error, and it never reports §7's offline
NOT_CHECKED for check 1. ``check-vectors`` needs no chain.
"""
from __future__ import annotations

import argparse
import base64
import contextlib
import copy
import hashlib
import io
import json
import posixpath
import re
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request
from pathlib import Path

import jsonschema
import solcx
from agent_action_capsule.canonical import compute_capsule_id, json_digest
from agent_action_capsule.media_types import CAPSULE_ID_MEDIA_TYPE
from agent_action_capsule.producer_envelope import verify_producer_envelope
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from scitt_cose.cose_sign1 import sign_sign1
from web3 import Web3

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[1]
BUILD = HERE / "build"
RUN_DIR = HERE / "run"
RUN = RUN_DIR / "run.json"
CONTRACT_DOC = HERE / "evidence-contract.json"
RPC = "https://sepolia.base.org"
CHAIN_ID = 84532
ERC1967_SLOT = "0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc"
LOG_CHUNK = 200  # the public RPC's eth_getLogs limit

# The reference contract is inline in the EIP. Nothing here changes it.
ERC_COMMIT = "a078cab5cc8e9581c15f76c091ed96eed28f02f7"
ERC_URL = f"https://raw.githubusercontent.com/ethereum/ERCs/{ERC_COMMIT}/ERCS/erc-8183.md"
ERC_SHA256 = "257c35bbaecab58d0c36823fe8fb2d0fffc83d6f1fd7301d97674707784efa3a"
SOLC = "0.8.38"
OZ_VERSION = "5.6.1"
OZ = {  # npm package -> (tarball, the registry's dist.integrity)
    "@openzeppelin/contracts": (
        f"https://registry.npmjs.org/@openzeppelin/contracts/-/contracts-{OZ_VERSION}.tgz",
        "Ly6SlsVJ3mj+b18W3R8gNufB7dTICT105fJhodGAGgyC2oqnBAhqSiNDJ8V8DLY05cCz81GLI0CU5vNYA1EC/w=="),
    "@openzeppelin/contracts-upgradeable": (
        f"https://registry.npmjs.org/@openzeppelin/contracts-upgradeable/-/contracts-upgradeable-{OZ_VERSION}.tgz",
        "n4a/vfRs114lXyUdYg7pyY8LvFKWvCDF5lEcRRAVxap8g6ZEdLqm+9tmt2zTtRHcNMxTYp9y5t6KBof4tHp7Og=="),
}
PROXY_SOURCE = "@openzeppelin/contracts/proxy/ERC1967/ERC1967Proxy.sol"
IMPORT = re.compile(r'^\s*import\s+(?:[^"\']*from\s+)?["\']([^"\']+)["\']', re.M)

CHECKS = ("is_evaluation", "reason_binding", "capsule_verifies", "contract_binding", "contract_digest",
          "deliverable_cited", "verdict_call")
PASS, FAIL, NOT_PRESENT, NOT_CHECKED = "PASS", "FAIL", "NOT_PRESENT", "NOT_CHECKED"
ZERO32 = "0x" + "00" * 32
STATUS = ("Open", "Funded", "Submitted", "Completed", "Rejected", "Expired")
REPORT_SCHEMA = json.loads((REPO / "schemas/judge/evaluation-report-v1.json").read_text())


# ---------------------------------------------------------------------------
# Digests and the held records (spec/adapters/erc-8183-v0.md §6, §7)
# ---------------------------------------------------------------------------

def load_record(path: Path) -> dict | None:
    """A `capsulectl get --raw` record, in the shape §7 reads. None when it holds no readable Capsule. A missing
    envelope or payload stays None here, which §7 step 3 reports as NOT_PRESENT."""
    try:
        raw = json.loads(path.read_text())
        capsule = json.loads(base64.b64decode(raw["capsule"]))
        if not isinstance(capsule, dict):
            return None
        envelope = raw.get("producer_envelope")
        artifact = next((a for a in raw.get("artifacts") or [] if a.get("name") == "payload"), None)
        payload = json.loads(base64.b64decode(artifact["content"])) if artifact else None
    except (ValueError, KeyError, TypeError, AttributeError):
        return None
    return {"capsule": capsule, "payload": payload,
            "envelope_hex": base64.b64decode(envelope).hex() if envelope else None}


def is_report(payload: object) -> bool:
    try:
        jsonschema.validate(payload, REPORT_SCHEMA)
    except jsonschema.ValidationError:
        return False
    return True


def same_address(a: str, b: str) -> bool:
    return bytes.fromhex(a[2:]) == bytes.fromhex(b[2:])


def supported(capsule: object) -> bool:
    return isinstance(capsule, dict) and capsule.get("format_version") == "4" and capsule.get("canonicalization_id") == "jcs"


def report_verifies(held: dict) -> bool:
    """§7 step 3, for a Capsule of the supported format with its envelope and payload held."""
    capsule, recomputed = held["capsule"], compute_capsule_id(dict(held["capsule"]))
    committed = ((capsule.get("model_attestation") or {}).get("compute_attestation") or {}).get("agent_input_digest")
    return (capsule.get("capsule_id") == recomputed
            and verify_producer_envelope(recomputed, bytes.fromhex(held["envelope_hex"])).ok
            and json_digest(held["payload"]) == committed and is_report(held["payload"]))


def check(job: dict, held: dict | None, contract_document: dict | None) -> dict:
    """§7, steps 1 to 7, in order, with its gating. ``job`` is the recorded lookups of §4."""
    get_job = job["getJob"]
    order = [event["event"] for event in job["events"]]
    events: dict[str, dict] = {}
    for event in job["events"]:
        events.setdefault(event["event"], event["args"])
    out: dict[str, str] = {}

    call = None
    if "JobCompleted" in events:
        call = ("complete", events["JobCompleted"])
        out["is_evaluation"] = PASS if same_address(call[1]["evaluator"], get_job["evaluator"]) else FAIL
    elif "JobRejected" in events:
        call = ("reject", events["JobRejected"])
        before = order[:order.index("JobRejected")]
        past_open = "JobFunded" in before or "JobSubmitted" in before
        out["is_evaluation"] = PASS if same_address(call[1]["rejector"], get_job["evaluator"]) and past_open else FAIL
    else:
        out["is_evaluation"] = NOT_PRESENT
    if out["is_evaluation"] == FAIL:
        return {**out, **{c: NOT_CHECKED for c in CHECKS[1:]}}

    capsule = held["capsule"] if held else None
    known = supported(capsule)

    if call is None or held is None or call[1]["reason"] == ZERO32:
        out["reason_binding"] = NOT_PRESENT
    elif not known:
        out["reason_binding"] = NOT_CHECKED
    else:
        out["reason_binding"] = PASS if call[1]["reason"][2:] == compute_capsule_id(dict(capsule)) else FAIL

    if held is None or not held.get("envelope_hex") or held.get("payload") is None:
        out["capsule_verifies"] = NOT_PRESENT
    elif not known:
        out["capsule_verifies"] = NOT_CHECKED
    else:
        out["capsule_verifies"] = PASS if report_verifies(held) else FAIL
    if out["capsule_verifies"] != PASS:
        return {**out, **{c: NOT_CHECKED for c in CHECKS[3:]}}
    report = held["payload"]

    line = get_job["description"].encode().split(b"\n", 1)[0]
    prefix = report["contract_ref"].encode() + b" sha256:"
    digits = line[len(prefix):]
    bound = line.startswith(prefix) and re.fullmatch(rb"[0-9a-f]{64}", digits) is not None
    out["contract_binding"] = PASS if bound else FAIL

    doc = contract_document
    if not bound or doc is None or f"{doc['id']}@{doc['version']}" != report["contract_ref"]:
        out["contract_digest"] = NOT_CHECKED
    else:
        out["contract_digest"] = PASS if json_digest(doc).encode() == digits else FAIL

    if "JobSubmitted" not in events:
        out["deliverable_cited"] = NOT_PRESENT
    else:
        wanted = events["JobSubmitted"]["deliverable"][2:]
        cited = any(a["digest_alg"] == "SHA-256" and a["digest"] == wanted for c in report["cases"] for a in c["acts"])
        out["deliverable_cited"] = PASS if cited else FAIL

    agrees = {"met": "complete", "not_met": "reject", "not_evaluable": "expire", "out_of_scope": "expire"}
    ended = call[0] if call else ("expire" if "JobExpired" in events else None)
    if ended is None:
        out["verdict_call"] = NOT_CHECKED
    else:
        one = len(report["cases"]) == 1 and agrees[report["cases"][0]["verdict"]] == ended
        out["verdict_call"] = PASS if one else FAIL
    return out


def predicates(st: dict) -> list[str]:
    """§9."""
    e1 = all(st[c] == PASS for c in ("is_evaluation", "reason_binding", "capsule_verifies", "contract_binding",
                                     "deliverable_cited", "verdict_call")) and st["contract_digest"] != FAIL
    e3 = (all(st[c] == PASS for c in ("capsule_verifies", "contract_binding", "deliverable_cited", "verdict_call"))
          and st["is_evaluation"] == st["reason_binding"] == NOT_PRESENT and st["contract_digest"] != FAIL)
    return (["E1"] if e1 else []) + (["E2"] if e1 and st["contract_digest"] == PASS else []) + (["E3"] if e3 else [])


def reseal(record: dict, label: str) -> dict:
    """``record`` sealed again with the vectors' public test key, so that it verifies."""
    key = Ed25519PrivateKey.from_private_bytes(hashlib.sha256(label.encode()).digest())
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    public = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    capsule = copy.deepcopy(record["capsule"])
    capsule["model_attestation"]["compute_attestation"]["agent_input_digest"] = json_digest(record["payload"])
    capsule["capsule_id"] = compute_capsule_id(dict(capsule))
    envelope = sign_sign1(bytes.fromhex(capsule["capsule_id"]), alg="EdDSA", private_key_pem=pem,
                          protected={3: CAPSULE_ID_MEDIA_TYPE, 4: public}, unprotected={})
    return {**record, "capsule": capsule, "envelope_hex": envelope.hex()}


def resolver_cases(data: dict) -> list[str]:
    """What the vectors do not reach: choosing the report, and printing the hops, with recorded lookups."""
    by_id = {case["id"]: case for case in data["cases"]}
    problems = []

    def held(*records: dict) -> dict:
        return {compute_capsule_id(dict(r["capsule"])): {**r, "path": f"record-{i}"} for i, r in enumerate(records)}

    def expect(name: str, got: object, want: object) -> None:
        if got != want:
            problems.append(f"{name}: got {got}, want {want}")

    # A changed report is a FAIL, not "none held", though `reason` no longer finds it.
    met = by_id["met-complete"]
    changed = copy.deepcopy(met["report"])
    changed["capsule"]["timestamp"] = "2000-01-01T00:00:00Z"
    with contextlib.redirect_stdout(io.StringIO()):
        statuses = print_resolution(met["job"], held(changed), met["contract_document"])
    expect("changed report", (statuses["reason_binding"], statuses["capsule_verifies"]), (FAIL, FAIL))

    # `reason` names a held capsule that is no report: the checks still print, and nothing reads its content.
    other = by_id["payload-not-a-report"]
    with contextlib.redirect_stdout(io.StringIO()) as printed:
        statuses = print_resolution(other["job"], held(other["report"]), other["contract_document"])
    expect("non-report", statuses["capsule_verifies"], FAIL)
    expect("non-report content printed", "report case" in printed.getvalue(), False)

    # An empty `cases` fails the schema, so it is never read either.
    empty = copy.deepcopy(met["report"])
    empty["payload"]["cases"] = []
    with contextlib.redirect_stdout(io.StringIO()):
        statuses = print_resolution(met["job"], held(empty), met["contract_document"])
    expect("empty cases", statuses["capsule_verifies"], FAIL)

    # The order of events decides whether a rejection is an evaluation.
    rejected = copy.deepcopy(by_id["not-met-reject"])
    rejected["job"]["events"].reverse()
    expect("rejection before funding", check(rejected["job"], rejected["report"], rejected["contract_document"])["is_evaluation"], FAIL)

    # No call: an unverifiable record cannot shadow the report, and two verifying reports are refused.
    refund = by_id["not-evaluable-refund"]
    decoy = copy.deepcopy(refund["report"])
    decoy["envelope_hex"] = decoy["envelope_hex"][:-2] + ("00" if not decoy["envelope_hex"].endswith("00") else "01")
    decoy["capsule"]["timestamp"] = "2000-01-01T00:00:00Z"
    chosen = find_report(refund["job"]["events"], held(decoy, refund["report"]))
    expect("decoy", chosen["capsule"] == refund["report"]["capsule"], True)
    twin = copy.deepcopy(refund["report"])
    twin["payload"]["record_id"] = "another-report"
    with contextlib.redirect_stdout(io.StringIO()):
        try:
            find_report(refund["job"]["events"], held(refund["report"], reseal(twin, data["test_keys"]["evaluator"]["label"])))
            problems.append("two verifying reports: not refused")
        except SystemExit:
            pass

    # A record with no envelope, or none of its parts, does not stop the resolver.
    with tempfile.TemporaryDirectory() as scratch:
        directory = Path(scratch)
        (directory / "a.record.json").write_text("{}")
        (directory / "b.record.json").write_text(json.dumps({
            "capsule": base64.b64encode(json.dumps(met["report"]["capsule"]).encode()).decode(), "artifacts": []}))
        records = held_records(directory)
    expect("incomplete records", len(records), 1)
    only = next(iter(records.values()))
    with contextlib.redirect_stdout(io.StringIO()):
        statuses = print_resolution(met["job"], records, met["contract_document"])
    expect("incomplete record", (only["envelope_hex"], statuses["capsule_verifies"]), (None, NOT_PRESENT))
    return problems


def cmd_check_vectors(_: argparse.Namespace) -> None:
    """This resolver's checks over the profile's vectors, so the run's output means what the vectors pin."""
    data = json.loads((REPO / "vectors/adapters/erc-8183/vectors.json").read_text())
    bad = 0
    for case in data["cases"]:
        st = check(case["job"], case["report"], case["contract_document"])
        if st != case["expected"] or predicates(st) != case["predicates"]:
            bad += 1
            print(f"MISMATCH {case['id']}: {st} {predicates(st)}")
    print(f"{len(data['cases']) - bad}/{len(data['cases'])} vectors agree")
    problems = resolver_cases(data)
    for problem in problems:
        print(f"RESOLVER {problem}")
    print(f"resolver cases: {len(problems)} problems")
    if bad or problems:
        sys.exit(1)


# ---------------------------------------------------------------------------
# Build: the reference contract at its pinned commit, unmodified
# ---------------------------------------------------------------------------

def fetch(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=120) as response:
        return response.read()


def package_sources(tarball: bytes, package: str) -> dict[str, str]:
    out = {}
    with tarfile.open(fileobj=io.BytesIO(tarball), mode="r:gz") as tar:
        for member in tar.getmembers():
            name = member.name.removeprefix("package/")
            if member.isfile() and name.endswith(".sol"):
                out[f"{package}/{name}"] = tar.extractfile(member).read().decode()
    return out


def closure(entry: dict[str, str], library: dict[str, str]) -> dict[str, str]:
    """``entry`` and every file it imports, so only what the contracts use is compiled."""
    sources, todo = {}, dict(entry)
    while todo:
        name, text = todo.popitem()
        sources[name] = text
        for target in IMPORT.findall(text):
            if target.startswith("."):
                target = posixpath.normpath(posixpath.join(posixpath.dirname(name), target))
            if target not in sources and target not in todo:
                todo[target] = entry.get(target) or library[target]
    return sources


def cmd_build(_: argparse.Namespace) -> None:
    text = fetch(ERC_URL)
    if hashlib.sha256(text).hexdigest() != ERC_SHA256:
        sys.exit("the ERC-8183 text does not match its pinned digest")
    BUILD.mkdir(exist_ok=True)
    (BUILD / "erc-8183.md").write_bytes(text)
    blocks = re.findall(r"```solidity\n(pragma solidity.*?)```", text.decode(), re.S)
    hook = next(b for b in blocks if "interface IACPHook" in b)
    commerce = next(b for b in blocks if "contract AgenticCommerce" in b)

    library: dict[str, str] = {}
    for package, (url, integrity) in OZ.items():
        tarball = fetch(url)
        if base64.b64encode(hashlib.sha512(tarball).digest()).decode() != integrity:
            sys.exit(f"{package} does not match its pinned integrity")
        library.update(package_sources(tarball, package))

    entry = {"IACPHook.sol": hook, "AgenticCommerce.sol": commerce,
             "TestToken.sol": (HERE / "TestToken.sol").read_text(), PROXY_SOURCE: library[PROXY_SOURCE]}
    sources = closure(entry, library)
    solcx.install_solc(SOLC)
    compiled = solcx.compile_standard({
        "language": "Solidity",
        "sources": {name: {"content": body} for name, body in sources.items()},
        "settings": {"optimizer": {"enabled": True, "runs": 200}, "evmVersion": "cancun",
                     "outputSelection": {"*": {"*": ["abi", "evm.bytecode.object"]}}},
    }, solc_version=SOLC)
    artifacts = {}
    for source, name in (("AgenticCommerce.sol", "AgenticCommerce"), ("TestToken.sol", "TestToken"),
                         (PROXY_SOURCE, "ERC1967Proxy")):
        unit = compiled["contracts"][source][name]
        artifacts[name] = {"abi": unit["abi"], "bytecode": unit["evm"]["bytecode"]["object"]}
        print(f"{name}: {len(artifacts[name]['bytecode']) // 2} bytes of creation code, "
              f"sha256 {hashlib.sha256(bytes.fromhex(artifacts[name]['bytecode'])).hexdigest()}")
    (BUILD / "artifacts.json").write_text(json.dumps(artifacts))
    print(f"reference source: ethereum/ERCs@{ERC_COMMIT} ERCS/erc-8183.md, sha256 {ERC_SHA256}")
    print(f"sha256 of AgenticCommerce.sol as extracted: {hashlib.sha256(commerce.encode()).hexdigest()}")
    print(f"solc {SOLC}, optimizer 200 runs, cancun, OpenZeppelin {OZ_VERSION}")


# ---------------------------------------------------------------------------
# Chain steps
# ---------------------------------------------------------------------------

def chain() -> Web3:
    w3 = Web3(Web3.HTTPProvider(RPC, request_kwargs={"timeout": 60}))
    if w3.eth.chain_id != CHAIN_ID:
        sys.exit(f"{RPC} is chain {w3.eth.chain_id}, not Base Sepolia")
    return w3


def account(w3: Web3, key_file: str):
    return w3.eth.account.from_key(json.loads(Path(key_file).read_text())["private_key"])


def artifacts() -> dict:
    return json.loads((BUILD / "artifacts.json").read_text())


def state() -> dict:
    return json.loads(RUN.read_text()) if RUN.exists() else {"chain": f"eip155:{CHAIN_ID}", "transactions": {}}


def save(run: dict) -> None:
    RUN_DIR.mkdir(exist_ok=True)
    RUN.write_text(json.dumps(run, indent=2, sort_keys=True) + "\n")


def send(w3: Web3, acct, call, name: str, run: dict):
    """One transaction, recorded as soon as it has a receipt. Only `deploy` skips what is recorded on a rerun."""
    nonce = w3.eth.get_transaction_count(acct.address, "pending")
    tx = call.build_transaction({"from": acct.address, "nonce": nonce, "chainId": CHAIN_ID}) if hasattr(
        call, "build_transaction") else {**call, "from": acct.address, "nonce": nonce, "chainId": CHAIN_ID}
    receipt = w3.eth.wait_for_transaction_receipt(
        w3.eth.send_raw_transaction(acct.sign_transaction(tx).raw_transaction), timeout=180)
    if receipt.status != 1:
        sys.exit(f"{name}: transaction 0x{receipt.transactionHash.hex()} reverted")
    tx_hash = "0x" + receipt.transactionHash.hex().removeprefix("0x")
    fee = receipt.gasUsed * receipt.effectiveGasPrice + int(receipt.get("l1Fee", "0x0"), 16)
    run["transactions"][name] = {"hash": tx_hash, "block": receipt.blockNumber, "from": acct.address,
                                 "gas_used": receipt.gasUsed, "fee_wei": fee}
    save(run)
    print(f"{name}: {tx_hash} block {receipt.blockNumber} gas {receipt.gasUsed} fee {fee} wei")
    return receipt


def deploy_one(w3: Web3, acct, name: str, args: list, run: dict, label: str) -> str:
    if label in run:
        return run[label]
    art = artifacts()[name]
    call = w3.eth.contract(abi=art["abi"], bytecode=art["bytecode"]).constructor(*args)
    run[label] = send(w3, acct, call, f"deploy {label}", run).contractAddress
    save(run)
    return run[label]


def commerce(w3: Web3, run: dict):
    return w3.eth.contract(address=run["agentic_commerce"], abi=artifacts()["AgenticCommerce"]["abi"])


def token(w3: Web3, run: dict):
    return w3.eth.contract(address=run["payment_token"], abi=artifacts()["TestToken"]["abi"])


def cmd_deploy(args: argparse.Namespace) -> None:
    w3, run = chain(), state()
    acct = account(w3, args.key_file)
    run["client"] = acct.address
    token_address = deploy_one(w3, acct, "TestToken", [], run, "payment_token")
    implementation = deploy_one(w3, acct, "AgenticCommerce", [], run, "implementation")
    init = w3.eth.contract(abi=artifacts()["AgenticCommerce"]["abi"]).encode_abi("initialize", [token_address, acct.address])
    deploy_one(w3, acct, "ERC1967Proxy", [implementation, init], run, "agentic_commerce")
    if "mint" not in run["transactions"]:
        send(w3, acct, token(w3, run).functions.mint(acct.address, 10**21), "mint", run)
    if "approve" not in run["transactions"]:
        send(w3, acct, token(w3, run).functions.approve(run["agentic_commerce"], 10**21), "approve", run)
    print(f"agentic_commerce (proxy): {run['agentic_commerce']}")
    print(f"balance left: {w3.eth.get_balance(acct.address)} wei")


def cmd_send_gas(args: argparse.Namespace) -> None:
    w3, run = chain(), state()
    acct = account(w3, args.key_file)
    fees = w3.eth.fee_history(1, "latest", [50])
    tip = 1_000_000
    tx = {"to": args.to, "value": args.wei, "gas": 21000, "maxPriorityFeePerGas": tip,
          "maxFeePerGas": fees["baseFeePerGas"][-1] * 2 + tip}
    send(w3, acct, tx, f"gas to {args.to}", run)


def cmd_open(args: argparse.Namespace) -> None:
    """createJob with the §6.1 first line, setBudget by the provider, fund by the client."""
    w3, run = chain(), state()
    client, provider = account(w3, args.key_file), account(w3, args.provider_key_file)
    acp = commerce(w3, run)
    doc = json.loads(CONTRACT_DOC.read_text())
    description = f"{doc['id']}@{doc['version']} sha256:{json_digest(doc)}\nSummarize the ERC-8183 job lifecycle."
    expires = w3.eth.get_block("latest").timestamp + args.expires_in
    job_id = acp.functions.jobCounter().call() + 1
    receipt = send(w3, client, acp.functions.createJob(provider.address, args.evaluator, expires, description,
                                                       "0x" + "00" * 20), f"job {job_id} createJob", run)
    run.setdefault("first_block", receipt.blockNumber)
    run.setdefault("jobs", {})[str(job_id)] = {"provider": provider.address, "evaluator": args.evaluator,
                                               "expired_at": expires, "budget": args.budget}
    save(run)
    send(w3, provider, acp.functions.setBudget(job_id, args.budget, b""), f"job {job_id} setBudget", run)
    send(w3, client, acp.functions.fund(job_id, b""), f"job {job_id} fund", run)
    print(f"job {job_id} funded, expires at {expires}")


def read_record(path: str) -> dict:
    record = load_record(Path(path))
    if record is None:
        sys.exit(f"{path} holds no readable Capsule")
    return record


def cmd_submit(args: argparse.Namespace) -> None:
    w3, run = chain(), state()
    capsule_id = bytes.fromhex(compute_capsule_id(dict(read_record(args.capsule)["capsule"])))
    send(w3, account(w3, args.key_file), commerce(w3, run).functions.submit(args.job, capsule_id, b""),
         f"job {args.job} submit", run)


def evaluator_call(args: argparse.Namespace, function: str, verdict: str) -> None:
    """§6.4: the call follows the sealed report's verdict, so a report can never be sent with the wrong one."""
    record = read_record(args.capsule)
    if not supported(record["capsule"]) or not record["envelope_hex"] or not report_verifies(record):
        sys.exit(f"{args.capsule} does not verify as an evaluation report")
    cases = record["payload"]["cases"]
    if len(cases) != 1 or cases[0]["verdict"] != verdict:
        sys.exit(f"{function} needs one case judged {verdict}; {args.capsule} has {[c['verdict'] for c in cases]}. See §6.4.")
    w3, run = chain(), state()
    reason = bytes.fromhex(compute_capsule_id(dict(record["capsule"])))
    call = getattr(commerce(w3, run).functions, function)(args.job, reason, b"")
    send(w3, account(w3, args.key_file), call, f"job {args.job} {function}", run)


def cmd_complete(args: argparse.Namespace) -> None:
    evaluator_call(args, "complete", "met")


def cmd_reject(args: argparse.Namespace) -> None:
    evaluator_call(args, "reject", "not_met")


def cmd_claim_refund(args: argparse.Namespace) -> None:
    w3, run = chain(), state()
    left = run["jobs"][str(args.job)]["expired_at"] - w3.eth.get_block("latest").timestamp
    if left >= 0:
        print(f"waiting {left + 4}s for expiredAt")
        time.sleep(left + 4)
    send(w3, account(w3, args.key_file), commerce(w3, run).functions.claimRefund(args.job), f"job {args.job} claimRefund", run)


# ---------------------------------------------------------------------------
# Sealing and judging, off chain
# ---------------------------------------------------------------------------

def capsulectl(*argv: str) -> dict:
    done = subprocess.run(["capsulectl", *argv], capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit(f"capsulectl {argv[0]}: {done.stderr.strip()}")
    return json.loads(done.stdout)


def cmd_seal(args: argparse.Namespace) -> None:
    """Seal one record with `capsulectl publish`, and keep it as a verifiable `get --raw` record."""
    payload = json.loads(Path(args.payload).read_text())
    timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    request = {"spec_version": "capsule-seal-request/v1", "payload": payload,
               "capsule": {"ActionID": args.action_id, "ActionType": "fyi", "Operator": args.operator,
                           "Developer": args.developer, "Timestamp": timestamp}}
    with tempfile.TemporaryDirectory() as scratch:
        path = Path(scratch) / "request.json"
        path.write_text(json.dumps(request))
        capsule_id = capsulectl("publish", "--profile", args.profile, "--request", str(path))["capsule_id"]
    capsulectl("get", "--profile", args.profile, "--capsule-id", capsule_id, "--raw", "--output", args.out)
    print(f"sealed {capsule_id} -> {args.out}")


def sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def cmd_judge(args: argparse.Namespace) -> None:
    """Ask the pinned judge about one deliverable, and write the JF evaluation-report/v1 of its answer."""
    held = read_record(args.deliverable)
    deliverable = compute_capsule_id(dict(held["capsule"]))
    doc = json.loads(CONTRACT_DOC.read_text())
    requirement = doc["requirements"][0]
    reference = (BUILD / "erc-8183.md").read_bytes()
    if hashlib.sha256(reference).hexdigest() != ERC_SHA256:
        sys.exit("build/erc-8183.md does not match its pinned digest")
    judge = [sys.executable, str(HERE / "judge.py")]
    template = json.loads(subprocess.run(judge, input='{"describe": true}', capture_output=True, text=True,
                                         check=True).stdout)["instruction_template_digest"]
    request = {"judge_model_id": args.model_id, "clause": {"id": requirement["id"], "statement": requirement["statement"]},
               "case": {"task_id": f"job-{args.job}", "work": held["payload"]}, "reference": reference.decode()}
    done = subprocess.run(judge, input=json.dumps(request), capture_output=True, text=True)
    if done.returncode != 0:
        sys.exit(f"evidence unavailable: the judge failed: {done.stderr.strip()}")
    answer = json.loads(done.stdout)
    prompt = sha256_file(HERE / "judge-prompt.md")
    report = {
        "record_version": "evaluation-report/v1",
        "record_id": f"er-erc8183-job-{args.job}",
        "epistemic_type": "semantic_judgment",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "contract_ref": f"{doc['id']}@{doc['version']}",
        "judge_pin": {
            "model_id": args.model_id,
            "prompt_digest": {"digest_alg": "SHA-256", "digest": prompt},
            "axes_digest": {"digest_alg": "SHA-256", "digest": sha256_file(HERE / "axes.json")},
            "sampling": {"temperature": "harness default", "instruction_template_digest": template,
                         "reference_digest": ERC_SHA256},
        },
        "cases": [{
            "case_id": f"job-{args.job}-case-1",
            "verdict": answer["verdict"],
            "acts": [{"type": "agent-action-capsule", "digest_alg": "SHA-256", "digest": deliverable,
                      "citation_purpose": "grounds"}],
            "method": {"type": "rubric", "digest_alg": "SHA-256", "digest": prompt, "citation_purpose": "method"},
        }],
    }
    Path(args.out).write_text(json.dumps(report, indent=2, sort_keys=True) + "\n")
    Path(args.out).with_suffix(".answer.json").write_text(json.dumps(answer, indent=2, sort_keys=True) + "\n")
    print(f"judge {args.model_id}: {answer['verdict']}: {answer['rationale']}")


# ---------------------------------------------------------------------------
# Resolve
# ---------------------------------------------------------------------------

def hop(name: str, value: object) -> None:
    print(f"{name}: {value if isinstance(value, str) else json.dumps(value, sort_keys=True)}")


def event_abi_signature(acp, name: str) -> str:
    abi = next(e for e in acp.abi if e["type"] == "event" and e["name"] == name)
    return f"{name}({','.join(i['type'] for i in abi['inputs'])})"


def recorded_job(w3: Web3, acp, job_id: int, from_block: int) -> dict:
    """§4's lookups: getJob, and the job's events in log order."""
    got = acp.functions.getJob(job_id).call()
    keys = ("id", "client", "provider", "evaluator", "description", "budget", "expiredAt", "status", "hook")
    get_job = dict(zip(keys, got))
    get_job["status"] = STATUS[get_job["status"]]
    terminal = {"JobCompleted", "JobRejected", "JobExpired"}
    decoders = {Web3.keccak(text=event_abi_signature(acp, name)).hex().removeprefix("0x"): getattr(acp.events, name)()
                for name in ("JobCreated", "JobFunded", "JobSubmitted", *terminal)}
    topics = [["0x" + t for t in decoders], "0x" + job_id.to_bytes(32, "big").hex()]
    events, latest, start = [], w3.eth.block_number, from_block
    while start <= latest:
        end = min(start + LOG_CHUNK - 1, latest)
        for raw in w3.eth.get_logs({"address": acp.address, "fromBlock": start, "toBlock": end, "topics": topics}):
            log = decoders[raw["topics"][0].hex().removeprefix("0x")].process_log(raw)
            event_args = {k: ("0x" + v.hex() if isinstance(v, bytes) else v) for k, v in log.args.items()}
            events.append({"event": log.event, "args": event_args, "block": log.blockNumber,
                           "tx": "0x" + log.transactionHash.hex().removeprefix("0x")})
        if any(e["event"] in terminal for e in events):  # the contract has no transition after these
            break
        start = end + 1
    if not events or events[0]["event"] != "JobCreated":
        sys.exit(f"job {job_id}: JobCreated is not in the logs from block {from_block}; "
                 "--from-block must be at or before the job's createJob")
    return {"contract": f"eip155:{CHAIN_ID}:{acp.address}", "job_id": job_id, "getJob": get_job, "events": events}


def held_records(directory: Path) -> dict[str, dict]:
    held = {}
    for path in sorted(directory.glob("*.record.json")):
        record = load_record(path)
        if record is None:
            print(f"skipped {path.name}: no readable Capsule")
            continue
        record["path"] = path.name
        held[compute_capsule_id(dict(record["capsule"]))] = record
    return held


def cites(record: dict, deliverable: str | None) -> bool:
    cases = record["payload"].get("cases") if isinstance(record["payload"], dict) else None
    if deliverable is None or not isinstance(cases, list):
        return False
    return any(isinstance(c, dict) and any(isinstance(a, dict) and a.get("digest") == deliverable
                                           for a in c.get("acts") or []) for c in cases)


def find_report(events: list[dict], held: dict[str, dict]) -> dict | None:
    """The record named by `reason`. Otherwise (§7, no call or a changed report) the one that cites the job's
    deliverable, preferring one that verifies, so a bad record cannot shadow it. §6.3 allows one report for a job,
    so two that verify are refused rather than picked between."""
    for event in events:
        if event["event"] in ("JobCompleted", "JobRejected") and event["args"]["reason"][2:] in held:
            return held[event["args"]["reason"][2:]]
    submitted = next((e["args"]["deliverable"][2:] for e in events if e["event"] == "JobSubmitted"), None)
    citing = [r for r in held.values() if cites(r, submitted)]
    verified = [r for r in citing if supported(r["capsule"]) and r["envelope_hex"] and report_verifies(r)]
    if len(verified) > 1:
        sys.exit(f"{len(verified)} verifying reports cite this job's deliverable: {[r['path'] for r in verified]}. "
                 "§6.3 allows one; keep only the one to check in --records.")
    return (verified or citing or [None])[0]


def print_envelope(name: str, record: dict) -> None:
    capsule_id = compute_capsule_id(dict(record["capsule"]))
    hop(f"{name} file", record["path"])
    hop(f"{name} Capsule ID, recomputed", capsule_id)
    if not record["envelope_hex"]:
        hop(f"{name} Producer Envelope", "not held")
        return
    verified = verify_producer_envelope(capsule_id, bytes.fromhex(record["envelope_hex"]))
    hop(f"{name} Producer Envelope", {"verifies": verified.ok, "key": verified.public_key.hex() if verified.ok else None})


def print_resolution(job: dict, held: dict[str, dict], doc: dict | None) -> dict:
    """Each hop, then §7's checks. A report's content prints only once check 3 has passed."""
    for event in job["events"]:
        hop(f"event {event['event']}", {k: event[k] for k in ("args", "tx", "block") if k in event})
    hop("description first line", job["getJob"]["description"].split("\n", 1)[0])
    report = find_report(job["events"], held)
    statuses = check(job, report, doc)
    if report is None:
        hop("report", "none held for this job")
    else:
        print_envelope("report", report)
        if statuses["capsule_verifies"] == PASS:
            hop("report payload digest", json_digest(report["payload"]))
            hop("report judge pin", report["payload"]["judge_pin"])
            hop("report case", report["payload"]["cases"][0])
    submitted = next((e["args"]["deliverable"][2:] for e in job["events"] if e["event"] == "JobSubmitted"), None)
    if submitted is not None and submitted in held:
        print_envelope("deliverable", held[submitted])
    elif submitted is not None:
        hop("deliverable", f"{submitted}: no capsule held")
    for name in CHECKS:
        print(f"check {name}: {statuses[name]}")
    print(f"predicates: {' '.join(predicates(statuses)) or 'none'}")
    if statuses["is_evaluation"] == NOT_PRESENT and report is not None:
        print("no call: no transaction of the evaluator binds this report, and nothing on chain says the evaluator "
              "made or stands behind it (§6.4, §9)")
    return statuses


def cmd_resolve(args: argparse.Namespace) -> None:
    w3 = chain()
    abi = json.loads((HERE / "agentic-commerce-abi.json").read_text())
    acp = w3.eth.contract(address=args.contract, abi=abi)
    job = recorded_job(w3, acp, args.job, args.from_block)
    hop("job", f"{job['contract']} jobId {args.job}")
    hop("implementation (ERC-1967 slot)", Web3.to_checksum_address(w3.eth.get_storage_at(acp.address, ERC1967_SLOT)[-20:]))
    hop("getJob", job["getJob"])
    print_resolution(job, held_records(Path(args.records)), json.loads(CONTRACT_DOC.read_text()))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    commands = parser.add_subparsers(dest="command", required=True)

    def command(name, func, *arguments):
        sub = commands.add_parser(name)
        sub.set_defaults(func=func)
        for flag, kwargs in arguments:
            sub.add_argument(flag, **kwargs)

    required = {"required": True}
    integer = {"required": True, "type": int}
    command("build", cmd_build)
    command("check-vectors", cmd_check_vectors)
    command("deploy", cmd_deploy, ("--key-file", required))
    command("send-gas", cmd_send_gas, ("--key-file", required), ("--to", required), ("--wei", integer))
    command("open", cmd_open, ("--key-file", required), ("--provider-key-file", required), ("--evaluator", required),
            ("--expires-in", integer), ("--budget", integer))
    command("seal", cmd_seal, ("--profile", required), ("--action-id", required), ("--developer", required),
            ("--operator", {"default": "erc8183-base-sepolia"}), ("--payload", required), ("--out", required))
    command("judge", cmd_judge, ("--job", integer), ("--deliverable", required), ("--model-id", required),
            ("--out", required))
    command("submit", cmd_submit, ("--key-file", required), ("--job", integer), ("--capsule", required))
    command("complete", cmd_complete, ("--key-file", required), ("--job", integer), ("--capsule", required))
    command("reject", cmd_reject, ("--key-file", required), ("--job", integer), ("--capsule", required))
    command("claim-refund", cmd_claim_refund, ("--key-file", required), ("--job", integer))
    command("resolve", cmd_resolve, ("--contract", required), ("--job", integer), ("--from-block", integer),
            ("--records", required))
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
