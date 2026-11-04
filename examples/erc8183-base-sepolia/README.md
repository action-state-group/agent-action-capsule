# ERC-8183 jobs on Base Sepolia (EXPERIMENTAL)

`erc8183_job.py` runs jobs under the adapter profile
[`spec/adapters/erc-8183-v0.md`](../../spec/adapters/erc-8183-v0.md) on a public testnet, and resolves a
job from its `jobId` to the profile's seven checks. [`run/`](run/) holds one run: one job that ended
`complete` and one that ended in `claimRefund`.

## The recorded run

| | |
|---|---|
| Chain | Base Sepolia, `eip155:84532` |
| `AgenticCommerce` proxy | `0x0Bea95653d2145b326c5B835F9bF3E5cCB705aD1` |
| Implementation | `0x50623B1Ed0aEE153E79C5341928cEc7A796e2434` |
| Payment token | `0x140543bBBE8B74B8482379E54c1e345F7b6213a9`, [`TestToken.sol`](TestToken.sol), which anyone can mint |
| Contract source | `ethereum/ERCs@a078cab5cc8e9581c15f76c091ed96eed28f02f7`, `ERCS/erc-8183.md`, extracted unmodified |
| Compiler | solc 0.8.38, optimizer 200 runs, `cancun`, OpenZeppelin 5.6.1 |
| Creation code, sha256 | `AgenticCommerce` `d573885fa65da205e0355e35f976188d2df4efae311b4de6f223b730483efce8`, `TestToken` `c604ce95779ef535abfbcaf20f1d83e710e39a56bd96cfe37a35cff8546d82cd`, `ERC1967Proxy` `6e5ab0a7c11a39fd0c1cb964d03736694bbd985682e4257077fdfd6f58cc5e76` |
| Judge | `claude-sonnet-5-5`, through [`judge.py`](judge.py) |

| Job | Judge's verdict | Ending | Predicates | Resolver output |
|---|---|---|---|---|
| 1 | `met` | `complete` | E1, E2 | [`run/job-1-resolve.txt`](run/job-1-resolve.txt) |
| 2 | `not_evaluable` | `claimRefund` after `expiredAt` | E3 | [`run/job-2-resolve.txt`](run/job-2-resolve.txt) |

[`run/run.json`](run/run.json) lists every transaction. The work each job judged is in
`run/job-N-deliverable.record.json`. Job 2's deliverable holds only a link to a PDF, which is the
"content not retrievable" case: the judge has nothing to read, the evaluator makes no call, and the
client gets the budget back.

The judge's rationale is in `run/job-N-report.answer.json`, beside the record it produced. The report
has no member for it (`schemas/judge/evaluation-report-v1.json`), so the capsule does not commit to it.

## Check the run

```bash
uv run erc8183_job.py resolve --contract 0x0Bea95653d2145b326c5B835F9bF3E5cCB705aD1 --job 1 --from-block 54546453 --records run
```

It reads `getJob` and the job's events from the chain, and each record from `--records`. It prints each
hop, then the seven checks and the predicates. `--from-block` must be at or before the job's `createJob`,
or it exits with an error. It reads logs 200 blocks per call, the public RPC's limit, and stops at the job's
terminal event. An RPC failure, or a contract without the reference interface, also exits with an error. A
terminal event counts as settled once it is logged. So `resolve` never reports §7's `NOT_CHECKED` or `INCONCLUSIVE`
for check 1.

To compare the deployed code, run `build`, compare the digests it prints with the table above, and compare
the creation code with the input of the `deploy` transactions in `run/run.json`. `resolve` prints the
implementation address it read from the proxy's ERC-1967 slot.

`uv run erc8183_job.py check-vectors` runs the same checks over `vectors/adapters/erc-8183/`, with no
chain, so that this output means what the vectors pin. It also tests how the resolver chooses a report
and prints its hops, and CI runs it.

## Run it again

You need:

- **Three testnet keys,** each in a file `{"address", "private_key"}`, outside this repository. Use keys that
  hold nothing on any chain: an EVM key controls the same address on mainnet too. A key is never printed.
- **About 0.0001 Base Sepolia ETH** on the client's address, from a faucet. The recorded run cost about
  0.00005 testnet ETH in all, more than half of it deploying the implementation.
- **`capsulectl`** on `PATH`, from [capsule-cli releases](https://github.com/action-state-group/capsule-cli/releases); v0.1.0-rc35 was used.
- **The `claude` CLI,** signed in, for `judge`.

Create one sealing profile per role, with its seeds and store outside this repository, so that no `git add`
picks them up. `DIR` is an absolute path to a directory of your own. Repeat this with `evaluator` in place of `provider`:

```bash
capsulectl key generate --output DIR/provider.seed
capsulectl key generate --output DIR/provider-checkpoint.seed
capsulectl profile create --name provider --type jsonl --jsonl-path DIR/provider-store --log cll --log-id erc8183-provider --operator erc8183-base-sepolia --namespace erc8183 --signing-key-file DIR/provider.seed --checkpoint-signing-key-file DIR/provider-checkpoint.seed --trusted-key PROVIDER_PUBLIC_KEY --checkpoint-trusted-key CHECKPOINT_PUBLIC_KEY
capsulectl store init --profile provider
```

`key generate` prints each `public_key`. The work to judge is a JSON file. `{"work": {"title": "...", "summary": "..."}}`
is the shape of job 1, and `{"work": {"title": "...", "summary_location": "https://..."}}` the shape of job 2. Each
recorded `run/job-N-deliverable.record.json` holds its work base64-encoded under `artifacts[0].content`.

`run/run.json` records the transactions, so move the recorded run aside first. Then:

```bash
uv run erc8183_job.py build
uv run erc8183_job.py deploy --key-file CLIENT.json
uv run erc8183_job.py send-gas --key-file CLIENT.json --to PROVIDER_ADDRESS --wei 6000000000000
uv run erc8183_job.py send-gas --key-file CLIENT.json --to EVALUATOR_ADDRESS --wei 2000000000000
uv run erc8183_job.py open --key-file CLIENT.json --provider-key-file PROVIDER.json --evaluator EVALUATOR_ADDRESS --expires-in 3600 --budget 1000000
uv run erc8183_job.py seal --profile provider --action-id urn:example:deliverable:1 --developer example-provider@v1 --payload WORK.json --out run/job-1-deliverable.record.json
uv run erc8183_job.py submit --key-file PROVIDER.json --job 1 --capsule run/job-1-deliverable.record.json
uv run erc8183_job.py judge --job 1 --deliverable run/job-1-deliverable.record.json --model-id claude-sonnet-5-5 --out run/job-1-report.json
uv run erc8183_job.py seal --profile evaluator --action-id urn:example:evaluation-report:1 --developer example-evaluator@v1 --payload run/job-1-report.json --out run/job-1-report.record.json
```

The next step follows the verdict `judge` printed (§6.4):

| Verdict | Step |
|---|---|
| `met` | `uv run erc8183_job.py complete --key-file EVALUATOR.json --job 1 --capsule run/job-1-report.record.json` |
| `not_met` | `uv run erc8183_job.py reject --key-file EVALUATOR.json --job 1 --capsule run/job-1-report.record.json` |
| `not_evaluable` | no call: `uv run erc8183_job.py claim-refund --key-file CLIENT.json --job 1`, which waits for `expiredAt` |

To reach the refund without a long wait, open the job with a short expiry: `createJob` needs more than 5 minutes,
and job 2 used `--expires-in 420`.

`complete` and `reject` read the sealed report and refuse a verdict that does not match them. Run the steps on
Base Sepolia only, and never on mainnet.

## What this does not show

- **Who signed.** The report's signing key is not bound to the evaluator's address; that is open point
  E-1 of the profile. In job 1, the evaluator's own transaction commits it to `reason`. Job 2 has no such
  transaction, so nothing on chain says the evaluator made or stands behind its report (E3, §9).
- **That the contract stays as deployed.** It is a UUPS proxy, and the client's address holds
  `DEFAULT_ADMIN_ROLE`, which can upgrade it. The checks read `getJob` through the proxy.
- **That the judge is right.** A pinned judge's verdict is its reading of the work. `temperature` is the
  CLI's default, recorded as such in the pin, so a rerun can differ.
- **Trust in a signing key.** The resolver checks each envelope against the key it carries. It holds no list
  of trusted keys.
