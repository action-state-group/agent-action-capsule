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
hop, then the seven checks and the predicates. It stops reading logs at the job's terminal event, 200
blocks per call, which is the public RPC's limit.

`uv run erc8183_job.py check-vectors` runs the same checks over `vectors/adapters/erc-8183/`, with no
chain, so that this output means what the vectors pin.

## Run it again

Each step takes a key file `{"address", "private_key"}` for a testnet-only key. Use keys that hold nothing
on any chain: an EVM key controls the same address on mainnet too. A key is never printed. `run/run.json`
records the transactions, so remove or move the recorded run first.

```bash
uv run erc8183_job.py build
uv run erc8183_job.py deploy --key-file CLIENT.json
uv run erc8183_job.py send-gas --key-file CLIENT.json --to PROVIDER_ADDRESS --wei 6000000000000
uv run erc8183_job.py send-gas --key-file CLIENT.json --to EVALUATOR_ADDRESS --wei 2000000000000
uv run erc8183_job.py open --key-file CLIENT.json --provider-key-file PROVIDER.json --evaluator EVALUATOR_ADDRESS --expires-in 3600 --budget 1000000
uv run erc8183_job.py seal --profile PROVIDER_PROFILE --action-id urn:example:deliverable:1 --developer example-provider@v1 --payload WORK.json --out run/job-1-deliverable.record.json
uv run erc8183_job.py submit --key-file PROVIDER.json --job 1 --capsule run/job-1-deliverable.record.json
uv run erc8183_job.py judge --job 1 --deliverable run/job-1-deliverable.record.json --model-id claude-sonnet-5-5 --out run/job-1-report.json
uv run erc8183_job.py seal --profile EVALUATOR_PROFILE --action-id urn:example:evaluation-report:1 --developer example-evaluator@v1 --payload run/job-1-report.json --out run/job-1-report.record.json
uv run erc8183_job.py complete --key-file EVALUATOR.json --job 1 --capsule run/job-1-report.record.json
```

For a verdict of `not_evaluable`, skip `complete` and run `claim-refund --key-file CLIENT.json --job N`,
which waits for `expiredAt`. `seal` needs `capsulectl` (capsule-cli v0.1.0-rc35 was used) on `PATH` and a
jsonl profile; `judge` needs the `claude` CLI. Run the steps on Base Sepolia only, and never on mainnet.

The recorded run cost about 0.00005 testnet ETH in all, more than half of it deploying the implementation.

## What this does not show

- **Who signed.** The report's signing key is not bound to the evaluator's address; that is open point
  E-1 of the profile. The evaluator's own transaction commits it to `reason`.
- **That the judge is right.** A pinned judge's verdict is its reading of the work. `temperature` is the
  CLI's default, recorded as such in the pin, so a rerun can differ.
- **`capsulectl` trust.** The resolver checks each envelope against the key it carries. It holds no list
  of trusted keys.
