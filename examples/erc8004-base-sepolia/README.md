# ERC-8004 carrier on Base Sepolia (EXPERIMENTAL)

`erc8004_carrier.py` shows the fourth carrier of
[`spec/bindings/evidence-commitment-carriers-v0.md`](../../spec/bindings/evidence-commitment-carriers-v0.md)
(§5.4) on a public testnet. It registers one agent on the ERC-8004 Identity Registry on Base Sepolia,
`eip155:84532:0x8004A818BFB912233c491871b3d84c89A494BD9e`, with a registration file whose `services[]`
lists an `evidence-commitment` entry. It then resolves an agent from its `agentId` to a verified
commitment.

```bash
uv run erc8004_carrier.py register --key-file KEY.json --commitment-url URL
uv run erc8004_carrier.py resolve --agent-id N
```

- **`register`.** It calls the registry's `register()`, which assigns the `agentId`. It then calls
  `setAgentURI()` with the registration file as a base64 `data:` URI, so the whole file is on chain.
  The file's `registrations[]` names that `agentId`. It has no `supportedTrust` (§5.4).
- **`KEY.json`.** It is `{"address", "private_key"}` for a testnet-only key holding Base Sepolia ETH
  for gas. The two transactions cost a few millionths of an ETH. Use a key that holds nothing on any
  other chain: an EVM key controls the same address on mainnet too. The key is never printed.
- **`resolve`.** It prints each hop: `tokenURI`, the registration file, the registrations check and
  the entry's form (V0), the commitment octets and digest (V1), the signature (V2) and the staples
  (V3). With `capsulectl` (capsule-cli v0.1.0-rc32 or later) on `PATH`, it then runs
  `capsulectl verify --history` on the commitment, which checks each stapled `history_card/1` and
  its checkpoint chain. V5, the key binding, needs a signed answer from the node, so it is not shown.
  It follows only a `data:` or `https:` *agentURI* and an `https:` endpoint; it stops on an `ipfs:`
  *agentURI* or a `nostr:` endpoint, which §5.4 allows but this example does not fetch.
- **A failed second transaction.** If `setAgentURI()` fails after `register()` succeeded, rerun
  `register` with `--agent-id` set to the printed id: it sends only `setAgentURI()`.

Only the Identity Registry is used, never the Reputation or Validation Registry. Run it on Base
Sepolia only, and never on mainnet. The vectors in `vectors/adapters/evidence-commitment-carriers/`
read no chain; this example is the only part that does.
