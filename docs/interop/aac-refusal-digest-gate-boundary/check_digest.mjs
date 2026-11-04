#!/usr/bin/env node
// Run the refusal-digest side of the gate-boundary vector through the public
// browser verifier (Go compiled to WebAssembly), under Node >= 20.
//
//   mkdir verifier && cd verifier
//   curl -O https://continuitylaboratories.com/verifier/sr-verify.wasm
//   curl -O https://continuitylaboratories.com/verifier/wasm_exec.js
//   cd .. && node check_digest.mjs verifier
//
// The WASM must match the SHA-256 pinned in vector.json before anything runs.
// Each digest case must verify, or fail at the check vector.json names; the
// verifier reports the failed refusal-transparency §4 step by name. Exit 1 on
// any case that lands elsewhere. Any implementation of §4 can be substituted.

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const dir = path.resolve(process.argv[2] ?? 'verifier');
const vector = JSON.parse(readFileSync(path.join(here, 'vector.json'), 'utf8'));
const pin = vector.pins.refusal_digest_verifier;

const wasm = readFileSync(path.join(dir, 'sr-verify.wasm'));
const got = createHash('sha256').update(wasm).digest('hex');
if (got !== pin.sha256) {
  console.error(`sr-verify.wasm is ${got}, vector.json pins ${pin.sha256}`);
  process.exit(1);
}

createRequire(import.meta.url)(path.join(dir, 'wasm_exec.js'));
const go = new globalThis.Go();
const { instance } = await WebAssembly.instantiate(wasm, go.importObject);
go.run(instance);
for (let i = 0; i < 200 && !globalThis.srVerifyReady; i++) await new Promise((r) => setTimeout(r, 25));
if (!globalThis.srVerifyReady) {
  console.error('the WASM verifier did not initialize');
  process.exit(1);
}

const keys = readFileSync(path.join(here, 'inputs', 'test-key.pub'), 'utf8');
const keyId = vector.derivation_inputs.test_signing_key.key_id;
let bad = 0;
for (const row of vector.digest_cases) {
  const res = globalThis.srVerify({
    kind: 'refusal', doc: readFileSync(path.join(here, row.file), 'utf8'), keys, keyId, evalAt: '',
  });
  const result = res.valid ? 'pass' : 'fail';
  const check = res.valid ? null : (res.failingCheck || 'unclassified');
  const ok = result === row.expect && check === row.failing_check;
  if (!ok) bad++;
  console.log(`${ok ? 'ok  ' : 'FAIL'}  ${row.case.padEnd(42)} ${result.padEnd(5)} ${(check ?? '-').padEnd(16)}`
    + ` (expected ${row.expect} ${row.failing_check ?? '-'})`);
}
console.log(`\n${vector.digest_cases.length} digest cases, ${bad} off`);
process.exit(bad ? 1 : 0);
