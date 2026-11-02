import {
  bindingApplies,
  STATUS_FAIL,
  STATUS_NOT_CHECKED,
  STATUS_PASS,
  verifyBinding,
  type BindingOptions,
  type BindingReport,
  type Instant,
} from "./controller-binding.js";

/**
 * Ladder rung 8 for one producer key (docs/controller-binding-carriage.md): the
 * Controller Binding v0 records a record cites through `references[]`, checked
 * against the record's `key_id`. The citing and the digest lookup belong to the
 * caller; this reads the binding octets it was handed. It adds no bundle
 * member and no rule to controller-binding-v0: each binding is checked by
 * {@link verifyBinding}, and a binding applies as CB §6.2 says.
 *
 * `NOT_CHECKED` when no handed binding names the key, `PASS` when at least one
 * applies, `FAIL` when some name it and none applies. `PASS` states what CB §7
 * allows: both key holders signed the claim. It names no controller, and
 * `revocationChecked` says whether a declaration that counts excluded a
 * revocation (CB-1), as no source for revocations is registered.
 */
export interface KeyBindingReport {
  readonly status: string;
  /** Every handed binding that names the key, with its report and the other bound key. */
  readonly bindings: readonly {
    readonly report: BindingReport;
    readonly otherKey: string;
    readonly applies: boolean;
  }[];
  /** True when an applying binding's revocation property is PASS (CB §6.1). */
  readonly revocationChecked: boolean;
}

export async function verifyKeyBinding(
  keyId: string,
  at: Instant,
  records: readonly (Uint8Array | string)[],
  opts: BindingOptions = {},
): Promise<KeyBindingReport> {
  const bindings: {
    report: BindingReport;
    otherKey: string;
    applies: boolean;
  }[] = [];
  for (const record of records) {
    const report = await verifyBinding(record, [at], opts);
    const keys = report.keys;
    if (keys === undefined || !keys.includes(keyId)) continue;
    bindings.push({
      report,
      otherKey: keys[0] === keyId ? keys[1] : keys[0],
      applies: bindingApplies(report),
    });
  }
  const applying = bindings.filter((b) => b.applies);
  return {
    status:
      bindings.length === 0
        ? STATUS_NOT_CHECKED
        : applying.length > 0
          ? STATUS_PASS
          : STATUS_FAIL,
    bindings,
    revocationChecked: applying.some(
      (b) => b.report.properties.controller_binding_revocation === STATUS_PASS,
    ),
  };
}
