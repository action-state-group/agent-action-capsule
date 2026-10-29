/**
 * `contract-report/v1` (spec/contract-report-v1.md): a producer's opt-in to
 * the contract-report view of a verified Evidence Result. The block is a
 * closed empty object. It carries no words, data, grouping, flags or
 * provenance: words come from the module's wording pack, a viewer input
 * (presentation contract section 6), and everything shown comes from the
 * sealed Result.
 */

export const CONTRACT_REPORT_KIND = "contract-report/v1";

/**
 * True when the bundle carries a well-formed `contract-report/v1` block: a
 * plain object with no members. Any other value, or an object with any
 * member, is declined (section 4.2): the kind is then not engaged.
 */
export function readContractReport(bundle: unknown): boolean {
  if (bundle === null || typeof bundle !== "object" || Array.isArray(bundle))
    return false;
  const extensions = (bundle as Record<string, unknown>).extensions;
  if (
    extensions === null ||
    typeof extensions !== "object" ||
    Array.isArray(extensions) ||
    !Object.hasOwn(extensions, CONTRACT_REPORT_KIND)
  )
    return false;
  const block = (extensions as Record<string, unknown>)[CONTRACT_REPORT_KIND];
  return (
    block !== null &&
    typeof block === "object" &&
    !Array.isArray(block) &&
    Object.keys(block).length === 0
  );
}
