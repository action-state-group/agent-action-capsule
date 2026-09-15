import { asJsonObject, type ParsedJson } from "./json.js";

/** Resolve an object-member path from the disclosure eligibility registry. */
export function resolveDisclosurePath(
  root: ParsedJson,
  path: string,
): ParsedJson | undefined {
  let value: ParsedJson | undefined = root;
  for (const member of path.split(".")) {
    if (member === "") return undefined;
    value = asJsonObject(value)?.[member];
    if (value === undefined) return undefined;
  }
  return value;
}
