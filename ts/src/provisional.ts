import snapshot from "./data/cpb_provisional.json" with { type: "json" };

/** Match Python's vendored check-8 projection; this never authorizes an artifact. */
export function provisionalClass(
  registry: string,
  value: string,
): string | undefined {
  const classes: Record<
    string,
    { status: string; capsule_field_values?: Record<string, readonly string[]> }
  > = snapshot.provisional_artifact_types;
  for (const [name, entry] of Object.entries(classes)) {
    if (entry.capsule_field_values?.[registry]?.includes(value)) return name;
  }
  return undefined;
}
