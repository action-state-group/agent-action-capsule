/**
 * `presentation/v1` typed extension: producer display name, logo, title.
 * This reads exactly those three members and nothing else -- the chrome
 * rule (presentation can never touch verification chrome) is enforced
 * structurally here: any other member of the block (a badge image, a
 * "verified" claim, extra markup) is never extracted, so it cannot reach
 * any renderer, header or otherwise.
 */
export interface PresentationBlock {
  readonly producerDisplayName?: string;
  readonly logoDataUrl?: string;
  readonly title?: string;
}

function object(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

const dataImageUrl = /^data:image\//u;

export function readPresentationBlock(
  bundle: unknown,
): PresentationBlock | undefined {
  const top = object(bundle);
  const extensions = object(top?.extensions);
  const block = object(extensions?.["presentation/v1"]);
  if (block === undefined) return undefined;
  const name =
    typeof block.producer_display_name === "string"
      ? block.producer_display_name
      : undefined;
  const logo =
    typeof block.logo_data_url === "string" &&
    dataImageUrl.test(block.logo_data_url)
      ? block.logo_data_url
      : undefined;
  const title = typeof block.title === "string" ? block.title : undefined;
  if (name === undefined && logo === undefined && title === undefined)
    return undefined;
  return {
    ...(name === undefined ? {} : { producerDisplayName: name }),
    ...(logo === undefined ? {} : { logoDataUrl: logo }),
    ...(title === undefined ? {} : { title }),
  };
}
