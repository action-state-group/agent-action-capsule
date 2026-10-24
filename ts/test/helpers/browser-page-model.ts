// The shipped browser build of the verification model: test/helpers/page-model.ts
// (which reads only src/ modules that src/browser.ts exports) bundled for the
// browser in memory, as capsule-viewer bundles src/browser.ts, so cll
// resolves to its browser substrate, which has no checkpoint authenticator.
import { build } from "esbuild";
import type { pageModel } from "./page-model.js";

export async function browserPageModel(): Promise<typeof pageModel> {
  const output = await build({
    entryPoints: [new URL("./page-model.ts", import.meta.url).pathname],
    bundle: true,
    format: "iife",
    platform: "browser",
    globalName: "PageModel",
    write: false,
    logLevel: "silent",
  });
  return (
    new Function(`${output.outputFiles[0]!.text}; return PageModel;`)() as {
      pageModel: typeof pageModel;
    }
  ).pageModel;
}
