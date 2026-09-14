import type { KeyObject } from "node:crypto";

export interface SigningIdentity {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}
