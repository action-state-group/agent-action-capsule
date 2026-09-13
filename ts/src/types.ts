import type { KeyObject } from "node:crypto";

export const CONTENT_TYPE = "application/agent-action-capsule-id";

export interface SigningIdentity {
  readonly privateKey: KeyObject;
  readonly publicKey: Uint8Array;
}

export interface EnvelopeFinding {
  readonly code: string;
  readonly detail: string;
}

export interface EnvelopeVerificationResult {
  readonly ok: boolean;
  readonly findings: readonly EnvelopeFinding[];
  readonly capsuleId: string;
  readonly publicKey?: Uint8Array;
}
