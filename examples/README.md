# RTQ examples

Each example is self-contained and runnable. They are **not** part of the
security envelope — they demonstrate API usage, and the CI workflow runs
them to ensure the published quickstart stays green.

| Example                                 | What it shows                                                                                                                                                                          |
| --------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `agent.ts`                              | register a tool, register a policy, authorize, execute. The complete minimal pipeline.                                                                                                 |
| `qr-approval.ts`                        | full challenge-response QR approval flow (mobile device verifies, signs, submits).                                                                                                     |
| `mobile-approval/device-perspective.ts` | the exact device-side steps of `apps/rtq-mobile` (pinned host-key check, strict QR parse, host-signature verify, forged-payload rejection, signed approval), runnable without a phone. |
| `sandbox-linux.ts`                      | construct a bubblewrap-backed Linux sandbox and run a real command inside it (requires `bwrap`).                                                                                       |

## Run them

```sh
# from the repo root (workspaces are installed there)
export RTQ_SIGNING_KEY="$(openssl rand -hex 32)"
npx tsx examples/agent.ts
npx tsx examples/qr-approval.ts
npx tsx examples/mobile-approval/device-perspective.ts
npx tsx examples/sandbox-linux.ts   # Linux only; needs `bwrap`
```

## Why QR, not a PIN

The QR example encodes a **challenge**, not an approval. Scanning it grants
nothing; the human's _device_ (which performed its own local
authentication) signs the exact challenge and returns the signed approval.
RTQ verifies the signature with a previously-stored device key. There is no
`approve=true` deep link and no PIN anywhere — see `docs/THREAT_MODEL.md`
(T7/T8) and `docs/SECURITY_VERIFICATION_MATRIX.md`.
