# Aartiq → RTQ Mobile Approval migration analysis

Evidence-grounded assessment of Aartiq's current approval mechanism compared
with the RTQ Mobile Approval model, and a concrete migration path. The goal is
not to copy Aartiq: **Aartiq should adopt the RTQ protocol** (`rtq-approval-v1`)
so both products share one security model and one implementation family.

## Current Aartiq behavior (evidence)

| File                                                              | What it does                                                                                                                    | Problem                                                                                                                                                           |
| ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `flutter_browser_app/lib/pages/connect_desktop_page.dart:409`     | reads the PIN from a deep-link URI query parameter (`uri.queryParameters['pin']`)                                               | **PIN in the QR/deep link** — the secret travels to the phone over an out-of-band channel                                                                         |
| `flutter_browser_app/lib/pages/connect_desktop_page.dart:243`     | passes `'pin': pin` to `SyncService().executeDesktopControl(...)` when approving a risk action                                  | **PIN in transit** back to the desktop over the control channel                                                                                                   |
| `flutter_browser_app/lib/pages/action_approval_page.dart:332-353` | compares the typed PIN to an expected PIN (`widget.pin`) and sends `{'approved': true, 'pin': enteredPin}` over `approve-shell` | **shared-secret PIN model**: the phone holds the expected PIN and the desktop must re-see it to trust the approval; no per-action binding, no nonce, no signature |

So Aartiq's approval is a _shared PIN over the wire_, which the RTQ threat
model explicitly rejects (no PIN ever leaves the device; a device signature
plus host-side verification is the authority).

## Migration table

| Aspect                    | Aartiq today                                | RTQ model                                                                                             | Verdict                                                                                       |
| ------------------------- | ------------------------------------------- | ----------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| Carrier of the request    | deep link + PIN in query                    | host-signed challenge QR (strict, canonical base64url)                                                | **Should be replaced** — RTQ `rtq://challenge?v=1&c=`                                         |
| Human's credential        | shared PIN typed on phone                   | local PIN (PBKDF2-wrapped key) + optional biometrics, never transmitted                               | **Should be replaced** — RTQ vault (`rtq.device_key.v1`)                                      |
| What authorizes an action | `approved:true` + PIN echo                  | device Ed25519 signature over the canonical challenge binding                                         | **Should be replaced** — RTQ `signApprovalV1`                                                 |
| Trust anchor              | implicit (whoever knows the PIN)            | host key pinned from a host-signed pairing QR; device registered by the host                          | **Needs hardening / new**: adopt RTQ pairing                                                  |
| Replay protection         | none visible                                | challenge nonce, expiry, single-use consumption on the host                                           | **Needs hardening** — adopt RTQ consumption                                                   |
| Wrong-action protection   | none visible (PIN attaches to nothing)      | binding = challengeId + capability + inputHash + risk + origin + nonce + …; host verifies every field | **Needs hardening** — adopt RTQ binding                                                       |
| UI honesty                | approval page exists but tied to shared PIN | dedicated per-state screens; destructive/irreversible warnings; nothing hidden                        | **Reusable in spirit** — reuse the UX patterns from `apps/rtq-mobile/lib/ui/`                 |
| Result transport          | desktop control channel                     | separate untrusted HTTP `/approve` (channel is not the trust boundary)                                | **Reusable as an integration** — desktop must call the RTQ host instead of trusting the phone |

## Adoption plan (Aartiq → RTQ protocol)

1. **Keep Aartiq's screens, swap the security core.** Replace the
   URI-PIN + `approve-shell` mechanism with RTQ's challenge/approval pair.
   The Aartiq desktop shows an RTQ challenge QR (`createChallengeV1`) instead
   of a deep link with a PIN.
2. **Drop the shared PIN.** The phone keeps the local PIN only; neither it nor
   any derived value is placed in URIs, QRs, or control-channel payloads.
3. **Introduce RTQ pairing** (host-signed pairing QR, device registration in
   the RTQ `DeviceRegistry`) so the host can authorize this device.
4. **Route approvals through the RTQ host.** Aartiq desktop calls the RTQ host
   (`packages/mobile/src/service.ts`) to create challenges and to verify the
   signed approval (`approval-v1.ts`) before executing — Aartiq then benefits
   from nonce/single-use/expiry/binding checks for free.
5. **Ship the shared vectors**: Aartiq's Dart app can reuse the `rtq-approval-v1`
   vectors and this repo's `apps/rtq-mobile` test suite as its conformance
   check.

## Non-goals

- Keeping PHI-style "PIN in the QR" anywhere on the Aartiq side.
- Letting the phone be the authorization authority for the desktop (the RTQ
  host stays the authority and enforces policy).
