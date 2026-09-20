/**
 * `@rtq/mobile` — host-side transport and service for the `rtq-approval-v1`
 * mobile approval protocol.
 *
 * Security model (see docs/mobile-approval/security-model.md):
 *  - the transport is untrusted; signatures + challenge binding carry trust;
 *  - the host independently verifies device authorization, expiry, replay,
 *    binding and the device signature before issuing any authorization.
 */
export * from "./service";
export * from "./http";
export * from "./client";
export {
  DeviceRegistry,
  PairingManager,
  ChallengeStoreV1,
  MobileApprovalVerifier,
  PROTOCOL_ERROR,
} from "@rtq/approval";
export type {
  ChallengeV1,
  SignedApprovalV1,
  PairingChallengeV1,
  SignedPairingResponseV1,
  DeviceRecord,
  DeviceStatus,
  ProtocolErrorCode,
} from "@rtq/approval";
