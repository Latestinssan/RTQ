/**
 * Stable protocol error codes for `rtq-approval-v1`.
 *
 * These codes are part of the wire contract: the device, the host and the
 * tests all agree on them, and the documentation enumerates them. They MUST
 * stay stable so that a mismatch can be diagnosed without guessing, and so the
 * mobile client can map a failure to a specific, non-leaky UI state.
 *
 * Codes are namespaced but intentionally human-readable. None of them may
 * contain secret material (no keys, no PINs, no signatures).
 */
export const PROTOCOL_ERROR = {
  // --- Envelope / framing ---------------------------------------------------
  INVALID_PREFIX: "protocol.invalid_prefix",
  MALFORMED_BASE64: "protocol.malformed_base64",
  MALFORMED_JSON: "protocol.malformed_json",
  DUPLICATE_JSON_KEY: "protocol.duplicate_json_key",
  PAYLOAD_NOT_OBJECT: "protocol.payload_not_object",
  UNKNOWN_KIND: "protocol.unknown_kind",
  UNSUPPORTED_PROTOCOL: "protocol.unsupported_protocol",
  UNSUPPORTED_VERSION: "protocol.unsupported_version",
  MISSING_FIELD: "protocol.missing_field",
  INVALID_FIELD: "protocol.invalid_field",

  // --- Host authenticity ----------------------------------------------------
  HOST_SIGNATURE_INVALID: "challenge.host_signature_invalid",
  HOST_MISMATCH: "challenge.host_mismatch",

  // --- Challenge lifecycle --------------------------------------------------
  CHALLENGE_UNKNOWN: "challenge.unknown",
  CHALLENGE_EXPIRED: "challenge.expired",
  CHALLENGE_NOT_YET_VALID: "challenge.not_yet_valid",
  CHALLENGE_REDEEMED: "challenge.redeemed",
  CLOCK_SKEW: "challenge.clock_skew",

  // --- Device identity ------------------------------------------------------
  DEVICE_UNKNOWN: "device.unknown",
  DEVICE_REVOKED: "device.revoked",
  DEVICE_EXPIRED: "device.expired",
  DEVICE_ID_MISMATCH: "device.id_mismatch",
  DEVICE_SIGNATURE_INVALID: "device.signature_invalid",

  // --- Approval binding -----------------------------------------------------
  BINDING_MISMATCH: "approval.binding_mismatch",
  DECISION_DENIED: "approval.denied",

  // --- Pairing --------------------------------------------------------------
  PAIRING_UNKNOWN: "pairing.unknown",
  PAIRING_EXPIRED: "pairing.expired",
  PAIRING_REDEEMED: "pairing.redeemed",
  PAIRING_SIGNATURE_INVALID: "pairing.signature_invalid",
  PAIRING_DEVICE_MISMATCH: "pairing.device_mismatch",
} as const;

export type ProtocolErrorCode =
  (typeof PROTOCOL_ERROR)[keyof typeof PROTOCOL_ERROR];

/** Machine-readable failure carrying a stable code plus a human reason. */
export class ProtocolError extends Error {
  readonly code: ProtocolErrorCode;
  constructor(code: ProtocolErrorCode, reason: string) {
    super(reason);
    this.name = "ProtocolError";
    this.code = code;
  }
}

export type ParseResult<T> =
  | { ok: true; value: T }
  | { ok: false; code: ProtocolErrorCode; reason: string };

export function ok<T>(value: T): ParseResult<T> {
  return { ok: true, value };
}

export function fail<T = never>(
  code: ProtocolErrorCode,
  reason: string,
): ParseResult<T> {
  return { ok: false, code, reason };
}
