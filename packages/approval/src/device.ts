/**
 * Device identity registry and pairing for `rtq-approval-v1`.
 *
 * The host is the authority for *which* devices may approve. A device is only
 * trusted after an explicit pairing ceremony:
 *
 *   1. Host creates a short-lived, single-use, host-signed pairing challenge
 *      and displays it as a QR code.
 *   2. Device scans it, generates a local Ed25519 key pair, and returns a
 *      signed pairing response proving possession of the private key.
 *   3. Host verifies the response, requires explicit user confirmation, and
 *      records the device as authorized with an optional expiry.
 *
 * Revocation is a first-class operation. A revoked device fails verification
 * immediately, regardless of how valid its signature is.
 */

import type { JsonWebKey } from "crypto";
import { deviceIdFromPublicKey, ed25519Sign } from "@rtq/crypto";
import {
  PROTOCOL_ERROR,
  type ParseResult,
  type ProtocolErrorCode,
} from "./errors";
import {
  PAIRING_TTL_MS_V1,
  RTQ_APPROVAL_PROTOCOL,
  RTQ_APPROVAL_PROTOCOL_VERSION,
  createPairingChallengeV1,
  encodePairingChallengeV1,
  encodePairingResponseV1,
  parsePairingResponseV1,
  verifyPairingResponseV1,
  type PairingChallengeV1,
  type SignedPairingResponseV1,
  type UnsignedPairingResponseV1,
} from "./protocol";

export type DeviceStatus = "authorized" | "revoked";

export interface DeviceRecord {
  /** `sha256(raw public key)` hex — recomputed by the host, never trusted. */
  deviceId: string;
  publicKeyJwk: JsonWebKey;
  name: string;
  status: DeviceStatus;
  registeredAt: number;
  /** Optional expiry; an expired device is treated like a revoked one. */
  expiresAt?: number;
  /** Optional free-form platform label ("ios", "android"). */
  platform?: string;
  revokedAt?: number;
  revokeReason?: string;
  lastSeenAt?: number;
}

export type DeviceAuditEvent =
  | "PAIRING_STARTED"
  | "PAIRING_COMPLETED"
  | "PAIRING_REJECTED"
  | "DEVICE_REGISTERED"
  | "DEVICE_AUTHORIZED"
  | "DEVICE_REVOKED";

export interface DeviceRegistryOptions {
  /** Structured audit hook. MUST NOT be given secret material. */
  onAudit?: (event: DeviceAuditEvent, detail: Record<string, unknown>) => void;
  /** Fixed clock injection for deterministic tests. */
  now?: () => number;
}

/**
 * In-memory device registry. A production host backs this with durable storage;
 * the verification logic is identical.
 */
export class DeviceRegistry {
  private readonly devices = new Map<string, DeviceRecord>();
  private readonly onAudit?: DeviceRegistryOptions["onAudit"];
  private readonly now: () => number;

  constructor(options: DeviceRegistryOptions = {}) {
    this.onAudit = options.onAudit;
    this.now = options.now ?? (() => Date.now());
  }

  private audit(
    event: DeviceAuditEvent,
    detail: Record<string, unknown>,
  ): void {
    this.onAudit?.(event, detail);
  }

  /** Register or replace a device record. */
  register(record: DeviceRecord): void {
    const expectedId = deviceIdFromPublicKey(record.publicKeyJwk);
    if (expectedId !== record.deviceId) {
      throw new Error(
        "deviceId does not match the fingerprint of publicKeyJwk",
      );
    }
    this.devices.set(record.deviceId, { ...record });
    this.audit("DEVICE_REGISTERED", {
      deviceId: record.deviceId,
      name: record.name,
      status: record.status,
    });
  }

  authorize(deviceId: string, expiresAt?: number): boolean {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    device.status = "authorized";
    delete device.revokedAt;
    delete device.revokeReason;
    if (expiresAt !== undefined) device.expiresAt = expiresAt;
    this.audit("DEVICE_AUTHORIZED", { deviceId, expiresAt });
    return true;
  }

  revoke(deviceId: string, reason: string): boolean {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    device.status = "revoked";
    device.revokedAt = this.now();
    device.revokeReason = reason;
    this.audit("DEVICE_REVOKED", { deviceId, reason });
    return true;
  }

  get(deviceId: string): DeviceRecord | null {
    const device = this.devices.get(deviceId);
    return device ? { ...device } : null;
  }

  getPublicKey(deviceId: string): JsonWebKey | null {
    return this.devices.get(deviceId)?.publicKeyJwk ?? null;
  }

  isAuthorized(deviceId: string): boolean {
    const device = this.devices.get(deviceId);
    if (!device) return false;
    if (device.status !== "authorized") return false;
    if (device.expiresAt !== undefined && this.now() > device.expiresAt) {
      return false;
    }
    return true;
  }

  /** Why a device is unusable, or null when it is authorized. */
  rejectionFor(deviceId: string): ProtocolErrorCode | null {
    const device = this.devices.get(deviceId);
    if (!device) return PROTOCOL_ERROR.DEVICE_UNKNOWN;
    if (device.status === "revoked") return PROTOCOL_ERROR.DEVICE_REVOKED;
    if (device.expiresAt !== undefined && this.now() > device.expiresAt) {
      return PROTOCOL_ERROR.DEVICE_EXPIRED;
    }
    return null;
  }

  list(): DeviceRecord[] {
    return [...this.devices.values()].map((d) => ({ ...d }));
  }

  get size(): number {
    return this.devices.size;
  }
}

// ===========================================================================
// Pairing
// ===========================================================================

export interface PairingManagerOptions {
  hostId: string;
  application: string;
  hostPrivateKey: Parameters<typeof ed25519Sign>[0];
  hostPublicKey: JsonWebKey;
  registry: DeviceRegistry;
  ttlMs?: number;
  /** Host-side user confirmation. Pairing MUST NOT complete without it. */
  onUserConfirmation?: (
    challenge: PairingChallengeV1,
  ) => Promise<boolean> | boolean;
  onAudit?: (event: DeviceAuditEvent, detail: Record<string, unknown>) => void;
  now?: () => number;
}

interface PendingPairing {
  challenge: PairingChallengeV1;
  redeemed: boolean;
}

export interface CreatedPairing {
  challenge: PairingChallengeV1;
  /** QR payload to display. */
  payload: string;
}

export type CompletePairingResult =
  | { ok: true; device: DeviceRecord }
  | { ok: false; code: ProtocolErrorCode; reason: string }
  | {
      ok: false;
      code: ProtocolErrorCode;
      reason: string;
      requiresConfirmation: true;
    };

export class PairingManager {
  private readonly registry: DeviceRegistry;
  private readonly options: PairingManagerOptions;
  private readonly pending = new Map<string, PendingPairing>();
  private readonly now: () => number;

  constructor(options: PairingManagerOptions) {
    this.options = options;
    this.registry = options.registry;
    this.now = options.now ?? (() => Date.now());
  }

  private audit(
    event: DeviceAuditEvent,
    detail: Record<string, unknown>,
  ): void {
    this.options.onAudit?.(event, detail);
  }

  private ttlMs(): number {
    return this.options.ttlMs ?? PAIRING_TTL_MS_V1;
  }

  purgeExpired(): number {
    const now = this.now();
    let purged = 0;
    for (const [id, entry] of this.pending) {
      if (now > entry.challenge.expiresAt) {
        this.pending.delete(id);
        purged += 1;
      }
    }
    return purged;
  }

  /** Host-side: create a short-lived, single-use pairing challenge. */
  createPairingChallenge(
    params: {
      userHint?: string;
      ttlMs?: number;
    } = {},
  ): CreatedPairing {
    this.purgeExpired();
    const challenge = createPairingChallengeV1({
      host: {
        hostId: this.options.hostId,
        application: this.options.application,
        hostPrivateKey: this.options.hostPrivateKey,
        hostPublicKey: this.options.hostPublicKey,
      },
      ...(params.userHint !== undefined ? { userHint: params.userHint } : {}),
      ttlMs: params.ttlMs ?? this.ttlMs(),
      now: this.now(),
    });
    this.pending.set(challenge.pairingId, { challenge, redeemed: false });
    this.audit("PAIRING_STARTED", {
      pairingId: challenge.pairingId,
      hostId: challenge.hostId,
      expiresAt: challenge.expiresAt,
    });
    return { challenge, payload: encodePairingChallengeV1(challenge) };
  }

  peek(pairingId: string): { expiresAt: number; redeemed: boolean } | null {
    const entry = this.pending.get(pairingId);
    if (!entry) return null;
    return { expiresAt: entry.challenge.expiresAt, redeemed: entry.redeemed };
  }

  /**
   * Host-side: complete pairing from a device's signed response.
   * Fails closed on every mismatch. Requires explicit user confirmation when
   * `onUserConfirmation` is configured (recommended and used by the CLI/demo).
   */
  async completePairing(
    response: SignedPairingResponseV1,
    options: { deviceName?: string; platform?: string } = {},
  ): Promise<CompletePairingResult> {
    const entry = this.pending.get(response.pairingId);
    if (!entry) {
      return {
        ok: false,
        code: PROTOCOL_ERROR.PAIRING_UNKNOWN,
        reason: "unknown pairing",
      };
    }
    if (entry.redeemed) {
      return {
        ok: false,
        code: PROTOCOL_ERROR.PAIRING_REDEEMED,
        reason: "pairing already completed (replay)",
      };
    }
    const now = this.now();
    if (now > entry.challenge.expiresAt) {
      this.pending.delete(response.pairingId);
      return {
        ok: false,
        code: PROTOCOL_ERROR.PAIRING_EXPIRED,
        reason: "pairing expired",
      };
    }
    if (
      response.hostId !== entry.challenge.hostId ||
      response.nonce !== entry.challenge.nonce
    ) {
      return {
        ok: false,
        code: PROTOCOL_ERROR.BINDING_MISMATCH,
        reason: "pairing response is not bound to the pending challenge",
      };
    }
    if (!verifyPairingResponseV1(response)) {
      this.audit("PAIRING_REJECTED", {
        pairingId: response.pairingId,
        deviceId: response.deviceId,
        reason: "invalid device signature",
      });
      return {
        ok: false,
        code: PROTOCOL_ERROR.PAIRING_SIGNATURE_INVALID,
        reason: "device pairing signature is invalid",
      };
    }
    if (
      this.registry.rejectionFor(response.deviceId) ===
      PROTOCOL_ERROR.DEVICE_REVOKED
    ) {
      return {
        ok: false,
        code: PROTOCOL_ERROR.DEVICE_REVOKED,
        reason: "device is revoked",
      };
    }
    if (this.options.onUserConfirmation) {
      const confirmed = await this.options.onUserConfirmation(entry.challenge);
      if (!confirmed) {
        this.audit("PAIRING_REJECTED", {
          pairingId: response.pairingId,
          deviceId: response.deviceId,
          reason: "user declined",
        });
        return {
          ok: false,
          code: PROTOCOL_ERROR.DECISION_DENIED,
          reason: "pairing was declined on the host",
        };
      }
    }
    entry.redeemed = true;
    const record: DeviceRecord = {
      deviceId: response.deviceId,
      publicKeyJwk: response.publicKeyJwk,
      name: options.deviceName ?? response.deviceName,
      status: "authorized",
      registeredAt: now,
      lastSeenAt: now,
    };
    if (options.platform !== undefined) record.platform = options.platform;
    this.registry.register(record);
    this.audit("PAIRING_COMPLETED", {
      pairingId: response.pairingId,
      deviceId: response.deviceId,
      name: record.name,
    });
    return { ok: true, device: record };
  }

  get size(): number {
    return this.pending.size;
  }
}

// ===========================================================================
// Pairing response parsing entry point (strict)
// ===========================================================================

/** Strictly parse a pairing response payload from raw JSON text. */
export function parsePairingResponseText(
  text: string,
): ParseResult<SignedPairingResponseV1> {
  return parsePairingResponseV1(text);
}

/** Convenience: canonical JSON for a pairing response. */
export function serializePairingResponse(
  response: SignedPairingResponseV1,
): string {
  return encodePairingResponseV1(response);
}

/** Build the unsigned pairing response body (helper for tests/tools). */
export function unsignedPairingResponse(params: {
  pairing: PairingChallengeV1;
  deviceId: string;
  deviceName: string;
  publicKeyJwk: JsonWebKey;
  signedAt: number;
}): UnsignedPairingResponseV1 {
  return {
    protocol: RTQ_APPROVAL_PROTOCOL,
    version: RTQ_APPROVAL_PROTOCOL_VERSION,
    kind: "pairing_response",
    pairingId: params.pairing.pairingId,
    hostId: params.pairing.hostId,
    nonce: params.pairing.nonce,
    deviceId: params.deviceId,
    deviceName: params.deviceName,
    publicKeyJwk: params.publicKeyJwk,
    signedAt: params.signedAt,
  };
}
