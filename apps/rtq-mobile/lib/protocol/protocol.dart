/// `rtq-approval-v1` — Flutter implementation.
///
/// Byte-compatible with the TypeScript implementation in
/// `packages/approval/src/protocol.ts`. The shared vectors in
/// `protocol/rtq-approval-v1.vectors.json` are the contract between them.
///
/// This module is pure Dart (no Flutter imports) so it can be unit-tested
/// headlessly and reused outside the UI.
library;

import 'dart:convert';
import 'dart:typed_data';

import 'base64url.dart';
import 'canonical.dart';
import 'crypto_ed25519.dart';
import 'errors.dart';
import 'models.dart';
import 'strict_json.dart';

final _hex64 = RegExp(r'^[0-9a-f]{64}$');
final _hex128 = RegExp(r'^[0-9a-f]{128}$');

class RtqApprovalProtocol {
  RtqApprovalProtocol._();

  static const protocol = rtqApprovalProtocol;
  static const version = rtqApprovalProtocolVersion;

  // -------------------------------------------------------------------------
  // Encoding
  // -------------------------------------------------------------------------

  static String encodeChallenge(RtqChallenge challenge) =>
      challengeQrPrefix +
      encodeUtf8Base64Url(canonicalStringify(challenge.toJson()));

  static String encodePairingChallenge(RtqPairingChallenge pairing) =>
      pairingQrPrefix +
      encodeUtf8Base64Url(canonicalStringify(pairing.toJson()));

  static String encodeSignedApproval(RtqSignedApproval approval) =>
      canonicalStringify(approval.toJson());

  static String encodePairingResponse(RtqPairingResponse response) =>
      canonicalStringify(response.toJson());

  /// True when this QR belongs to any `rtq-approval-v1` flow we understand.
  static bool isSupportedRtqQr(String payload) =>
      payload.startsWith(challengeQrPrefix) ||
      payload.startsWith(approvalQrPrefix) ||
      payload.startsWith(pairingQrPrefix);

  // -------------------------------------------------------------------------
  // Decoding
  // -------------------------------------------------------------------------

  static ProtocolResult<RtqChallenge> parseChallenge(String payload) {
    final env = _parseCommon(payload, [challengeQrPrefix, approvalQrPrefix]);
    if (!env.ok) return ProtocolResult.fail(env.code!, env.reason!);
    final raw = env.value!;
    if (raw['kind'] != 'challenge') {
      return ProtocolResult.fail(
        ProtocolError.unknownKind,
        'expected kind "challenge", got "${raw['kind']}"',
      );
    }
    if (!isNonEmptyString(raw['challengeId']) ||
        !isNonEmptyString(raw['capability']) ||
        raw['capabilityVersion'] is! int ||
        !isHex(raw['inputHash'], 64) ||
        raw['summary'] is! Map ||
        !isNonEmptyString(raw['policyVersion']) ||
        !isNonEmptyString(raw['application']) ||
        !isNonEmptyString(raw['hostId']) ||
        !isNonEmptyString(raw['nonce']) ||
        (raw['nonce'] as String).length < 16 ||
        raw['expiresAt'] is! int ||
        !isRiskLevel(raw['risk']) ||
        !isOrigin(raw['origin']) ||
        raw['hostPublicKey'] is! String ||
        !isValidPublicKeyBase64Url(raw['hostPublicKey'] as String) ||
        !isHex(raw['hostSignature'], 128)) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'challenge has a missing or invalid required field',
      );
    }
    return ProtocolResult.ok(
      RtqChallenge(
        challengeId: raw['challengeId'] as String,
        capability: raw['capability'] as String,
        capabilityVersion: raw['capabilityVersion'] as int,
        inputHash: raw['inputHash'] as String,
        summary: Map<String, Object?>.from(raw['summary'] as Map),
        risk: raw['risk'] as String,
        policyVersion: raw['policyVersion'] as String,
        origin: raw['origin'] as String,
        application: raw['application'] as String,
        hostId: raw['hostId'] as String,
        hostPublicKey: raw['hostPublicKey'] as String,
        expiresAt: raw['expiresAt'] as int,
        nonce: raw['nonce'] as String,
        hostSignature: raw['hostSignature'] as String,
      ),
    );
  }

  static ProtocolResult<RtqPairingChallenge> parsePairingChallenge(
    String payload,
  ) {
    final env = _parseCommon(payload, [pairingQrPrefix]);
    if (!env.ok) return ProtocolResult.fail(env.code!, env.reason!);
    final raw = env.value!;
    if (raw['kind'] != 'pairing') {
      return ProtocolResult.fail(
        ProtocolError.unknownKind,
        'expected kind "pairing", got "${raw['kind']}"',
      );
    }
    if (!isNonEmptyString(raw['pairingId']) ||
        !isNonEmptyString(raw['hostId']) ||
        !isNonEmptyString(raw['application']) ||
        !isNonEmptyString(raw['nonce']) ||
        (raw['nonce'] as String).length < 16 ||
        raw['expiresAt'] is! int ||
        raw['hostPublicKey'] is! String ||
        !isValidPublicKeyBase64Url(raw['hostPublicKey'] as String) ||
        !isHex(raw['hostSignature'], 128) ||
        (raw['userHint'] != null && raw['userHint'] is! String)) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'pairing challenge has a missing or invalid required field',
      );
    }
    return ProtocolResult.ok(
      RtqPairingChallenge(
        pairingId: raw['pairingId'] as String,
        hostId: raw['hostId'] as String,
        hostPublicKey: raw['hostPublicKey'] as String,
        application: raw['application'] as String,
        userHint: raw['userHint'] as String?,
        expiresAt: raw['expiresAt'] as int,
        nonce: raw['nonce'] as String,
        hostSignature: raw['hostSignature'] as String,
      ),
    );
  }

  static ProtocolResult<RtqSignedApproval> parseSignedApproval(String text) {
    final base = _parseSignedCommon(text, 'approval');
    if (!base.ok) return ProtocolResult.fail(base.code!, base.reason!);
    final raw = base.value!;
    final challenge = raw['challenge'];
    if (challenge is! Map) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'approval.challenge must be an object',
      );
    }
    if (!isNonEmptyString(challenge['challengeId']) ||
        !isNonEmptyString(challenge['capability']) ||
        challenge['capabilityVersion'] is! int ||
        !isHex(challenge['inputHash'], 64) ||
        !isRiskLevel(challenge['risk']) ||
        !isOrigin(challenge['origin']) ||
        !isNonEmptyString(challenge['application']) ||
        !isNonEmptyString(challenge['hostId']) ||
        !isNonEmptyString(challenge['policyVersion']) ||
        challenge['expiresAt'] is! int ||
        !isNonEmptyString(challenge['nonce']) ||
        (raw['decision'] != 'granted' && raw['decision'] != 'denied') ||
        !isHex(raw['deviceId'], 64) ||
        raw['signedAt'] is! int ||
        !isHex(raw['signature'], 128)) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'approval has a missing or invalid required field',
      );
    }
    return ProtocolResult.ok(
      RtqSignedApproval(
        challenge: RtqApprovalBinding(
          challengeId: challenge['challengeId'] as String,
          capability: challenge['capability'] as String,
          capabilityVersion: challenge['capabilityVersion'] as int,
          inputHash: challenge['inputHash'] as String,
          risk: challenge['risk'] as String,
          origin: challenge['origin'] as String,
          application: challenge['application'] as String,
          hostId: challenge['hostId'] as String,
          policyVersion: challenge['policyVersion'] as String,
          expiresAt: challenge['expiresAt'] as int,
          nonce: challenge['nonce'] as String,
        ),
        decision: raw['decision'] as String,
        deviceId: raw['deviceId'] as String,
        signedAt: raw['signedAt'] as int,
        signature: raw['signature'] as String,
      ),
    );
  }

  static ProtocolResult<RtqPairingResponse> parsePairingResponse(String text) {
    final base = _parseSignedCommon(text, 'pairing_response');
    if (!base.ok) return ProtocolResult.fail(base.code!, base.reason!);
    final raw = base.value!;
    final jwk = raw['publicKeyJwk'];
    if (jwk is! Map) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'pairing_response.publicKeyJwk must be an object',
      );
    }
    final x = jwk['x'];
    if (jwk['kty'] != 'OKP' ||
        jwk['crv'] != 'Ed25519' ||
        x is! String ||
        !isValidPublicKeyBase64Url(x) ||
        !isNonEmptyString(raw['pairingId']) ||
        !isNonEmptyString(raw['hostId']) ||
        !isNonEmptyString(raw['nonce']) ||
        !isHex(raw['deviceId'], 64) ||
        !isNonEmptyString(raw['deviceName']) ||
        raw['signedAt'] is! int ||
        !isHex(raw['deviceSignature'], 128)) {
      return ProtocolResult.fail(
        ProtocolError.invalidField,
        'pairing response has a missing or invalid required field',
      );
    }
    return ProtocolResult.ok(
      RtqPairingResponse(
        pairingId: raw['pairingId'] as String,
        hostId: raw['hostId'] as String,
        nonce: raw['nonce'] as String,
        deviceId: raw['deviceId'] as String,
        deviceName: raw['deviceName'] as String,
        publicKeyJwk: <String, Object?>{'kty': 'OKP', 'crv': 'Ed25519', 'x': x},
        signedAt: raw['signedAt'] as int,
        deviceSignature: raw['deviceSignature'] as String,
      ),
    );
  }

  // -------------------------------------------------------------------------
  // Signing / verification
  // -------------------------------------------------------------------------

  /// Verify the host's Ed25519 signature over a challenge.
  ///
  /// When [pinnedHostPublicKey] is provided (a previously paired host), the
  /// challenge's embedded key must match it, so a malicious QR cannot
  /// impersonate the host.
  static Future<bool> verifyHostSignature(
    RtqChallenge challenge, {
    String? pinnedHostPublicKey,
  }) async {
    if (pinnedHostPublicKey != null &&
        challenge.hostPublicKey != pinnedHostPublicKey) {
      return false;
    }
    try {
      final key = decodeCanonicalBase64Url(challenge.hostPublicKey);
      final message = canonicalUtf8(challenge.signingBody());
      return await RtqEd25519.verify(
        key,
        message,
        fromHex(challenge.hostSignature),
      );
    } catch (_) {
      return false;
    }
  }

  static Future<bool> verifyPairingHostSignature(
    RtqPairingChallenge pairing, {
    String? pinnedHostPublicKey,
  }) async {
    if (pinnedHostPublicKey != null &&
        pairing.hostPublicKey != pinnedHostPublicKey) {
      return false;
    }
    try {
      final key = decodeCanonicalBase64Url(pairing.hostPublicKey);
      final message = canonicalUtf8(pairing.signingBody());
      return await RtqEd25519.verify(
        key,
        message,
        fromHex(pairing.hostSignature),
      );
    } catch (_) {
      return false;
    }
  }

  /// Device-side: sign an approval binding the exact challenge fields.
  static Future<RtqSignedApproval> signApproval({
    required RtqChallenge challenge,
    required RtqDeviceKey deviceKey,
    required String decision,
    required int signedAt,
  }) async {
    final binding = challenge.toBinding();
    final unsigned = <String, Object?>{
      'protocol': protocol,
      'version': version,
      'kind': 'approval',
      'challenge': binding.toJson(),
      'decision': decision,
      'deviceId': deviceKey.deviceId,
      'signedAt': signedAt,
    };
    final signature = await RtqEd25519.sign(
      deviceKey.seed,
      canonicalUtf8(unsigned),
    );
    return RtqSignedApproval(
      challenge: binding,
      decision: decision,
      deviceId: deviceKey.deviceId,
      signedAt: signedAt,
      signature: toHex(signature),
    );
  }

  /// Verify a device approval signature and the `deviceId` fingerprint.
  static Future<bool> verifyApprovalSignature(
    RtqSignedApproval approval,
    List<int> publicKey,
  ) async {
    if (publicKey.length != 32) return false;
    if (deviceIdFromPublicKey(publicKey) != approval.deviceId) return false;
    try {
      return await RtqEd25519.verify(
        publicKey,
        canonicalUtf8(approval.signingBody()),
        fromHex(approval.signature),
      );
    } catch (_) {
      return false;
    }
  }

  /// Device-side: sign a pairing response (proves possession of the key).
  static Future<RtqPairingResponse> signPairingResponse({
    required RtqPairingChallenge pairing,
    required RtqDeviceKey deviceKey,
    required String deviceName,
    required int signedAt,
  }) async {
    final jwk = <String, Object?>{
      'kty': 'OKP',
      'crv': 'Ed25519',
      'x': encodeBase64Url(deviceKey.publicKey),
    };
    final unsigned = <String, Object?>{
      'protocol': protocol,
      'version': version,
      'kind': 'pairing_response',
      'pairingId': pairing.pairingId,
      'hostId': pairing.hostId,
      'nonce': pairing.nonce,
      'deviceId': deviceKey.deviceId,
      'deviceName': deviceName,
      'publicKeyJwk': jwk,
      'signedAt': signedAt,
    };
    final signature = await RtqEd25519.sign(
      deviceKey.seed,
      canonicalUtf8(unsigned),
    );
    return RtqPairingResponse(
      pairingId: pairing.pairingId,
      hostId: pairing.hostId,
      nonce: pairing.nonce,
      deviceId: deviceKey.deviceId,
      deviceName: deviceName,
      publicKeyJwk: jwk,
      signedAt: signedAt,
      deviceSignature: toHex(signature),
    );
  }

  /// Host-side: verify a device's pairing signature + ID fingerprint.
  static Future<bool> verifyPairingResponse(RtqPairingResponse response) async {
    final x = response.publicKeyJwk['x'];
    if (x is! String) return false;
    try {
      final publicKey = decodeCanonicalBase64Url(x);
      if (publicKey.length != 32) return false;
      if (deviceIdFromPublicKey(publicKey) != response.deviceId) return false;
      return await RtqEd25519.verify(
        publicKey,
        canonicalUtf8(response.signingBody()),
        fromHex(response.deviceSignature),
      );
    } catch (_) {
      return false;
    }
  }

  // -------------------------------------------------------------------------
  // Internal envelope parsing
  // -------------------------------------------------------------------------

  static ProtocolResult<Map<String, Object?>> _parseCommon(
    String payload,
    List<String> prefixes,
  ) {
    String? matched;
    for (final prefix in prefixes) {
      if (payload.startsWith(prefix)) {
        matched = prefix;
        break;
      }
    }
    if (matched == null) {
      return ProtocolResult.fail(
        ProtocolError.invalidPrefix,
        'payload does not start with a known rtq-approval-v1 prefix',
      );
    }
    final encoded = payload.substring(matched.length);
    String text;
    try {
      text = utf8.decode(decodeCanonicalBase64Url(encoded));
    } catch (_) {
      return ProtocolResult.fail(
        ProtocolError.malformedBase64,
        'payload is not canonical base64url',
      );
    }
    return _parseObjectStrict(text);
  }

  static ProtocolResult<Map<String, Object?>> _parseSignedCommon(
    String text,
    String expectedKind,
  ) {
    final parsed = _parseObjectStrict(text);
    if (!parsed.ok) return parsed;
    final raw = parsed.value!;
    if (raw['protocol'] != rtqApprovalProtocol) {
      return ProtocolResult.fail(
        ProtocolError.unsupportedProtocol,
        'unsupported protocol "${raw['protocol']}"',
      );
    }
    if (raw['version'] != rtqApprovalProtocolVersion) {
      return ProtocolResult.fail(
        ProtocolError.unsupportedVersion,
        'unsupported protocol version "${raw['version']}"',
      );
    }
    if (raw['kind'] != expectedKind) {
      return ProtocolResult.fail(
        ProtocolError.unknownKind,
        'expected kind "$expectedKind", got "${raw['kind']}"',
      );
    }
    return ProtocolResult.ok(raw);
  }

  static ProtocolResult<Map<String, Object?>> _parseObjectStrict(String text) {
    Object? value;
    try {
      value = strictJsonParse(text);
    } on StrictJsonException catch (error) {
      final duplicate = error.message.contains('duplicate object key');
      return ProtocolResult.fail(
        duplicate
            ? ProtocolError.duplicateJsonKey
            : ProtocolError.malformedJson,
        error.message,
      );
    } catch (_) {
      return ProtocolResult.fail(
        ProtocolError.malformedJson,
        'payload is not valid JSON',
      );
    }
    if (value is! Map) {
      return ProtocolResult.fail(
        ProtocolError.payloadNotObject,
        'payload must be a JSON object',
      );
    }
    final raw = Map<String, Object?>.from(value);
    if (raw['protocol'] != rtqApprovalProtocol) {
      return ProtocolResult.fail(
        ProtocolError.unsupportedProtocol,
        'unsupported protocol "${raw['protocol']}"',
      );
    }
    if (raw['version'] != rtqApprovalProtocolVersion) {
      return ProtocolResult.fail(
        ProtocolError.unsupportedVersion,
        'unsupported protocol version "${raw['version']}"',
      );
    }
    return ProtocolResult.ok(raw);
  }
}

// ---------------------------------------------------------------------------
// Small validation helpers (kept file-local)
// ---------------------------------------------------------------------------

bool isNonEmptyString(Object? value) => value is String && value.isNotEmpty;

bool isHex(Object? value, int bytes) =>
    value is String && (bytes == 64 ? _hex64 : _hex128).hasMatch(value);

/// Raw Ed25519 public key bytes from a base64url JWK `x` value.
Uint8List publicKeyBytesFromBase64Url(String x) =>
    Uint8List.fromList(decodeCanonicalBase64Url(x));
