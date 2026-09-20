/// Typed models for `rtq-approval-v1`.
///
/// These are deliberately thin: each model knows how to render its wire JSON and
/// how to validate the shape. The cryptographic rules live in `protocol.dart`.
library;

import 'base64url.dart';

const String rtqApprovalProtocol = 'rtq-approval-v1';
const int rtqApprovalProtocolVersion = 1;

const String challengeQrPrefix = 'rtq://challenge?v=1&c=';
const String approvalQrPrefix = 'rtq://approval?v=1&c=';
const String pairingQrPrefix = 'rtq://pair?v=1&c=';

const List<String> riskLevels = ['low', 'medium', 'high', 'critical'];

const List<String> origins = [
  'local',
  'remote',
  'mobile',
  'plugin',
  'agent',
  'automation',
  'unknown',
];

bool isRiskLevel(Object? value) =>
    value is String && riskLevels.contains(value);

bool isOrigin(Object? value) => value is String && origins.contains(value);

/// A challenge as received in a QR payload (before host-signature verification).
class RtqChallenge {
  const RtqChallenge({
    required this.challengeId,
    required this.capability,
    required this.capabilityVersion,
    required this.inputHash,
    required this.summary,
    required this.risk,
    required this.policyVersion,
    required this.origin,
    required this.application,
    required this.hostId,
    required this.hostPublicKey,
    required this.expiresAt,
    required this.nonce,
    required this.hostSignature,
  });

  final String challengeId;
  final String capability;
  final int capabilityVersion;
  final String inputHash;
  final Map<String, Object?> summary;
  final String risk;
  final String policyVersion;
  final String origin;
  final String application;
  final String hostId;

  /// Raw host Ed25519 public key, base64url.
  final String hostPublicKey;
  final int expiresAt;
  final String nonce;
  final String hostSignature;

  Map<String, Object?> toJson() => <String, Object?>{
    'protocol': rtqApprovalProtocol,
    'version': rtqApprovalProtocolVersion,
    'kind': 'challenge',
    'challengeId': challengeId,
    'capability': capability,
    'capabilityVersion': capabilityVersion,
    'inputHash': inputHash,
    'summary': summary,
    'risk': risk,
    'policyVersion': policyVersion,
    'origin': origin,
    'application': application,
    'hostId': hostId,
    'hostPublicKey': hostPublicKey,
    'expiresAt': expiresAt,
    'nonce': nonce,
    'hostSignature': hostSignature,
  };

  /// The exact object the host signs (no `hostSignature`).
  Map<String, Object?> signingBody() => <String, Object?>{
    'protocol': rtqApprovalProtocol,
    'version': rtqApprovalProtocolVersion,
    'kind': 'challenge',
    'challengeId': challengeId,
    'capability': capability,
    'capabilityVersion': capabilityVersion,
    'inputHash': inputHash,
    'summary': summary,
    'risk': risk,
    'policyVersion': policyVersion,
    'origin': origin,
    'application': application,
    'hostId': hostId,
    'hostPublicKey': hostPublicKey,
    'expiresAt': expiresAt,
    'nonce': nonce,
  };

  /// The subset bound into a device approval.
  RtqApprovalBinding toBinding() => RtqApprovalBinding(
    challengeId: challengeId,
    capability: capability,
    capabilityVersion: capabilityVersion,
    inputHash: inputHash,
    risk: risk,
    origin: origin,
    application: application,
    hostId: hostId,
    policyVersion: policyVersion,
    expiresAt: expiresAt,
    nonce: nonce,
  );
}

class RtqPairingChallenge {
  const RtqPairingChallenge({
    required this.pairingId,
    required this.hostId,
    required this.hostPublicKey,
    required this.application,
    required this.expiresAt,
    required this.nonce,
    required this.hostSignature,
    this.userHint,
  });

  final String pairingId;
  final String hostId;
  final String hostPublicKey;
  final String application;
  final String? userHint;
  final int expiresAt;
  final String nonce;
  final String hostSignature;

  Map<String, Object?> signingBody() => <String, Object?>{
    'protocol': rtqApprovalProtocol,
    'version': rtqApprovalProtocolVersion,
    'kind': 'pairing',
    'pairingId': pairingId,
    'hostId': hostId,
    'hostPublicKey': hostPublicKey,
    'application': application,
    'userHint': userHint,
    'expiresAt': expiresAt,
    'nonce': nonce,
  };

  Map<String, Object?> toJson() => <String, Object?>{
    ...signingBody(),
    'hostSignature': hostSignature,
  };
}

class RtqApprovalBinding {
  const RtqApprovalBinding({
    required this.challengeId,
    required this.capability,
    required this.capabilityVersion,
    required this.inputHash,
    required this.risk,
    required this.origin,
    required this.application,
    required this.hostId,
    required this.policyVersion,
    required this.expiresAt,
    required this.nonce,
  });

  final String challengeId;
  final String capability;
  final int capabilityVersion;
  final String inputHash;
  final String risk;
  final String origin;
  final String application;
  final String hostId;
  final String policyVersion;
  final int expiresAt;
  final String nonce;

  Map<String, Object?> toJson() => <String, Object?>{
    'challengeId': challengeId,
    'capability': capability,
    'capabilityVersion': capabilityVersion,
    'inputHash': inputHash,
    'risk': risk,
    'origin': origin,
    'application': application,
    'hostId': hostId,
    'policyVersion': policyVersion,
    'expiresAt': expiresAt,
    'nonce': nonce,
  };
}

class RtqSignedApproval {
  const RtqSignedApproval({
    required this.challenge,
    required this.decision,
    required this.deviceId,
    required this.signedAt,
    required this.signature,
  });

  final RtqApprovalBinding challenge;
  final String decision;
  final String deviceId;
  final int signedAt;

  /// Ed25519 hex signature by the device.
  final String signature;

  Map<String, Object?> signingBody() => <String, Object?>{
    'protocol': rtqApprovalProtocol,
    'version': rtqApprovalProtocolVersion,
    'kind': 'approval',
    'challenge': challenge.toJson(),
    'decision': decision,
    'deviceId': deviceId,
    'signedAt': signedAt,
  };

  Map<String, Object?> toJson() => <String, Object?>{
    ...signingBody(),
    'signature': signature,
  };
}

class RtqPairingResponse {
  const RtqPairingResponse({
    required this.pairingId,
    required this.hostId,
    required this.nonce,
    required this.deviceId,
    required this.deviceName,
    required this.publicKeyJwk,
    required this.signedAt,
    required this.deviceSignature,
  });

  final String pairingId;
  final String hostId;
  final String nonce;
  final String deviceId;
  final String deviceName;
  final Map<String, Object?> publicKeyJwk;
  final int signedAt;
  final String deviceSignature;

  Map<String, Object?> signingBody() => <String, Object?>{
    'protocol': rtqApprovalProtocol,
    'version': rtqApprovalProtocolVersion,
    'kind': 'pairing_response',
    'pairingId': pairingId,
    'hostId': hostId,
    'nonce': nonce,
    'deviceId': deviceId,
    'deviceName': deviceName,
    'publicKeyJwk': <String, Object?>{
      'kty': publicKeyJwk['kty'],
      'crv': publicKeyJwk['crv'],
      'x': publicKeyJwk['x'],
    },
    'signedAt': signedAt,
  };

  Map<String, Object?> toJson() => <String, Object?>{
    ...signingBody(),
    'deviceSignature': deviceSignature,
  };
}

/// Validate that [value] is the canonical base64url of a 32-byte key.
bool isValidPublicKeyBase64Url(String value) {
  try {
    return decodeCanonicalBase64Url(value).length == 32;
  } catch (_) {
    return false;
  }
}
