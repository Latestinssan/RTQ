/// Shared helpers for building valid signed protocol objects in tests.
///
/// Everything here mirrors what the host does: sign the canonical signing body
/// with an Ed25519 private seed. TEST KEYS ONLY — real keys are generated
/// on-device and never written to files.
library;

import 'package:rtq_mobile/protocol/base64url.dart';
import 'package:rtq_mobile/protocol/canonical.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/protocol/models.dart';

final _baseSummary = <String, Object?>{
  'action': 'Delete file',
  'path': '/workspace/secret.txt',
  'reversible': false,
};

/// An unsigned challenge object ready to be host-signed.
RtqChallenge buildChallengeUnsigned({
  required RtqDeviceKey hostKey,
  required String challengeId,
  required int expiresAt,
  String capability = 'files.delete',
  String risk = 'high',
  String hostId = 'rtq-host-01',
  String application = 'RTQ Desktop',
  String policyVersion = 'policy-v3',
  String origin = 'local',
  String inputHash =
      '2c98b3df041868746630bda0015a842d0df6a47168a98943b2eb4911fbf67e8b',
  String nonce = '0123456789abcdef0123456789abcdef',
  Map<String, Object?>? summary,
}) {
  return RtqChallenge(
    challengeId: challengeId,
    capability: capability,
    capabilityVersion: 1,
    inputHash: inputHash,
    summary: summary ?? _baseSummary,
    risk: risk,
    policyVersion: policyVersion,
    origin: origin,
    application: application,
    hostId: hostId,
    hostPublicKey: encodeBase64Url(hostKey.publicKey),
    expiresAt: expiresAt,
    nonce: nonce,
    hostSignature: '',
  );
}

/// A host-signed challenge (as the host would encode into a QR).
Future<RtqChallenge> buildSignedChallenge({
  required RtqDeviceKey hostKey,
  required String challengeId,
  required int expiresAt,
  String capability = 'files.delete',
  String risk = 'high',
  String hostId = 'rtq-host-01',
  String application = 'RTQ Desktop',
  String policyVersion = 'policy-v3',
  String origin = 'local',
  String inputHash =
      '2c98b3df041868746630bda0015a842d0df6a47168a98943b2eb4911fbf67e8b',
  String nonce = '0123456789abcdef0123456789abcdef',
  Map<String, Object?>? summary,
}) async {
  final unsigned = buildChallengeUnsigned(
    hostKey: hostKey,
    challengeId: challengeId,
    expiresAt: expiresAt,
    capability: capability,
    risk: risk,
    hostId: hostId,
    application: application,
    policyVersion: policyVersion,
    origin: origin,
    inputHash: inputHash,
    nonce: nonce,
    summary: summary,
  );
  final signature = await RtqEd25519.sign(
    hostKey.seed,
    canonicalUtf8(unsigned.signingBody()),
  );
  return RtqChallenge(
    challengeId: challengeId,
    capability: capability,
    capabilityVersion: 1,
    inputHash: inputHash,
    summary: summary ?? _baseSummary,
    risk: risk,
    policyVersion: policyVersion,
    origin: origin,
    application: application,
    hostId: hostId,
    hostPublicKey: encodeBase64Url(hostKey.publicKey),
    expiresAt: expiresAt,
    nonce: nonce,
    hostSignature: toHex(signature),
  );
}

RtqPairingChallenge buildPairingUnsigned({
  required RtqDeviceKey hostKey,
  required String pairingId,
  required int expiresAt,
  String hostId = 'rtq-host-01',
  String application = 'RTQ Desktop',
  String nonce = 'fedcba9876543210fedcba9876543210',
  String? userHint,
}) {
  return RtqPairingChallenge(
    pairingId: pairingId,
    hostId: hostId,
    hostPublicKey: encodeBase64Url(hostKey.publicKey),
    application: application,
    userHint: userHint,
    expiresAt: expiresAt,
    nonce: nonce,
    hostSignature: '',
  );
}

Future<RtqPairingChallenge> buildSignedPairing({
  required RtqDeviceKey hostKey,
  required String pairingId,
  required int expiresAt,
  String hostId = 'rtq-host-01',
  String application = 'RTQ Desktop',
  String nonce = 'fedcba9876543210fedcba9876543210',
  String? userHint,
}) async {
  final unsigned = buildPairingUnsigned(
    hostKey: hostKey,
    pairingId: pairingId,
    expiresAt: expiresAt,
    hostId: hostId,
    application: application,
    nonce: nonce,
    userHint: userHint,
  );
  final signature = await RtqEd25519.sign(
    hostKey.seed,
    canonicalUtf8(unsigned.signingBody()),
  );
  return RtqPairingChallenge(
    pairingId: pairingId,
    hostId: hostId,
    hostPublicKey: encodeBase64Url(hostKey.publicKey),
    application: application,
    userHint: userHint,
    expiresAt: expiresAt,
    nonce: nonce,
    hostSignature: toHex(signature),
  );
}
