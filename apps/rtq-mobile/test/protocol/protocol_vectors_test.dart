/// Cross-implementation vector tests.
///
/// The vectors in `protocol/rtq-approval-v1.vectors.json` are produced by the
/// TypeScript implementation and consumed here byte-for-byte: canonical bodies,
/// host signatures and device signatures must all match identically. Ed25519 is
/// deterministic (RFC 8032), so re-signing in Dart must reproduce the exact
/// signature bytes the Node host produced.
library;

import 'dart:convert';
import 'dart:io';

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/base64url.dart';
import 'package:rtq_mobile/protocol/canonical.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/protocol/models.dart';
import 'package:rtq_mobile/protocol/protocol.dart';

File _findVectorsFile() {
  final candidates = <String>[
    '${Directory.current.path}/../../protocol/rtq-approval-v1.vectors.json',
    '${Directory.current.path}/protocol/rtq-approval-v1.vectors.json',
  ];
  for (final path in candidates) {
    final file = File(path);
    if (file.existsSync()) return file;
  }
  fail(
    'Missing shared vectors file (tried $candidates). '
    'Generate with: RTQ_WRITE_VECTORS=1 npx vitest run tests/protocol/generate-vectors.test.ts',
  );
}

Map<String, Object?> _loadVectors() {
  return Map<String, Object?>.from(
    jsonDecode(_findVectorsFile().readAsStringSync()) as Map,
  );
}

Map<String, Object?> _keys(Map<String, Object?> top) =>
    Map<String, Object?>.from(top['keys'] as Map);

Map<String, Object?> _key(Map<String, Object?> keys, String name) =>
    Map<String, Object?>.from(keys[name] as Map);

Map<String, Object?> _jwk(Map<String, Object?> keyHolder, String field) =>
    Map<String, Object?>.from(keyHolder[field] as Map);

/// The 32-byte Ed25519 seed from a private JWK `d` value.
List<int> _seedFromJwk(Map<String, Object?> jwk) =>
    decodeCanonicalBase64Url(jwk['d'] as String);

void main() {
  final vectors = _loadVectors();
  final keys = _keys(vectors);
  final host = _jwk(_key(keys, 'host'), 'publicKeyJwk');
  final deviceA = _key(keys, 'deviceA');
  final deviceB = _key(keys, 'deviceB');
  final hostX = host['x'] as String;
  final deviceAX = _jwk(deviceA, 'publicKeyJwk')['x'] as String;
  final deviceBX = _jwk(deviceB, 'publicKeyJwk')['x'] as String;

  group('canonical stringify examples', () {
    final examples = (vectors['canonicalStringifyExamples']! as List)
        .cast<Map>();
    for (var i = 0; i < examples.length; i++) {
      test('example $i', () {
        final example = Map<String, Object?>.from(
          examples[i] as Map<Object?, Object?>,
        );
        expect(canonicalStringify(example['input']), example['canonical']);
      });
    }
  });

  group('challenge vectors', () {
    final challenge = Map<String, Object?>.from(vectors['challenge']! as Map);
    final qrPayload = challenge['qrPayload'] as String;
    final expectedSigningBody = challenge['signingBody'] as String;
    final expectedHostSignature = challenge['hostSignature'] as String;

    test('QR payload parses strictly', () {
      final parsed = RtqApprovalProtocol.parseChallenge(qrPayload);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      expect(parsed.value!.challengeId, isNotEmpty);
      expect(parsed.value!.hostPublicKey, hostX);
    });

    test('host signature verifies against the host key', () async {
      final parsed = RtqApprovalProtocol.parseChallenge(qrPayload);
      final ok = await RtqApprovalProtocol.verifyHostSignature(
        parsed.value!,
        pinnedHostPublicKey: hostX,
      );
      expect(ok, isTrue);
    });

    test('canonical signing body matches TypeScript exactly', () {
      final parsed = RtqApprovalProtocol.parseChallenge(qrPayload);
      expect(
        canonicalStringify(parsed.value!.signingBody()),
        expectedSigningBody,
      );
      expect(parsed.value!.hostSignature, expectedHostSignature);
    });

    test('verification fails when the pinned key differs', () async {
      final parsed = RtqApprovalProtocol.parseChallenge(qrPayload);
      final ok = await RtqApprovalProtocol.verifyHostSignature(
        parsed.value!,
        pinnedHostPublicKey: deviceAX,
      );
      expect(ok, isFalse);
    });
  });

  group('device approval vectors', () {
    final granted = Map<String, Object?>.from(
      (vectors['approvals']! as Map)['granted']! as Map,
    );
    final denied = Map<String, Object?>.from(
      (vectors['approvals']! as Map)['denied']! as Map,
    );

    void checkApproval(
      String label,
      Map<String, Object?> vector,
      Map<String, Object?> keyHolder,
      String expectedDeviceId,
      String expectedDeviceX,
    ) {
      final unsigned = Map<String, Object?>.from(vector['unsigned']! as Map);
      final expectedSignature = vector['signature'] as String;
      final expectedSigningBody = vector['signingBody'] as String;
      final seed = _seedFromJwk(_jwk(keyHolder, 'privateKeyJwk'));
      final challenge = Map<String, Object?>.from(
        unsigned['challenge']! as Map,
      );

      test('$label: deviceId matches the key fingerprint', () async {
        final device = await RtqEd25519.fromSeed(seed);
        expect(device.deviceId, expectedDeviceId);
        expect(base64UrlEncode(device.publicKey), expectedDeviceX);
      });

      test(
        '$label: re-signing reproduces the exact vector signature',
        () async {
          final binding = RtqApprovalBinding(
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
          );
          final approval = RtqSignedApproval(
            challenge: binding,
            decision: unsigned['decision'] as String,
            deviceId: unsigned['deviceId'] as String,
            signedAt: unsigned['signedAt'] as int,
            signature: '',
          );
          expect(
            canonicalStringify(approval.signingBody()),
            expectedSigningBody,
          );
          final signature = await RtqEd25519.sign(
            seed,
            canonicalUtf8(approval.signingBody()),
          );
          expect(
            toHex(signature),
            expectedSignature,
            reason: 'Dart Ed25519 must match Node Ed25519 byte-for-byte',
          );
        },
      );

      test('$label: vector JSON parses and verifies', () async {
        final approved = RtqSignedApproval(
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
          decision: unsigned['decision'] as String,
          deviceId: unsigned['deviceId'] as String,
          signedAt: unsigned['signedAt'] as int,
          signature: expectedSignature,
        );
        final json = RtqApprovalProtocol.encodeSignedApproval(approved);
        final parsed = RtqApprovalProtocol.parseSignedApproval(json);
        expect(parsed.ok, isTrue, reason: parsed.reason);
        final verified = await RtqApprovalProtocol.verifyApprovalSignature(
          parsed.value!,
          devicePublicKey(keyHolder),
        );
        expect(verified, isTrue);
      });
    }

    group('granted (deviceA)', () {
      checkApproval(
        'granted',
        granted,
        deviceA,
        'f95dbe3083fd842807089d1ffd980c7e7774b13e3bd5352b1e2cedcd8930aca5',
        deviceAX,
      );
    });

    group('denied (deviceB)', () {
      checkApproval(
        'denied',
        denied,
        deviceB,
        '571fab4093c51c4fb320441b1c7181e8b2218ee263ac9cba095f19d24a9c0a54',
        deviceBX,
      );
    });
  });

  group('pairing vectors', () {
    final pairing = Map<String, Object?>.from(vectors['pairing']! as Map);
    final qrPayload = pairing['qrPayload'] as String;
    final responseMap = Map<String, Object?>.from(pairing['response']! as Map);
    final responseUnsigned = Map<String, Object?>.from(
      responseMap['unsigned']! as Map,
    );

    test('pairing QR parses and host signature verifies', () async {
      final parsed = RtqApprovalProtocol.parsePairingChallenge(qrPayload);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      expect(parsed.value!.hostPublicKey, hostX);
      expect(
        await RtqApprovalProtocol.verifyPairingHostSignature(parsed.value!),
        isTrue,
      );
      expect(
        canonicalStringify(parsed.value!.signingBody()),
        pairing['signingBody'],
      );
    });

    test(
      'device pair response re-signs to the exact vector signature',
      () async {
        final responseSigningBody = responseMap['signingBody'] as String;
        final expectedDeviceSignature =
            responseMap['deviceSignature'] as String;
        final jwk = Map<String, Object?>.from(
          responseUnsigned['publicKeyJwk']! as Map,
        );
        final seed = _seedFromJwk(_jwk(deviceA, 'privateKeyJwk'));
        final device = await RtqEd25519.fromSeed(seed);

        final response = RtqPairingResponse(
          pairingId: responseUnsigned['pairingId'] as String,
          hostId: responseUnsigned['hostId'] as String,
          nonce: responseUnsigned['nonce'] as String,
          deviceId: responseUnsigned['deviceId'] as String,
          deviceName: responseUnsigned['deviceName'] as String,
          publicKeyJwk: <String, Object?>{
            'kty': jwk['kty'],
            'crv': jwk['crv'],
            'x': jwk['x'],
          },
          signedAt: responseUnsigned['signedAt'] as int,
          deviceSignature: '',
        );
        expect(canonicalStringify(response.signingBody()), responseSigningBody);
        final signature = await RtqEd25519.sign(
          seed,
          canonicalUtf8(response.signingBody()),
        );
        expect(toHex(signature), expectedDeviceSignature);
        expect(device.deviceId, responseUnsigned['deviceId']);
      },
    );

    test('vector response JSON parses and verifies', () async {
      final text = responseMap['json'] as String;
      final parsed = RtqApprovalProtocol.parsePairingResponse(text);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      final verified = await RtqApprovalProtocol.verifyPairingResponse(
        parsed.value!,
      );
      expect(verified, isTrue);
    });
  });
}

/// Public key bytes from a publicKeyJwk holder map.
List<int> devicePublicKey(Map<String, Object?> keyHolder) =>
    decodeCanonicalBase64Url(_jwk(keyHolder, 'publicKeyJwk')['x'] as String);

String base64UrlEncode(List<int> bytes) => encodeBase64Url(bytes);
