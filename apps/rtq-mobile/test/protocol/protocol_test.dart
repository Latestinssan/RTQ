/// Protocol encode/parse/verify behavior independent of the shared vectors.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/base64url.dart';
import 'package:rtq_mobile/protocol/canonical.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/protocol/errors.dart';
import 'package:rtq_mobile/protocol/models.dart';
import 'package:rtq_mobile/protocol/protocol.dart';

import '../support/rtq_test_helpers.dart';

void main() {
  group('challenge encode/parse', () {
    test('QR payload round trips and verifies against the host key', () async {
      final host = await RtqEd25519.generate();
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'challenge-1',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
      );
      final qr = RtqApprovalProtocol.encodeChallenge(challenge);
      expect(qr, startsWith(challengeQrPrefix));

      final parsed = RtqApprovalProtocol.parseChallenge(qr);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      expect(parsed.value!.challengeId, 'challenge-1');
      expect(parsed.value!.hostPublicKey, encodeBase64Url(host.publicKey));

      final verified = await RtqApprovalProtocol.verifyHostSignature(
        parsed.value!,
        pinnedHostPublicKey: encodeBase64Url(host.publicKey),
      );
      expect(verified, isTrue);
    });

    test('verification fails with a different pinned host key', () async {
      final host = await RtqEd25519.generate();
      final other = await RtqEd25519.generate();
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'challenge-2',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
      );
      final qr = RtqApprovalProtocol.encodeChallenge(challenge);
      final parsed = RtqApprovalProtocol.parseChallenge(qr);
      final verified = await RtqApprovalProtocol.verifyHostSignature(
        parsed.value!,
        pinnedHostPublicKey: encodeBase64Url(other.publicKey),
      );
      expect(verified, isFalse);
    });

    test('rejects a tampered host signature', () async {
      final host = await RtqEd25519.generate();
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'challenge-3',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
      );
      final qr = RtqApprovalProtocol.encodeChallenge(challenge);
      final parsed = RtqApprovalProtocol.parseChallenge(qr);
      final tampered = RtqChallenge(
        challengeId: parsed.value!.challengeId,
        capability: parsed.value!.capability,
        capabilityVersion: parsed.value!.capabilityVersion,
        inputHash: parsed.value!.inputHash,
        summary: parsed.value!.summary,
        risk: parsed.value!.risk,
        policyVersion: parsed.value!.policyVersion,
        origin: parsed.value!.origin,
        application: parsed.value!.application,
        hostId: parsed.value!.hostId,
        hostPublicKey: parsed.value!.hostPublicKey,
        expiresAt: parsed.value!.expiresAt,
        nonce: parsed.value!.nonce,
        hostSignature: 'd${parsed.value!.hostSignature.substring(1)}',
      );
      final verified = await RtqApprovalProtocol.verifyHostSignature(
        tampered,
        pinnedHostPublicKey: encodeBase64Url(host.publicKey),
      );
      expect(verified, isFalse);
    });

    test('rejects non-RTQ, malformed, or invalid payloads with stable codes', () {
      expect(
        RtqApprovalProtocol.parseChallenge('https://example.com/foo').code,
        ProtocolError.invalidPrefix,
      );
      expect(
        RtqApprovalProtocol.parseChallenge('$challengeQrPrefix@@@').code,
        ProtocolError.malformedBase64,
      );
      expect(
        RtqApprovalProtocol.parseChallenge(
          '$challengeQrPrefix${encodeUtf8Base64Url('not json')}',
        ).code,
        ProtocolError.malformedJson,
      );
      expect(
        RtqApprovalProtocol.parseChallenge(
          '$challengeQrPrefix${encodeUtf8Base64Url('{"protocol":"rtq-approval-v1","version":1,"kind":"challenge"}')}',
        ).code,
        ProtocolError.invalidField,
      );
      expect(
        RtqApprovalProtocol.parseChallenge(
          '$challengeQrPrefix${encodeUtf8Base64Url('{"protocol":"other"}')}',
        ).code,
        ProtocolError.unsupportedProtocol,
      );
    });

    test('rejects duplicate JSON keys in the QR envelope', () {
      const dup =
          '{"protocol":"rtq-approval-v1","version":1,"kind":"challenge",'
          '"kind":"challenge"}';
      final result = RtqApprovalProtocol.parseChallenge(
        '$challengeQrPrefix${encodeUtf8Base64Url(dup)}',
      );
      expect(result.code, ProtocolError.duplicateJsonKey);
    });

    test('isSupportedRtqQr accepts only rtq flows', () {
      expect(
        RtqApprovalProtocol.isSupportedRtqQr('rtq://challenge?v=1&c=x'),
        isTrue,
      );
      expect(
        RtqApprovalProtocol.isSupportedRtqQr('rtq://approval?v=1&c=x'),
        isTrue,
      );
      expect(
        RtqApprovalProtocol.isSupportedRtqQr('rtq://pair?v=1&c=x'),
        isTrue,
      );
      expect(RtqApprovalProtocol.isSupportedRtqQr('https://x'), isFalse);
      expect(RtqApprovalProtocol.isSupportedRtqQr(''), isFalse);
    });
  });

  group('signed approval', () {
    test('sign → parse → verify round trip', () async {
      final host = await RtqEd25519.generate();
      final device = await RtqEd25519.generate();
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'approval-1',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
      );
      final approved = await RtqApprovalProtocol.signApproval(
        challenge: challenge,
        deviceKey: device,
        decision: 'granted',
        signedAt: DateTime.now().millisecondsSinceEpoch,
      );

      final json = RtqApprovalProtocol.encodeSignedApproval(approved);
      final parsed = RtqApprovalProtocol.parseSignedApproval(json);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      expect(parsed.value!.decision, 'granted');
      expect(parsed.value!.deviceId, device.deviceId);

      final verified = await RtqApprovalProtocol.verifyApprovalSignature(
        parsed.value!,
        device.publicKey,
      );
      expect(verified, isTrue);
    });

    test('verification fails on wrong public key', () async {
      final host = await RtqEd25519.generate();
      final device = await RtqEd25519.generate();
      final other = await RtqEd25519.generate();
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'approval-2',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
      );
      final approved = await RtqApprovalProtocol.signApproval(
        challenge: challenge,
        deviceKey: device,
        decision: 'granted',
        signedAt: DateTime.now().millisecondsSinceEpoch,
      );
      expect(
        await RtqApprovalProtocol.verifyApprovalSignature(
          approved,
          other.publicKey,
        ),
        isFalse,
      );
    });

    test('parse rejects invalid approval fields', () {
      expect(
        RtqApprovalProtocol.parseSignedApproval(
          '{"protocol":"rtq-approval-v1","version":1,"kind":"approval","decision":"granted"}',
        ).code,
        ProtocolError.invalidField,
      );
      expect(
        RtqApprovalProtocol.parseSignedApproval(
          '{"protocol":"rtq-approval-v1","version":1,"kind":"pairing_response"}',
        ).code,
        ProtocolError.unknownKind,
      );
    });
  });

  group('pairing', () {
    test('pairing QR parse + host verify + response verify', () async {
      final host = await RtqEd25519.generate();
      final device = await RtqEd25519.generate();
      final pairing = await buildSignedPairing(
        hostKey: host,
        pairingId: 'pair-1',
        expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
        userHint: 'pair me',
      );
      final qr = RtqApprovalProtocol.encodePairingChallenge(pairing);
      final parsed = RtqApprovalProtocol.parsePairingChallenge(qr);
      expect(parsed.ok, isTrue, reason: parsed.reason);
      expect(parsed.value!.userHint, 'pair me');
      expect(
        await RtqApprovalProtocol.verifyPairingHostSignature(parsed.value!),
        isTrue,
      );

      final response = await RtqApprovalProtocol.signPairingResponse(
        pairing: parsed.value!,
        deviceKey: device,
        deviceName: 'test device',
        signedAt: DateTime.now().millisecondsSinceEpoch,
      );
      final json = RtqApprovalProtocol.encodePairingResponse(response);
      final parsedResponse = RtqApprovalProtocol.parsePairingResponse(json);
      expect(parsedResponse.ok, isTrue, reason: parsedResponse.reason);
      expect(
        await RtqApprovalProtocol.verifyPairingResponse(parsedResponse.value!),
        isTrue,
      );
    });

    test(
      'pairing response body excludes hostSignature and is canonical',
      () async {
        final host = await RtqEd25519.generate();
        final device = await RtqEd25519.generate();
        final pairing = await buildSignedPairing(
          hostKey: host,
          pairingId: 'pair-2',
          expiresAt: DateTime.now().millisecondsSinceEpoch + 300_000,
        );
        final response = await RtqApprovalProtocol.signPairingResponse(
          pairing: pairing,
          deviceKey: device,
          deviceName: 'd',
          signedAt: 5,
        );
        final body = canonicalStringify(response.signingBody());
        expect(body, isNot(contains('hostSignature')));
        expect(body, isNot(contains('deviceSignature')));
      },
    );
  });
}
