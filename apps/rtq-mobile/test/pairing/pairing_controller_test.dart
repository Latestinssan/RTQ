/// Pairing controller: scan → verify host signature → review → PIN → sign →
/// submit → persist pinned host. Fail-closed on wrong PIN, bad signatures,
/// expiry, or replay of an already-paired host.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/pairing/pairing_controller.dart';
import 'package:rtq_mobile/pairing/pairing_store.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/protocol/errors.dart';
import 'package:rtq_mobile/protocol/models.dart';
import 'package:rtq_mobile/protocol/protocol.dart';
import 'package:rtq_mobile/security/device_key_vault.dart';
import 'package:rtq_mobile/security/secure_store.dart';
import 'package:rtq_mobile/transport/approval_transport.dart';

import '../support/rtq_test_helpers.dart';

const String _pin = '135790';
const int _t0 = 1750000000000;

class TestHarness {
  TestHarness({
    required this.vault,
    required this.pairingStore,
    required this.transport,
    required this.controller,
    required this.clock,
  });

  final DeviceKeyVault vault;
  final PairingStore pairingStore;
  final FakeApprovalTransport transport;
  final PairingController controller;
  int clock;
}

Future<TestHarness> make({bool createKey = true}) async {
  final store = InMemorySecureStore();
  final vault = DeviceKeyVault(store: store, pbkdf2Iterations: 500);
  if (createKey) await vault.create(_pin);
  final pairingStore = PairingStore(store);
  final transport = FakeApprovalTransport();
  var clock = _t0;
  final controller = PairingController(
    vault: vault,
    transport: transport,
    store: pairingStore,
    now: () => DateTime.fromMillisecondsSinceEpoch(clock),
  );
  return TestHarness(
    vault: vault,
    pairingStore: pairingStore,
    transport: transport,
    controller: controller,
    clock: 0,
  )..clock = clock;
}

String _qr(RtqPairingChallenge pairing) =>
    RtqApprovalProtocol.encodePairingChallenge(pairing);

void main() {
  test('non-RTQ payload is rejected', () async {
    final h = await make();
    await h.controller.scan('https://example.com/x');
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, ProtocolError.invalidPrefix);
  });

  test('malformed RTQ pairing QR is rejected', () async {
    final h = await make();
    await h.controller.scan('rtq://pair?v=1&c=@@@');
    expect(h.controller.state, PairingUiState.failed);
  });

  test('host signature tampering is rejected', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-tamper',
      expiresAt: _t0 + 300_000,
    );
    // Flip one hex nibble in the host signature.
    final tampered = RtqPairingChallenge(
      pairingId: pairing.pairingId,
      hostId: pairing.hostId,
      hostPublicKey: pairing.hostPublicKey,
      application: pairing.application,
      userHint: pairing.userHint,
      expiresAt: pairing.expiresAt,
      nonce: pairing.nonce,
      hostSignature:
          (pairing.hostSignature[0] == 'd' ? 'e' : 'd') +
          pairing.hostSignature.substring(1),
    );
    await h.controller.scan(_qr(tampered));
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, ProtocolError.pairingSignatureInvalid);
  });

  test('expired pairing QR is rejected', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-expired',
      expiresAt: _t0 - 1,
    );
    await h.controller.scan(_qr(pairing));
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, ProtocolError.pairingExpired);
  });

  test(
    're-scanning a host the device is already paired with is rejected',
    () async {
      final h = await make();
      final host = await RtqEd25519.generate();
      final pairing = await buildSignedPairing(
        hostKey: host,
        pairingId: 'pair-replay',
        expiresAt: _t0 + 300_000,
      );
      await h.controller.scan(_qr(pairing));
      expect(h.controller.state, PairingUiState.pairingReady);
      h.controller.showDetails();
      await h.controller.complete(_pin, deviceName: 'test device');
      expect(h.controller.state, PairingUiState.complete);

      // The same host QR again must be refused (pairing is single-use).
      await h.controller.scan(_qr(pairing));
      expect(h.controller.state, PairingUiState.failed);
      expect(h.controller.errorCode, ProtocolError.pairingRedeemed);
    },
  );

  test(
    'happy path persists the pinned host and submits a verifiable response',
    () async {
      final h = await make();
      final host = await RtqEd25519.generate();
      final pairing = await buildSignedPairing(
        hostKey: host,
        pairingId: 'pair-ok',
        expiresAt: _t0 + 300_000,
        userHint: 'desk host',
      );
      await h.controller.scan(_qr(pairing));
      expect(h.controller.state, PairingUiState.pairingReady);
      expect(h.controller.pairing!.userHint, 'desk host');

      h.controller.showDetails();
      expect(h.controller.state, PairingUiState.details);

      await h.controller.complete(_pin, deviceName: 'my phone');
      expect(h.controller.state, PairingUiState.complete);
      expect(h.transport.completeCalls, 1);

      final record = await h.pairingStore.read();
      expect(record, isNotNull);
      expect(record!.hostId, pairing.hostId);
      expect(record.hostPublicKey, pairing.hostPublicKey);

      // The submitted response is signed by the device key and verifies.
      final parsed = RtqApprovalProtocol.parsePairingResponse(
        h.transport.completedResponses.single,
      );
      expect(parsed.ok, isTrue, reason: parsed.reason);
      final deviceKey = await h.vault.unlock(_pin);
      expect(parsed.value!.deviceId, deviceKey.deviceId);
      expect(parsed.value!.deviceName, 'my phone');
      expect(
        await RtqApprovalProtocol.verifyPairingResponse(parsed.value!),
        isTrue,
      );
    },
  );

  test('wrong PIN refuses pairing', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-pin',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(_qr(pairing));
    h.controller.showDetails();
    await h.controller.complete('000000', deviceName: 'x');
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, 'vault.wrong_pin');
    expect(h.transport.completeCalls, 0);
    expect(await h.pairingStore.read(), isNull);
  });

  test('no device key yet fails closed with setup.required', () async {
    final h = await make(createKey: false);
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-setup',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(_qr(pairing));
    h.controller.showDetails();
    await h.controller.complete(_pin, deviceName: 'x');
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, 'setup.required');
  });

  test('host rejection surfaces the host code', () async {
    final h = await make();
    h.transport.completeResult = const TransportResult.fail(
      'pairing.signature_invalid',
      'the host refused',
    );
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-reject',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(_qr(pairing));
    h.controller.showDetails();
    await h.controller.complete(_pin, deviceName: 'x');
    expect(h.controller.state, PairingUiState.failed);
    expect(h.controller.errorCode, 'pairing.signature_invalid');
    expect(await h.pairingStore.read(), isNull);
  });

  test('unpair clears the pinned host', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    final pairing = await buildSignedPairing(
      hostKey: host,
      pairingId: 'pair-unpair',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(_qr(pairing));
    h.controller.showDetails();
    await h.controller.complete(_pin, deviceName: 'x');
    expect(await h.pairingStore.read(), isNotNull);

    await h.controller.unpair();
    expect(h.controller.state, PairingUiState.waiting);
    expect(await h.pairingStore.read(), isNull);
  });
}
