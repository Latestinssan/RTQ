/// Approval controller state machine end-to-end (device side), driven with
/// fakes: in-memory store, fake biometrics, fake transport, fixed clock.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/approval/approval_controller.dart';
import 'package:rtq_mobile/approval/approval_state.dart';
import 'package:rtq_mobile/pairing/pairing_store.dart';
import 'package:rtq_mobile/protocol/base64url.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/protocol/errors.dart';
import 'package:rtq_mobile/protocol/protocol.dart';
import 'package:rtq_mobile/security/biometric_gate.dart';
import 'package:rtq_mobile/security/device_key_vault.dart';
import 'package:rtq_mobile/security/secure_store.dart';
import 'package:rtq_mobile/transport/approval_transport.dart';

import '../support/rtq_test_helpers.dart';

const String _pin = '135790';
const int _t0 = 1750000000000;

/// Mutable clock box so tests can move time without rebuilding the controller.
class ClockBox {
  int t = _t0;
}

class TestHarness {
  TestHarness({
    required this.vault,
    required this.pairingStore,
    required this.transport,
    required this.controller,
    required this.biometrics,
    required this.clock,
  });

  final DeviceKeyVault vault;
  final PairingStore pairingStore;
  final FakeApprovalTransport transport;
  final ApprovalController controller;
  final FakeBiometricGate biometrics;
  final ClockBox clock;
}

Future<TestHarness> make({
  bool requireBiometric = false,
  BiometricResult biometricResult = BiometricResult.authenticated,
}) async {
  final store = InMemorySecureStore();
  final vault = DeviceKeyVault(store: store, pbkdf2Iterations: 500);
  await vault.create(_pin);
  final pairingStore = PairingStore(store);
  final transport = FakeApprovalTransport();
  final biometrics = FakeBiometricGate(result: biometricResult);
  final clock = ClockBox();
  final controller = ApprovalController(
    vault: vault,
    biometricGate: biometrics,
    transport: transport,
    pinnedHostPublicKey: pairingStore.pinnedHostPublicKey,
    requireBiometric: requireBiometric,
    now: () => DateTime.fromMillisecondsSinceEpoch(clock.t),
  );
  return TestHarness(
    vault: vault,
    pairingStore: pairingStore,
    transport: transport,
    controller: controller,
    biometrics: biometrics,
    clock: clock,
  );
}

void main() {
  test('non-RTQ QR is rejected as invalid challenge', () async {
    final h = await make();
    await h.controller.scan('https://evil.example/approve');
    expect(h.controller.state, ApprovalUiState.invalidChallenge);
    expect(h.controller.errorCode, ProtocolError.invalidPrefix);
  });

  test('malformed RTQ QR is rejected', () async {
    final h = await make();
    await h.controller.scan('rtq://challenge?v=1&c=@@@');
    expect(h.controller.state, ApprovalUiState.invalidChallenge);
  });

  test('valid challenge on an unpaired device cannot be trusted', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-unpaired',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    expect(h.controller.state, ApprovalUiState.deviceNotPaired);
  });

  test(
    'challenge signed by a different host is rejected (hostMismatch)',
    () async {
      final h = await make();
      final pairedHost = await RtqEd25519.generate();
      final attacker = await RtqEd25519.generate();
      await h.pairingStore.save(
        PairedHostRecord(
          hostId: 'host-1',
          hostPublicKey: encodeBase64Url(pairedHost.publicKey),
          application: 'RTQ Test',
          pairedAt: _t0,
        ),
      );
      final challenge = await buildSignedChallenge(
        hostKey: attacker,
        challengeId: 'c-spoof',
        expiresAt: _t0 + 300_000,
      );
      await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
      expect(h.controller.state, ApprovalUiState.invalidChallenge);
      expect(h.controller.errorCode, ProtocolError.hostMismatch);
    },
  );

  test('expired challenge is rejected even by the paired host', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-expired',
      expiresAt: _t0 - 1,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    expect(h.controller.state, ApprovalUiState.expired);
    expect(h.controller.errorCode, ProtocolError.challengeExpired);
  });

  test(
    'happy path: scan → details → auth → approved, binding intact',
    () async {
      final h = await make();
      final host = await RtqEd25519.generate();
      await h.pairingStore.save(
        PairedHostRecord(
          hostId: 'host-1',
          hostPublicKey: encodeBase64Url(host.publicKey),
          application: 'RTQ Test',
          pairedAt: _t0,
        ),
      );
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'c-ok',
        expiresAt: _t0 + 300_000,
      );
      await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
      expect(h.controller.state, ApprovalUiState.challengeFound);

      h.controller.showApprovalDetails();
      expect(h.controller.state, ApprovalUiState.approvalDetails);

      h.controller.requestApprovalAuthentication();
      expect(h.controller.state, ApprovalUiState.authenticationRequired);

      await h.controller.approve(_pin);
      expect(h.controller.state, ApprovalUiState.approved);

      final json = h.transport.submittedApprovals.single;
      final parsed = RtqApprovalProtocol.parseSignedApproval(json);
      expect(parsed.ok, isTrue, reason: parsed.reason);

      final deviceKey = await h.vault.unlock(_pin);
      expect(parsed.value!.decision, 'granted');
      expect(parsed.value!.deviceId, deviceKey.deviceId);
      expect(
        await RtqApprovalProtocol.verifyApprovalSignature(
          parsed.value!,
          deviceKey.publicKey,
        ),
        isTrue,
      );

      // The approval binds the exact challenge fields.
      final binding = parsed.value!.challenge;
      expect(binding.challengeId, challenge.challengeId);
      expect(binding.capability, challenge.capability);
      expect(binding.capabilityVersion, challenge.capabilityVersion);
      expect(binding.inputHash, challenge.inputHash);
      expect(binding.risk, challenge.risk);
      expect(binding.origin, challenge.origin);
      expect(binding.application, challenge.application);
      expect(binding.hostId, challenge.hostId);
      expect(binding.policyVersion, challenge.policyVersion);
      expect(binding.expiresAt, challenge.expiresAt);
      expect(binding.nonce, challenge.nonce);
    },
  );

  test('wrong PIN blocks signing (verification error)', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-pin',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    h.controller.requestApprovalAuthentication();
    await h.controller.approve('000000');
    expect(h.controller.state, ApprovalUiState.verificationError);
    expect(h.controller.errorCode, 'vault.wrong_pin');
    expect(h.transport.submitCalls, 0);
  });

  test('required biometrics failing blocks signing', () async {
    final h = await make(
      requireBiometric: true,
      biometricResult: BiometricResult.failed,
    );
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-bio',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    h.controller.requestApprovalAuthentication();
    await h.controller.approve(_pin);
    expect(h.controller.state, ApprovalUiState.verificationError);
    expect(h.controller.errorCode, 'biometric.failed');
    expect(h.transport.submitCalls, 0);
    expect(h.biometrics.calls, 1);
  });

  test(
    'transport failure is a connection error, nothing is fabricated',
    () async {
      final h = await make();
      h.transport.submitResult = const TransportResult.fail(
        'transport.connection_error',
        'offline',
      );
      final host = await RtqEd25519.generate();
      await h.pairingStore.save(
        PairedHostRecord(
          hostId: 'host-1',
          hostPublicKey: encodeBase64Url(host.publicKey),
          application: 'RTQ Test',
          pairedAt: _t0,
        ),
      );
      final challenge = await buildSignedChallenge(
        hostKey: host,
        challengeId: 'c-net',
        expiresAt: _t0 + 300_000,
      );
      await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
      h.controller.requestApprovalAuthentication();
      await h.controller.approve(_pin);
      expect(h.controller.state, ApprovalUiState.connectionError);
      expect(h.controller.errorCode, 'transport.connection_error');
    },
  );

  test('deny signs and submits a denied approval', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-deny',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    h.controller.requestDenialAuthentication();
    await h.controller.deny(_pin);
    expect(h.controller.state, ApprovalUiState.denied);

    final parsed = RtqApprovalProtocol.parseSignedApproval(
      h.transport.submittedApprovals.single,
    );
    expect(parsed.value!.decision, 'denied');
    expect(parsed.value!.challenge.challengeId, 'c-deny');
  });

  test('challenge expiring mid-review fails closed at submit', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-expiring',
      expiresAt: _t0 + 1000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    expect(h.controller.state, ApprovalUiState.challengeFound);

    h.clock.t = _t0 + 5000; // the user took too long
    h.controller.requestApprovalAuthentication();
    await h.controller.approve(_pin);
    expect(h.controller.state, ApprovalUiState.expired);
    expect(h.controller.errorCode, ProtocolError.challengeExpired);
    expect(h.transport.submitCalls, 0);
  });

  test('reset returns to waiting and clears state', () async {
    final h = await make();
    final host = await RtqEd25519.generate();
    await h.pairingStore.save(
      PairedHostRecord(
        hostId: 'host-1',
        hostPublicKey: encodeBase64Url(host.publicKey),
        application: 'RTQ Test',
        pairedAt: _t0,
      ),
    );
    final challenge = await buildSignedChallenge(
      hostKey: host,
      challengeId: 'c-reset',
      expiresAt: _t0 + 300_000,
    );
    await h.controller.scan(RtqApprovalProtocol.encodeChallenge(challenge));
    expect(h.controller.state, ApprovalUiState.challengeFound);
    h.controller.reset();
    expect(h.controller.state, ApprovalUiState.waiting);
    expect(h.controller.challenge, isNull);
  });
}
