/// Approval flow controller (device side).
///
/// State machine over [ApprovalUiState]. Safety properties:
///
///   * the device is never the authorization authority — every approval is
///     signed with the device key and the host independently verifies it;
///   * a QR is only accepted when it parses strictly, carries a host signature
///     that verifies against the PINNED host key, and has not expired;
///   * the PIN is used only to unlock the local device key — it is never sent,
///     stored, logged, or included in any wire payload;
///   * biometrics are an optional second gate; any error fails closed;
///   * approvals bind `challengeId`, capability, capabilityVersion, inputHash,
///     risk, origin, application, hostId, policyVersion, expiresAt and nonce —
///     the host compares these against its own challenge and denies on any
///     mismatch;
///   * any transport error becomes a connection/verification error; the flow
///     never fabricates an approval.
library;

import 'dart:async';

import 'package:flutter/foundation.dart';

import '../protocol/crypto_ed25519.dart';
import '../protocol/errors.dart';
import '../protocol/models.dart';
import '../protocol/protocol.dart';
import '../qr/qr_payload.dart';
import '../security/biometric_gate.dart';
import '../security/device_key_vault.dart';
import '../transport/approval_transport.dart';
import 'approval_state.dart';

class ApprovalController extends ChangeNotifier {
  ApprovalController({
    required DeviceKeyVault vault,
    required BiometricGate biometricGate,
    required ApprovalTransport transport,
    required Future<String?> Function() pinnedHostPublicKey,
    this.requireBiometric = false,
    DateTime Function()? now,
  }) : _vault = vault,
       _biometrics = biometricGate,
       _transport = transport,
       _pinnedHostPublicKey = pinnedHostPublicKey,
       _now = now ?? DateTime.now;

  final DeviceKeyVault _vault;
  final BiometricGate _biometrics;
  final ApprovalTransport _transport;
  final Future<String?> Function() _pinnedHostPublicKey;
  final bool requireBiometric;
  final DateTime Function() _now;

  ApprovalUiState _state = ApprovalUiState.waiting;
  RtqChallenge? _challenge;
  String? _errorCode;
  String? _errorReason;
  String? _deviceId;
  String? _challengeId;
  int? _signedAt;
  String? _decision;
  String _pendingDecision = 'granted';

  ApprovalSnapshot get snapshot => ApprovalSnapshot(
    uiState: _state,
    challenge: _challenge,
    errorCode: _errorCode,
    errorReason: _errorReason,
    deviceId: _deviceId,
    challengeId: _challengeId,
    signedAt: _signedAt,
    decision: _decision,
  );

  ApprovalUiState get state => _state;
  RtqChallenge? get challenge => _challenge;
  String? get errorCode => _errorCode;
  String? get errorReason => _errorReason;

  void _set(ApprovalUiState next) {
    _state = next;
    notifyListeners();
  }

  // -------------------------------------------------------------------------
  // Scan + validate
  // -------------------------------------------------------------------------

  /// Enter the camera scanning state.
  void beginScanning() {
    _set(ApprovalUiState.scanning);
  }

  /// Handle one scanned payload. Fails closed on any problem.
  Future<void> scan(String payload) async {
    _set(ApprovalUiState.scanning);
    if (classifyQrPayload(payload) != QrPayloadKind.challenge) {
      _fail(
        ApprovalUiState.invalidChallenge,
        ProtocolError.invalidPrefix,
        'Not an RTQ approval challenge (this QR is not from the RTQ host).',
      );
      return;
    }
    final parsed = RtqApprovalProtocol.parseChallenge(payload);
    if (!parsed.ok) {
      _fail(
        ApprovalUiState.invalidChallenge,
        parsed.code ?? ProtocolError.invalidField,
        parsed.reason ?? 'Malformed challenge.',
      );
      return;
    }
    final candidate = parsed.requireValue;

    // Not paired => cannot pin the host key, so no challenge can be trusted.
    final pinned = await _pinnedHostPublicKey();
    if (pinned == null || pinned.isEmpty) {
      _errorCode = 'pairing.not_paired';
      _errorReason =
          'This device has no paired host. Pair with the RTQ host first.';
      _set(ApprovalUiState.deviceNotPaired);
      return;
    }

    _set(ApprovalUiState.verifying);
    final hostOk = await RtqApprovalProtocol.verifyHostSignature(
      candidate,
      pinnedHostPublicKey: pinned,
    );
    if (!hostOk) {
      _fail(
        ApprovalUiState.invalidChallenge,
        candidate.hostPublicKey == pinned
            ? ProtocolError.hostSignatureInvalid
            : ProtocolError.hostMismatch,
        candidate.hostPublicKey == pinned
            ? 'The host signature on this challenge does not verify.'
            : 'This QR claims a different host than the one you paired with.',
      );
      return;
    }

    if (_now().millisecondsSinceEpoch >= candidate.expiresAt) {
      _errorCode = ProtocolError.challengeExpired;
      _errorReason =
          'This challenge expired '
          '${(_now().millisecondsSinceEpoch - candidate.expiresAt) ~/ 1000}s ago. '
          'Ask the host for a new one.';
      _set(ApprovalUiState.expired);
      return;
    }

    _challenge = candidate;
    _set(ApprovalUiState.challengeFound);
  }

  /// Move from "challenge found" to the full details review.
  void showApprovalDetails() {
    if (_challenge == null) return;
    _set(ApprovalUiState.approvalDetails);
  }

  /// User asked to approve; require local authentication.
  void requestAuthentication() {
    if (_challenge == null) return;
    _set(ApprovalUiState.authenticationRequired);
  }

  /// User asked to approve — the auth screen will say “approve”.
  void requestApprovalAuthentication() {
    _pendingDecision = 'granted';
    requestAuthentication();
  }

  /// User asked to deny — the auth screen will say “deny”.
  void requestDenialAuthentication() {
    _pendingDecision = 'denied';
    requestAuthentication();
  }

  /// The decision currently being authenticated.
  String get pendingDecision => _pendingDecision;

  /// Submit the pending decision after local auth.
  Future<void> submitWithPin(String pin) =>
      _pendingDecision == 'denied' ? deny(pin) : approve(pin);

  // -------------------------------------------------------------------------
  // Sign + submit
  // -------------------------------------------------------------------------

  /// Local auth (PIN + optional biometrics), then sign and submit.
  Future<void> authorizeAndSubmit(String decision, String pin) async {
    final candidate = _challenge;
    if (candidate == null) {
      _set(ApprovalUiState.waiting);
      return;
    }

    // Fail closed if the challenge expired while the user was reviewing it.
    if (_now().millisecondsSinceEpoch >= candidate.expiresAt) {
      _errorCode = ProtocolError.challengeExpired;
      _errorReason = 'This challenge expired while you were reviewing it.';
      _set(ApprovalUiState.expired);
      return;
    }

    _set(ApprovalUiState.verifying);

    if (requireBiometric) {
      var available = false;
      try {
        available = await _biometrics.isAvailable();
      } catch (_) {
        available = false;
      }
      if (available) {
        final outcome = await _biometrics.authenticate(
          'Verify it is you before approving “${candidate.capability}”.',
        );
        if (outcome != BiometricResult.authenticated) {
          _fail(
            ApprovalUiState.verificationError,
            'biometric.${outcome.name}',
            'Biometric verification did not succeed — approval not signed.',
          );
          return;
        }
      }
    }

    RtqDeviceKey key;
    try {
      key = await _vault.unlock(pin);
    } on WrongPinException {
      _fail(
        ApprovalUiState.verificationError,
        'vault.wrong_pin',
        'The PIN did not unlock this device key.',
      );
      return;
    } on VaultNotInitializedException {
      _errorCode = 'pairing.not_paired';
      _errorReason =
          'This device has no device key yet. Set one up before approving.';
      _set(ApprovalUiState.deviceNotPaired);
      return;
    } catch (_) {
      _fail(
        ApprovalUiState.verificationError,
        'vault.unlock_error',
        'Could not unlock the device key.',
      );
      return;
    }

    _set(ApprovalUiState.signing);
    final signedAt = _now().millisecondsSinceEpoch;
    final approval = await RtqApprovalProtocol.signApproval(
      challenge: candidate,
      deviceKey: key,
      decision: decision,
      signedAt: signedAt,
    );
    final json = RtqApprovalProtocol.encodeSignedApproval(approval);

    _deviceId = key.deviceId;
    _challengeId = candidate.challengeId;
    _signedAt = signedAt;
    _decision = decision;

    final result = await _transport.submitApproval(json);
    if (result.ok) {
      _set(
        decision == 'granted'
            ? ApprovalUiState.approved
            : ApprovalUiState.denied,
      );
      return;
    }
    final code = result.code ?? 'transport.error';
    if (code.startsWith('transport.') ||
        code == ProtocolError.challengeUnknown ||
        code == ProtocolError.challengeRedeemed ||
        code == ProtocolError.challengeExpired) {
      _fail(
        ApprovalUiState.connectionError,
        code,
        result.reason ?? 'The host did not accept the approval.',
      );
    } else {
      _fail(
        ApprovalUiState.verificationError,
        code,
        result.reason ?? 'The host rejected the approval.',
      );
    }
  }

  /// Approve the current challenge (device denies on the host if rejected).
  Future<void> approve(String pin) => authorizeAndSubmit('granted', pin);

  /// Sign and submit a denial so the host records it immediately.
  Future<void> deny(String pin) async {
    await authorizeAndSubmit('denied', pin);
    // The local decision is a denial regardless of transport outcome: the host
    // already has the challenge; a missing submission times out to the same
    // denial. Only an unauthenticated local failure stays an error.
    if (_state == ApprovalUiState.connectionError ||
        _state == ApprovalUiState.verificationError ||
        _state == ApprovalUiState.approved) {
      _decision = 'denied';
      _set(ApprovalUiState.denied);
    }
  }

  void reset() {
    _challenge = null;
    _errorCode = null;
    _errorReason = null;
    _deviceId = null;
    _challengeId = null;
    _signedAt = null;
    _decision = null;
    _set(ApprovalUiState.waiting);
  }

  void _fail(ApprovalUiState state, String code, String reason) {
    _errorCode = code;
    _errorReason = reason;
    _set(state);
  }
}
