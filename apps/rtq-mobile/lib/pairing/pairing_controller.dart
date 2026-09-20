/// Pairing flow controller.
///
/// Pairing establishes the trust anchor: the device pins the host's Ed25519
/// public key (from a host-signed pairing QR, never changed by a later
/// challenge QR). This controller drives:
///
///   scan (pairing QR)
///     → strict parse → host-signature verification → expiry check
///     → review details → local auth → sign pairing response
///     → submit to host → persist pinned host record.
///
/// Nothing sensitive ever moves over the pairing channel: the device sends its
/// public key and a device signature proving key possession; the private seed
/// and PIN stay on-device.
library;

import 'package:flutter/foundation.dart';

import '../protocol/crypto_ed25519.dart';
import '../protocol/errors.dart';
import '../protocol/models.dart';
import '../protocol/protocol.dart';
import '../qr/qr_payload.dart';
import '../security/device_key_vault.dart';
import '../transport/approval_transport.dart';
import 'pairing_store.dart';

enum PairingUiState {
  waiting('Waiting'),
  scanning('Scanning'),
  pairingReady('Pairing QR verified'),
  details('Review host'),
  verifying('Verifying'),
  signing('Signing'),
  complete('Paired'),
  failed('Pairing failed');

  const PairingUiState(this.label);
  final String label;
}

class PairingSnapshot {
  const PairingSnapshot({
    required this.state,
    this.pairing,
    this.errorCode,
    this.errorReason,
    this.pairedRecord,
  });

  final PairingUiState state;
  final RtqPairingChallenge? pairing;
  final String? errorCode;
  final String? errorReason;
  final PairedHostRecord? pairedRecord;
}

class PairingController extends ChangeNotifier {
  PairingController({
    required DeviceKeyVault vault,
    required ApprovalTransport transport,
    required PairingStore store,
    DateTime Function()? now,
  }) : _vault = vault,
       _transport = transport,
       _store = store,
       _now = now ?? DateTime.now;

  final DeviceKeyVault _vault;
  final ApprovalTransport _transport;
  final PairingStore _store;
  final DateTime Function() _now;

  PairingUiState _state = PairingUiState.waiting;
  RtqPairingChallenge? _pairing;
  String? _errorCode;
  String? _errorReason;
  PairedHostRecord? _pairedRecord;

  PairingSnapshot get snapshot => PairingSnapshot(
    state: _state,
    pairing: _pairing,
    errorCode: _errorCode,
    errorReason: _errorReason,
    pairedRecord: _pairedRecord,
  );

  PairingUiState get state => _state;
  RtqPairingChallenge? get pairing => _pairing;
  String? get errorCode => _errorCode;
  String? get errorReason => _errorReason;

  /// Enter the camera scanning state.
  void beginScanning() {
    _resetError();
    _set(PairingUiState.scanning);
  }

  /// Handle a scanned pairing QR payload.
  Future<void> scan(String payload) async {
    _resetError();
    if (classifyQrPayload(payload) != QrPayloadKind.pairing) {
      _fail(ProtocolError.invalidPrefix, 'Not an RTQ pairing QR.');
      return;
    }
    final parsed = RtqApprovalProtocol.parsePairingChallenge(payload);
    if (!parsed.ok) {
      _fail(
        parsed.code ?? ProtocolError.invalidField,
        parsed.reason ?? 'Malformed pairing QR.',
      );
      return;
    }
    final candidate = parsed.requireValue;

    final hostOk = await RtqApprovalProtocol.verifyPairingHostSignature(
      candidate,
    );
    if (!hostOk) {
      _fail(
        ProtocolError.pairingSignatureInvalid,
        'The host signature on this pairing QR does not verify.',
      );
      return;
    }
    if (_now().millisecondsSinceEpoch >= candidate.expiresAt) {
      _fail(
        ProtocolError.pairingExpired,
        'This pairing QR has expired. Ask the host to generate a new one.',
      );
      return;
    }

    final existing = await _store.read();
    if (existing != null && existing.hostPublicKey == candidate.hostPublicKey) {
      _fail(
        ProtocolError.pairingRedeemed,
        'This device is already paired with this host.',
      );
      return;
    }

    _pairing = candidate;
    _set(PairingUiState.pairingReady);
  }

  void showDetails() {
    if (_pairing == null) return;
    _set(PairingUiState.details);
  }

  /// Confirm pairing: unlock the device key, sign the pairing response, submit
  /// it to the host, and persist the pinned host on success.
  Future<void> complete(String pin, {required String deviceName}) async {
    final pairing = _pairing;
    if (pairing == null) {
      _set(PairingUiState.waiting);
      return;
    }
    _resetError();
    _set(PairingUiState.verifying);

    RtqDeviceKey key;
    try {
      key = await _vault.unlock(pin);
    } on WrongPinException {
      _fail('vault.wrong_pin', 'The PIN did not unlock this device key.');
      return;
    } on VaultNotInitializedException {
      _fail(
        'setup.required',
        'No device key exists yet. Create one in Settings before pairing.',
      );
      return;
    } catch (_) {
      _fail('vault.unlock_error', 'Could not unlock the device key.');
      return;
    }

    _set(PairingUiState.signing);
    final response = await RtqApprovalProtocol.signPairingResponse(
      pairing: pairing,
      deviceKey: key,
      deviceName: deviceName,
      signedAt: _now().millisecondsSinceEpoch,
    );
    final json = RtqApprovalProtocol.encodePairingResponse(response);

    final result = await _transport.completePairing(json);
    if (!result.ok) {
      _fail(
        result.code ?? 'transport.error',
        result.reason ?? 'The host rejected the pairing response.',
      );
      return;
    }

    await _store.save(
      PairedHostRecord(
        hostId: pairing.hostId,
        hostPublicKey: pairing.hostPublicKey,
        application: pairing.application,
        pairedAt: _now().millisecondsSinceEpoch,
      ),
    );
    _pairedRecord = PairedHostRecord(
      hostId: pairing.hostId,
      hostPublicKey: pairing.hostPublicKey,
      application: pairing.application,
      pairedAt: _now().millisecondsSinceEpoch,
    );
    _set(PairingUiState.complete);
  }

  Future<void> reset() async {
    _pairing = null;
    _pairedRecord = null;
    _resetError();
    _set(PairingUiState.waiting);
  }

  Future<void> unpair() async {
    await _store.clear();
    _pairing = null;
    _pairedRecord = null;
    _resetError();
    _set(PairingUiState.waiting);
  }

  void _resetError() {
    _errorCode = null;
    _errorReason = null;
  }

  void _fail(String code, String reason) {
    _errorCode = code;
    _errorReason = reason;
    _set(PairingUiState.failed);
  }

  void _set(PairingUiState next) {
    _state = next;
    notifyListeners();
  }
}
