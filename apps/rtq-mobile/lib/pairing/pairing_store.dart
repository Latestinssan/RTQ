/// Persisted pairing record: which host this device trusts.
///
/// The only security-relevant value is `hostPublicKey` — the Ed25519 public key
/// the device pins. A challenge QR is only accepted when its embedded key
/// equals the pinned key, so a foreign QR cannot impersonate the host. The
/// record contains no device secret.
library;

import 'dart:convert';

import '../security/secure_store.dart';

class PairedHostRecord {
  const PairedHostRecord({
    required this.hostId,
    required this.hostPublicKey,
    required this.application,
    required this.pairedAt,
  });

  final String hostId;

  /// Base64url raw Ed25519 public key. The trust anchor for challenge QRs.
  final String hostPublicKey;

  final String application;
  final int pairedAt;

  Map<String, Object?> toJson() => <String, Object?>{
    'v': 1,
    'hostId': hostId,
    'hostPublicKey': hostPublicKey,
    'application': application,
    'pairedAt': pairedAt,
  };

  static PairedHostRecord? tryParse(Map<String, Object?> json) {
    final hostId = json['hostId'];
    final hostPublicKey = json['hostPublicKey'];
    final application = json['application'];
    final pairedAt = json['pairedAt'];
    if (hostId is! String ||
        hostPublicKey is! String ||
        application is! String ||
        pairedAt is! int) {
      return null;
    }
    return PairedHostRecord(
      hostId: hostId,
      hostPublicKey: hostPublicKey,
      application: application,
      pairedAt: pairedAt,
    );
  }
}

class PairingStore {
  PairingStore(this._store);

  static const String storageKey = 'rtq.paired_host.v1';

  final SecureStore _store;

  Future<PairedHostRecord?> read() async {
    final raw = await _store.read(storageKey);
    if (raw == null) return null;
    try {
      return PairedHostRecord.tryParse(
        Map<String, Object?>.from(jsonDecode(raw) as Map),
      );
    } catch (_) {
      return null;
    }
  }

  Future<void> save(PairedHostRecord record) =>
      _store.write(storageKey, jsonEncode(record.toJson()));

  Future<void> clear() => _store.delete(storageKey);

  Future<bool> isPaired() async => (await read()) != null;

  /// Pinned host public key (base64url), or null when unpaired.
  Future<String?> pinnedHostPublicKey() async => (await read())?.hostPublicKey;
}
