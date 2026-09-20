/// Device key vault: a PIN-wrapped Ed25519 device key.
///
/// Threat model: the private seed is the device's authority to approve. It is
/// generated on-device and encrypted at rest with a key derived from the user's
/// PIN (PBKDF2-HMAC-SHA256) and authenticated with AES-256-GCM. Consequences:
///
///   * the PIN is NEVER stored, logged, transmitted, or placed in a QR code;
///   * a wrong PIN fails as an authentication error, not a comparison against a
///     stored secret, so there is nothing to leak if storage is read;
///   * the seed is unusable without the PIN even though it lives in the
///     platform keystore;
///   * the host never sees the seed or the PIN.
///
/// This module is pure Dart except for the injected [SecureStore].
library;

import 'dart:convert';
import 'dart:typed_data';

import 'package:cryptography/cryptography.dart';

import '../protocol/crypto_ed25519.dart';
import 'secure_store.dart';

class WrongPinException implements Exception {
  const WrongPinException();
  @override
  String toString() => 'WrongPinException: PIN did not unlock the device key';
}

class VaultNotInitializedException implements Exception {
  const VaultNotInitializedException();
  @override
  String toString() => 'VaultNotInitializedException';
}

class PinPolicy {
  const PinPolicy._();

  static const int minLength = 6;
  static const int maxLength = 64;

  /// Returns a human-readable error, or null when the PIN is acceptable.
  static String? validate(String pin) {
    if (pin.length < minLength) {
      return 'PIN must be at least $minLength digits.';
    }
    if (pin.length > maxLength) {
      return 'PIN is too long.';
    }
    if (RegExp(r'^\d+$').hasMatch(pin)) {
      if (pin.split('').toSet().length == 1) {
        return 'PIN must not be a single repeated digit.';
      }
      var ascending = true;
      var descending = true;
      for (var i = 1; i < pin.length; i++) {
        final delta = pin.codeUnitAt(i) - pin.codeUnitAt(i - 1);
        if (delta != 1) ascending = false;
        if (delta != -1) descending = false;
      }
      if (ascending || descending) {
        return 'PIN must not be a simple sequence.';
      }
    }
    return null;
  }
}

/// The persisted, encrypted record. Contains no plaintext secret.
class _VaultRecord {
  const _VaultRecord({
    required this.iterations,
    required this.salt,
    required this.nonce,
    required this.ciphertext,
    required this.mac,
    required this.publicKey,
  });

  final int iterations;
  final Uint8List salt;
  final Uint8List nonce;
  final Uint8List ciphertext;
  final Uint8List mac;
  final Uint8List publicKey;

  Map<String, Object?> toJson() => <String, Object?>{
    'v': 1,
    'kdf': 'pbkdf2-hmac-sha256',
    'cipher': 'aes-256-gcm',
    'iterations': iterations,
    'salt': base64UrlEncode(salt),
    'nonce': base64UrlEncode(nonce),
    'ciphertext': base64UrlEncode(ciphertext),
    'mac': base64UrlEncode(mac),
    'publicKey': base64UrlEncode(publicKey),
  };

  static _VaultRecord fromJson(Map<String, Object?> json) => _VaultRecord(
    iterations: json['iterations'] as int,
    salt: _b64(json['salt'] as String),
    nonce: _b64(json['nonce'] as String),
    ciphertext: _b64(json['ciphertext'] as String),
    mac: _b64(json['mac'] as String),
    publicKey: _b64(json['publicKey'] as String),
  );
}

String base64UrlEncode(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

Uint8List _b64(String value) {
  final normalized = value.replaceAll('-', '+').replaceAll('_', '/');
  return Uint8List.fromList(
    base64.decode(normalized.padRight((normalized.length + 3) & ~3, '=')),
  );
}

class DeviceKeyVault {
  DeviceKeyVault({required SecureStore store, this.pbkdf2Iterations = 210000})
    : _store = store;

  static const String storageKey = 'rtq.device_key.v1';

  final SecureStore _store;
  final int pbkdf2Iterations;

  Future<bool> isInitialized() => _store.containsKey(storageKey);

  /// The public device identity without unlocking (public-key fingerprint).
  Future<String?> pendingDeviceId() async {
    final record = await _readRecord();
    if (record == null) return null;
    return deviceIdFromPublicKey(record.publicKey);
  }

  /// Generate a fresh device key, wrap it with [pin], and persist it.
  Future<RtqDeviceKey> create(String pin) async {
    final policyError = PinPolicy.validate(pin);
    if (policyError != null) {
      throw ArgumentError(policyError);
    }
    final key = await RtqEd25519.generate();
    await _persist(key, pin);
    return key;
  }

  /// Unlock the device key. Throws [WrongPinException] on a wrong PIN.
  Future<RtqDeviceKey> unlock(String pin) async {
    final record = await _readRecord();
    if (record == null) throw const VaultNotInitializedException();
    final kek = await _deriveKek(pin, record.salt, record.iterations);
    final cipher = AesGcm.with256bits();
    try {
      final seed = await cipher.decrypt(
        SecretBox(record.ciphertext, nonce: record.nonce, mac: Mac(record.mac)),
        secretKey: kek,
      );
      final key = await RtqEd25519.fromSeed(seed);
      if (!_sameBytes(key.publicKey, record.publicKey)) {
        throw const WrongPinException();
      }
      return key;
    } on SecretBoxAuthenticationError {
      throw const WrongPinException();
    } catch (_) {
      throw const WrongPinException();
    }
  }

  /// Change the PIN, re-wrapping the same device key.
  Future<void> changePin(String oldPin, String newPin) async {
    final key = await unlock(oldPin);
    final policyError = PinPolicy.validate(newPin);
    if (policyError != null) throw ArgumentError(policyError);
    await _persist(key, newPin);
  }

  /// Legacy compatibility migration: takes a raw public key, stores the given
  /// seed. Only used by tests and the demo host.
  Future<void> wipe() => _store.delete(storageKey);

  Future<void> _persist(RtqDeviceKey key, String pin) async {
    final salt = randomBytes(16);
    final nonce = randomBytes(12);
    final kek = await _deriveKek(pin, salt, pbkdf2Iterations);
    final cipher = AesGcm.with256bits();
    final box = await cipher.encrypt(key.seed, secretKey: kek, nonce: nonce);
    final record = _VaultRecord(
      iterations: pbkdf2Iterations,
      salt: salt,
      nonce: Uint8List.fromList(box.nonce),
      ciphertext: Uint8List.fromList(box.cipherText),
      mac: Uint8List.fromList(box.mac.bytes),
      publicKey: key.publicKey,
    );
    await _store.write(storageKey, jsonEncode(record.toJson()));
  }

  Future<SecretKey> _deriveKek(
    String pin,
    List<int> salt,
    int iterations,
  ) async {
    final pbkdf2 = Pbkdf2(
      macAlgorithm: Hmac.sha256(),
      iterations: iterations,
      bits: 256,
    );
    return pbkdf2.deriveKey(
      secretKey: SecretKey(utf8.encode(pin)),
      nonce: salt,
    );
  }

  Future<_VaultRecord?> _readRecord() async {
    final raw = await _store.read(storageKey);
    if (raw == null) return null;
    try {
      return _VaultRecord.fromJson(
        Map<String, Object?>.from(jsonDecode(raw) as Map),
      );
    } catch (_) {
      return null;
    }
  }

  bool _sameBytes(List<int> a, List<int> b) {
    if (a.length != b.length) return false;
    var diff = 0;
    for (var i = 0; i < a.length; i++) {
      diff |= a[i] ^ b[i];
    }
    return diff == 0;
  }
}
