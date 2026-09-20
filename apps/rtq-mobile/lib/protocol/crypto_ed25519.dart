/// Ed25519 device identity for `rtq-approval-v1`.
///
/// The device holds a 32-byte Ed25519 private seed. It never leaves the device:
/// the host only ever sees the 32-byte public key, and the `deviceId` is
/// `sha256(rawPublicKey)`, so an identity cannot be spoofed independently of
/// the key.
///
/// Signatures are RFC 8032 deterministic, identical to the Node host's
/// `ed25519Sign`, so the shared vectors in `protocol/rtq-approval-v1.vectors.json`
/// verify byte-for-byte on both platforms.
library;

import 'dart:math';
import 'dart:typed_data';

import 'package:crypto/crypto.dart' as crypto;
import 'package:cryptography/cryptography.dart';

class RtqDeviceKey {
  RtqDeviceKey({required this.seed, required this.publicKey});

  /// 32-byte Ed25519 private seed. Secret.
  final Uint8List seed;

  /// 32-byte Ed25519 public key. Safe to share.
  final Uint8List publicKey;

  /// `sha256(publicKey)` hex — the host-computed device identity.
  String get deviceId => deviceIdFromPublicKey(publicKey);
}

/// `sha256(raw 32-byte public key)` hex, matching the TypeScript host.
String deviceIdFromPublicKey(List<int> publicKey) =>
    crypto.sha256.convert(publicKey).toString();

Uint8List randomBytes(int length) {
  final random = Random.secure();
  final out = Uint8List(length);
  for (var i = 0; i < length; i++) {
    out[i] = random.nextInt(256);
  }
  return out;
}

class RtqEd25519 {
  RtqEd25519._();

  static final Ed25519 _algorithm = Ed25519();

  /// Generate a fresh device key from a CSPRNG seed.
  static Future<RtqDeviceKey> generate() => fromSeed(randomBytes(32));

  /// Derive the key pair from a 32-byte seed. Deterministic.
  static Future<RtqDeviceKey> fromSeed(List<int> seed) async {
    if (seed.length != 32) {
      throw ArgumentError('Ed25519 seed must be 32 bytes, got ${seed.length}');
    }
    final normalized = Uint8List.fromList(seed);
    final keyPair = await _algorithm.newKeyPairFromSeed(normalized);
    final publicKey = await keyPair.extractPublicKey();
    return RtqDeviceKey(
      seed: normalized,
      publicKey: Uint8List.fromList(publicKey.bytes),
    );
  }

  /// Sign [message] with the seed; returns the 64-byte signature.
  static Future<Uint8List> sign(List<int> seed, List<int> message) async {
    final keyPair = await _algorithm.newKeyPairFromSeed(
      Uint8List.fromList(seed),
    );
    final signature = await _algorithm.sign(message, keyPair: keyPair);
    return Uint8List.fromList(signature.bytes);
  }

  /// Verify a 64-byte [signature] over [message] with a 32-byte [publicKey].
  static Future<bool> verify(
    List<int> publicKey,
    List<int> message,
    List<int> signature,
  ) async {
    if (publicKey.length != 32 || signature.length != 64) return false;
    try {
      return await _algorithm.verify(
        message,
        signature: Signature(
          signature,
          publicKey: SimplePublicKey(publicKey, type: KeyPairType.ed25519),
        ),
      );
    } catch (_) {
      return false;
    }
  }
}

String toHex(List<int> bytes) {
  final buffer = StringBuffer();
  for (final b in bytes) {
    buffer.write(b.toRadixString(16).padLeft(2, '0'));
  }
  return buffer.toString();
}

Uint8List fromHex(String hex) {
  if (hex.length.isOdd) throw FormatException('odd-length hex');
  final out = Uint8List(hex.length ~/ 2);
  for (var i = 0; i < out.length; i++) {
    out[i] = int.parse(hex.substring(i * 2, i * 2 + 2), radix: 16);
  }
  return out;
}

bool isValidHex(String value, int bytes) =>
    value.length == bytes * 2 && RegExp(r'^[0-9a-f]+$').hasMatch(value);
