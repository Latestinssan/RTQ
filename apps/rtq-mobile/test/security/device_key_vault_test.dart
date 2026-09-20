/// PIN-wrapped device key vault: create/unlock/change/wipe, wrong-PIN
/// fail-closed behavior, and PIN policy. Uses low PBKDF2 iterations so the
/// tests stay fast; the production default is 210,000.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/crypto_ed25519.dart';
import 'package:rtq_mobile/security/device_key_vault.dart';
import 'package:rtq_mobile/security/secure_store.dart';

DeviceKeyVault vaultWith(SecureStore store, {int iterations = 500}) =>
    DeviceKeyVault(store: store, pbkdf2Iterations: iterations);

void main() {
  group('PinPolicy', () {
    test('accepts a normal PIN', () {
      expect(PinPolicy.validate('73915024'), isNull);
      expect(PinPolicy.validate('4829 1042'.replaceAll(' ', '')), isNull);
    });

    test('rejects short or overly long PINs', () {
      expect(PinPolicy.validate('12345'), isNotNull);
      expect(PinPolicy.validate('1' * 65), isNotNull);
    });

    test('rejects repeated digits and simple sequences', () {
      expect(PinPolicy.validate('111111'), isNotNull);
      expect(PinPolicy.validate('123456'), isNotNull); // ascending
      expect(PinPolicy.validate('654321'), isNotNull); // descending
    });
  });

  group('DeviceKeyVault', () {
    test('create then unlock returns the same key', () async {
      final store = InMemorySecureStore();
      final vault = vaultWith(store);

      final key = await vault.create('135790');
      expect(key.seed.length, 32);
      expect(key.publicKey.length, 32);
      expect(key.deviceId, deviceIdFromPublicKey(key.publicKey));

      final unlocked = await vault.unlock('135790');
      expect(unlocked.seed, orderedEquals(key.seed));
      expect(unlocked.deviceId, key.deviceId);
    });

    test('wrong PIN fails closed (throws, never compares plaintext)', () async {
      final vault = vaultWith(InMemorySecureStore());
      await vault.create('135790');

      expect(() => vault.unlock('135791'), throwsA(isA<WrongPinException>()));
      expect(() => vault.unlock(''), throwsA(isA<WrongPinException>()));
    });

    test('the persisted record contains no PIN or seed in the clear', () async {
      final store = InMemorySecureStore();
      final vault = vaultWith(store);
      final key = await vault.create('135790');

      final raw = await store.read(DeviceKeyVault.storageKey);
      expect(raw, isNotNull);
      expect(raw, isNot(contains('135790')));
      expect(raw, isNot(contains(toHex(key.seed))));
      // Public material is fine to store.
      expect(raw, contains('publicKey'));
    });

    test('key survives a fresh vault instance (persistence)', () async {
      final store = InMemorySecureStore();
      await vaultWith(store).create('135790');

      final reopened = vaultWith(store);
      final unlocked = await reopened.unlock('135790');
      expect(unlocked.seed.length, 32);
    });

    test('changePin re-wraps the same key', () async {
      final store = InMemorySecureStore();
      final vault = vaultWith(store);
      final key = await vault.create('135790');

      await vault.changePin('135790', '975310');
      final unlocked = await vault.unlock('975310');
      expect(unlocked.seed, orderedEquals(key.seed));
      expect(() => vault.unlock('135790'), throwsA(isA<WrongPinException>()));
    });

    test(
      'pendingDeviceId exposes the public fingerprint without unlock',
      () async {
        final vault = vaultWith(InMemorySecureStore());
        expect(await vault.pendingDeviceId(), isNull);
        final key = await vault.create('135790');
        expect(await vault.pendingDeviceId(), key.deviceId);
      },
    );

    test('isInitialized and wipe', () async {
      final store = InMemorySecureStore();
      final vault = vaultWith(store);
      expect(await vault.isInitialized(), isFalse);
      await vault.create('135790');
      expect(await vault.isInitialized(), isTrue);
      await vault.wipe();
      expect(await vault.isInitialized(), isFalse);
      expect(
        () => vault.unlock('135790'),
        throwsA(isA<VaultNotInitializedException>()),
      );
    });
  });
}
