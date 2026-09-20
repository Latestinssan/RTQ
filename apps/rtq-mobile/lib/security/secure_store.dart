/// Storage abstraction for device secrets.
///
/// The real app backs this with the platform keystore/Keychain via
/// `flutter_secure_storage` (see `flutter_secure_store.dart`). Tests and
/// headless environments use [InMemorySecureStore], so the vault logic is fully
/// unit-testable without a platform channel.
library;

abstract class SecureStore {
  Future<String?> read(String key);
  Future<void> write(String key, String value);
  Future<void> delete(String key);
  Future<bool> containsKey(String key);
}

class InMemorySecureStore implements SecureStore {
  final Map<String, String> _values = <String, String>{};

  @override
  Future<String?> read(String key) async => _values[key];

  @override
  Future<void> write(String key, String value) async {
    _values[key] = value;
  }

  @override
  Future<void> delete(String key) async {
    _values.remove(key);
  }

  @override
  Future<bool> containsKey(String key) async => _values.containsKey(key);
}
