/// Biometric user-verification gate.
///
/// Biometrics are an OPTIONAL second factor on top of the PIN. The device key is
/// still PIN-wrapped; biometrics never replace possession of the seed. The gate
/// is an abstraction so the approval flow is testable without a platform
/// channel.
library;

enum BiometricResult { authenticated, failed, unavailable, cancelled }

abstract class BiometricGate {
  Future<bool> isAvailable();

  /// Prompt for biometric verification. Implementations MUST fail closed.
  Future<BiometricResult> authenticate(String reason);
}

class FakeBiometricGate implements BiometricGate {
  FakeBiometricGate({
    this.available = true,
    this.result = BiometricResult.authenticated,
  });

  bool available;
  BiometricResult result;
  int calls = 0;

  @override
  Future<bool> isAvailable() async => available;

  @override
  Future<BiometricResult> authenticate(String reason) async {
    calls++;
    return result;
  }
}
