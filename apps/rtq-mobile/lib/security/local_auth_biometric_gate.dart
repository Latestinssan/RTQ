/// `local_auth`-backed biometric gate.
///
/// Isolated from the rest of the app so headless tests never touch a platform
/// channel. Fails closed: any error or non-success biometrics result denies.
library;

import 'package:flutter/services.dart';
import 'package:local_auth/local_auth.dart';

import 'biometric_gate.dart';

class LocalAuthBiometricGate implements BiometricGate {
  LocalAuthBiometricGate({LocalAuthentication? auth})
    : _auth = auth ?? LocalAuthentication();

  final LocalAuthentication _auth;

  @override
  Future<bool> isAvailable() async {
    try {
      return await _auth.canCheckBiometrics || await _auth.isDeviceSupported();
    } catch (_) {
      return false;
    }
  }

  @override
  Future<BiometricResult> authenticate(String reason) async {
    try {
      final ok = await _auth.authenticate(
        localizedReason: reason,
        options: const AuthenticationOptions(
          biometricOnly: true,
          stickyAuth: true,
          useErrorDialogs: true,
        ),
      );
      return ok ? BiometricResult.authenticated : BiometricResult.failed;
    } on PlatformException catch (error) {
      // Map platform codes (see local_auth error_codes.dart). Anything that is
      // not an explicit "no hardware / not enrolled" condition is a failed
      // attempt; the caller treats every non-authenticated outcome as a deny.
      switch (error.code) {
        case 'NotAvailable':
        case 'notAvailable':
        case 'NotEnrolled':
        case 'PasscodeNotSet':
        case 'OtherOperatingSystem':
          return BiometricResult.unavailable;
        case 'LockedOut':
        case 'PermanentlyLockedOut':
        case 'lockedOut':
        case 'permanentlyLockedOut':
          return BiometricResult.failed;
        default:
          return BiometricResult.failed;
      }
    } catch (_) {
      return BiometricResult.failed;
    }
  }
}
