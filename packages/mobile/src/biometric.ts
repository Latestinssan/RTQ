/**
 * Biometric helper for Android & iOS using react-native-biometrics.
 *
 * The function `ensureBiometricAuth` resolves when the user successfully authenticates
 * via the device's biometric (fingerprint, face, iris) or device credentials (PIN/
 * pattern). It throws on failure or if biometrics are unavailable.
 */
import ReactNativeBiometrics from "react-native-biometrics";

export async function ensureBiometricAuth(): Promise<void> {
  const rnBiometrics = new ReactNativeBiometrics({ allowDeviceCredentials: true });
  const { available, biometryType } = await rnBiometrics.isSensorAvailable();
  if (!available) {
    throw new Error("Biometric authentication not available on this device");
  }
  // Prompt the user. The message can be customized later.
  const result = await rnBiometrics.simplePrompt({
    promptMessage: "Authenticate to approve",
    cancelButtonText: "Cancel",
  });
  if (!result.success) {
    throw new Error("Biometric authentication failed");
  }
}
