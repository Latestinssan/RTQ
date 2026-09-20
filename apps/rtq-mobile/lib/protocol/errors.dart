/// Stable `rtq-approval-v1` error codes. Mirrors the TypeScript
/// `PROTOCOL_ERROR` constants so a failure names the same condition on both
/// sides and can be mapped to a specific UI state.
library;

class ProtocolError {
  ProtocolError._();

  // Envelope / framing.
  static const invalidPrefix = 'protocol.invalid_prefix';
  static const malformedBase64 = 'protocol.malformed_base64';
  static const malformedJson = 'protocol.malformed_json';
  static const duplicateJsonKey = 'protocol.duplicate_json_key';
  static const payloadNotObject = 'protocol.payload_not_object';
  static const unknownKind = 'protocol.unknown_kind';
  static const unsupportedProtocol = 'protocol.unsupported_protocol';
  static const unsupportedVersion = 'protocol.unsupported_version';
  static const missingField = 'protocol.missing_field';
  static const invalidField = 'protocol.invalid_field';

  // Host authenticity.
  static const hostSignatureInvalid = 'challenge.host_signature_invalid';
  static const hostMismatch = 'challenge.host_mismatch';

  // Challenge lifecycle.
  static const challengeUnknown = 'challenge.unknown';
  static const challengeExpired = 'challenge.expired';
  static const challengeNotYetValid = 'challenge.not_yet_valid';
  static const challengeRedeemed = 'challenge.redeemed';
  static const clockSkew = 'challenge.clock_skew';

  // Device identity.
  static const deviceUnknown = 'device.unknown';
  static const deviceRevoked = 'device.revoked';
  static const deviceExpired = 'device.expired';
  static const deviceIdMismatch = 'device.id_mismatch';
  static const deviceSignatureInvalid = 'device.signature_invalid';

  // Approval binding.
  static const bindingMismatch = 'approval.binding_mismatch';
  static const decisionDenied = 'approval.denied';

  // Pairing.
  static const pairingUnknown = 'pairing.unknown';
  static const pairingExpired = 'pairing.expired';
  static const pairingRedeemed = 'pairing.redeemed';
  static const pairingSignatureInvalid = 'pairing.signature_invalid';
  static const pairingDeviceMismatch = 'pairing.device_mismatch';
}

/// Thrown when a protocol operation cannot proceed. The [code] is stable.
class ProtocolException implements Exception {
  ProtocolException(this.code, this.reason);
  final String code;
  final String reason;

  @override
  String toString() => 'ProtocolException($code): $reason';
}

/// Result of a parse/verify that may fail with a stable code.
class ProtocolResult<T> {
  ProtocolResult.ok(this.value) : ok = true, code = null, reason = null;
  ProtocolResult.fail(this.code, this.reason) : ok = false, value = null;

  final bool ok;
  final T? value;
  final String? code;
  final String? reason;

  T get requireValue {
    final v = value;
    if (!ok || v == null) {
      throw ProtocolException(code ?? invalidField, reason ?? 'no value');
    }
    return v;
  }

  static const invalidField = ProtocolError.invalidField;
}
