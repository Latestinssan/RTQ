/// QR payload classification.
///
/// The scanner is exposed to arbitrary QR codes. This classifier distinguishes
/// the RTQ flows we understand from everything else, so arbitrary codes are
/// rejected before any UI is shown.
library;

enum QrPayloadKind { challenge, pairing, unsupported }

class QrPayload {
  const QrPayload(this.raw);
  final String raw;
}

QrPayloadKind classifyQrPayload(String? payload) {
  if (payload == null || payload.isEmpty) return QrPayloadKind.unsupported;
  if (payload.startsWith('rtq://pair')) return QrPayloadKind.pairing;
  if (payload.startsWith('rtq://challenge') ||
      payload.startsWith('rtq://approval')) {
    return QrPayloadKind.challenge;
  }
  return QrPayloadKind.unsupported;
}
