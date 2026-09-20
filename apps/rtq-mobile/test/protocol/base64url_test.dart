/// Canonical base64url (RFC 4648 §5, no padding) — the QR envelope encoding.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/base64url.dart';

void main() {
  group('base64url', () {
    test('round trips arbitrary bytes', () {
      final bytes = List<int>.generate(64, (i) => (i * 7) % 256);
      expect(decodeCanonicalBase64Url(encodeBase64Url(bytes)), bytes);
    });

    test('requires canonical form and rejects padding', () {
      expect(() => decodeCanonicalBase64Url('AQID'), returnsNormally);
      expect(
        () => decodeCanonicalBase64Url('AQID=='),
        throwsA(isA<FormatException>()),
      );
      // 'AQI' is a self-canonical 2-byte value (matches Node's re-encode check).
      expect(() => decodeCanonicalBase64Url('AQI'), returnsNormally);
    });

    test('rejects non-alphabet characters', () {
      expect(
        () => decodeCanonicalBase64Url('AQ+D'), // '+' is not URL-safe base64
        throwsA(isA<FormatException>()),
      );
      expect(
        () => decodeCanonicalBase64Url('AQ/D'),
        throwsA(isA<FormatException>()),
      );
      expect(
        () => decodeCanonicalBase64Url('AQ+D!'),
        throwsA(isA<FormatException>()),
      );
    });

    test('utf8 wrapper', () {
      final encoded = encodeUtf8Base64Url('hello ☃');
      expect(decodeCanonicalBase64Url(encoded), [
        104,
        101,
        108,
        108,
        111,
        32,
        226,
        152,
        131,
      ]);
    });
  });
}
