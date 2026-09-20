/// Canonical base64url (RFC 4648 §5, no padding) used by the QR payloads.
///
/// The TypeScript encoder strips `=` padding. We require the same canonical
/// form on decode and reject aliases/padding so the two implementations cannot
/// disagree about the bytes.
library;

import 'dart:convert';

final _canonical = RegExp(r'^[A-Za-z0-9_-]+$');

String encodeBase64Url(List<int> bytes) =>
    base64Url.encode(bytes).replaceAll('=', '');

List<int> decodeCanonicalBase64Url(String input) {
  if (input.isEmpty || !_canonical.hasMatch(input)) {
    throw FormatException('not canonical base64url');
  }
  final normalized = base64Url.normalize(input);
  final bytes = base64Url.decode(normalized);
  if (encodeBase64Url(bytes) != input) {
    throw const FormatException('not canonical base64url');
  }
  return bytes;
}

String encodeUtf8Base64Url(String text) => encodeBase64Url(utf8.encode(text));
