/// Deterministic canonical serialization for `rtq-approval-v1`.
///
/// This MUST match the TypeScript `canonicalStringify` byte-for-byte, because a
/// host signature produced by the Node host is verified here by re-serializing
/// the same object. The rules are:
///   * object keys are sorted by UTF-16 code unit order (Dart/JS string order);
///   * strings are JSON-escaped with the standard short escapes and `\u00xx`
///     for other control characters, leaving non-ASCII text unescaped;
///   * integers print without a decimal point; integral doubles print as
///     integers;
///   * `null` prints as `null`; booleans as `true`/`false`.
///
/// Floats that are not integral cannot be guaranteed to format identically to
/// JavaScript's `Number.prototype.toString`. Security-critical numeric fields
/// in this protocol are integers by construction; human-readable `summary`
/// values SHOULD be strings, integers, booleans or null.
library;

import 'dart:convert';

class CanonicalizationError extends Error {
  CanonicalizationError(this.message);
  final String message;

  @override
  String toString() => 'CanonicalizationError: $message';
}

/// Serialize [value] with recursively sorted object keys.
String canonicalStringify(Object? value) {
  final buffer = StringBuffer();
  _write(value, buffer);
  return buffer.toString();
}

void _write(Object? value, StringBuffer out) {
  if (value == null) {
    out.write('null');
    return;
  }
  if (value is String) {
    _writeString(value, out);
    return;
  }
  if (value is bool) {
    out.write(value ? 'true' : 'false');
    return;
  }
  if (value is int) {
    out.write(value.toString());
    return;
  }
  if (value is double) {
    if (!value.isFinite) {
      throw CanonicalizationError(
        'cannot canonically serialize non-finite number: $value',
      );
    }
    if (value == value.truncateToDouble() && value.abs() < 1e21) {
      out.write(value.truncate().toString());
    } else {
      out.write(value.toString());
    }
    return;
  }
  if (value is List) {
    out.write('[');
    for (var i = 0; i < value.length; i++) {
      if (i > 0) out.write(',');
      _write(value[i], out);
    }
    out.write(']');
    return;
  }
  if (value is Map) {
    final keys = value.keys.map((k) {
      if (k is! String) {
        throw CanonicalizationError('object keys must be strings, got $k');
      }
      return k;
    }).toList()..sort();
    out.write('{');
    for (var i = 0; i < keys.length; i++) {
      if (i > 0) out.write(',');
      _writeString(keys[i], out);
      out.write(':');
      _write(value[keys[i]], out);
    }
    out.write('}');
    return;
  }
  throw CanonicalizationError(
    'cannot canonically serialize ${value.runtimeType}',
  );
}

void _writeString(String value, StringBuffer out) {
  out.write('"');
  for (final codeUnit in value.codeUnits) {
    switch (codeUnit) {
      case 0x22:
        out.write(r'\"');
        break;
      case 0x5c:
        out.write(r'\\');
        break;
      case 0x08:
        out.write(r'\b');
        break;
      case 0x0c:
        out.write(r'\f');
        break;
      case 0x0a:
        out.write(r'\n');
        break;
      case 0x0d:
        out.write(r'\r');
        break;
      case 0x09:
        out.write(r'\t');
        break;
      default:
        if (codeUnit < 0x20) {
          out.write('\\u${codeUnit.toRadixString(16).padLeft(4, '0')}');
        } else {
          out.writeCharCode(codeUnit);
        }
    }
  }
  out.write('"');
}

/// Convenience: canonical stringify then UTF-8 encode.
List<int> canonicalUtf8(Object? value) =>
    utf8.encode(canonicalStringify(value));
