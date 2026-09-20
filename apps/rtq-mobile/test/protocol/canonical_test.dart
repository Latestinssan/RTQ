/// Canonical serialization must match the TypeScript host byte-for-byte.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/canonical.dart';

void main() {
  group('canonicalStringify', () {
    test('sorts object keys recursively', () {
      expect(
        canonicalStringify(<String, Object?>{'b': 1, 'a': 2}),
        '{"a":2,"b":1}',
      );
      expect(
        canonicalStringify(<String, Object?>{
          'z': <Object?>[
            3,
            <String, Object?>{'y': true, 'x': null},
          ],
          'a': 's',
        }),
        '{"a":"s","z":[3,{"x":null,"y":true}]}',
      );
    });

    test('serializes integers without decimals', () {
      expect(canonicalStringify(1750000300000), '1750000300000');
      expect(canonicalStringify(0), '0');
      expect(canonicalStringify(-12), '-12');
    });

    test('integral doubles print as integers (JS compatible)', () {
      expect(canonicalStringify(7.0), '7');
      expect(canonicalStringify(-7.0), '-7');
    });

    test('standard JSON string escapes', () {
      expect(canonicalStringify('a"b\\c\nd\te'), r'"a\"b\\c\nd\te"');
      expect(canonicalStringify('\u0000\u001f'), r'"\u0000\u001f"');
      expect(canonicalStringify('héllo ☃'), '"héllo ☃"');
    });

    test('rejects non-finite numbers', () {
      expect(
        () => canonicalStringify(double.nan),
        throwsA(isA<CanonicalizationError>()),
      );
      expect(
        () => canonicalStringify(double.infinity),
        throwsA(isA<CanonicalizationError>()),
      );
    });

    test('rejects non-string object keys and unknown types', () {
      expect(
        () => canonicalStringify(<Object?, Object?>{1: 'x'}),
        throwsA(isA<CanonicalizationError>()),
      );
    });

    test('booleans and null', () {
      expect(canonicalStringify(true), 'true');
      expect(canonicalStringify(false), 'false');
      expect(canonicalStringify(null), 'null');
    });
  });
}
