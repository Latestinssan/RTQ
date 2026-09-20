/// Strict JSON parsing: duplicate object keys are rejected so the Dart and
/// TypeScript parsers cannot disagree about a payload.
library;

import 'package:flutter_test/flutter_test.dart';
import 'package:rtq_mobile/protocol/strict_json.dart';

void main() {
  group('strictJsonParse', () {
    test('parses plain objects', () {
      final value = strictJsonParse('{"a":1,"b":[true,null,"x"]}');
      expect(value, <String, Object?>{
        'a': 1,
        'b': <Object?>[true, null, 'x'],
      });
    });

    test('rejects duplicate keys at top level', () {
      expect(
        () => strictJsonParse('{"a":1,"a":2}'),
        throwsA(isA<StrictJsonException>()),
      );
    });

    test('rejects duplicate keys nested', () {
      expect(
        () => strictJsonParse('{"outer":{"x":1,"x":2}}'),
        throwsA(isA<StrictJsonException>()),
      );
    });

    test('rejects trailing garbage', () {
      expect(
        () => strictJsonParse('{"a":1} extra'),
        throwsA(isA<StrictJsonException>()),
      );
    });

    test('rejects unescaped control characters', () {
      expect(
        () => strictJsonParse('{"a":"\u0001"}'),
        throwsA(isA<StrictJsonException>()),
      );
    });

    test('numbers parse as int when integral, double otherwise', () {
      final value = Map<String, Object?>.from(
        strictJsonParse('{"i":123,"d":1.5,"e":1e3}') as Map,
      );
      expect(value['i'], 123);
      expect(value['d'], 1.5);
      expect(value['e'], 1000.0);
    });
  });
}
