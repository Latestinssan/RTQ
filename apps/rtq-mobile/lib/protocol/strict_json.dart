/// Strict JSON parser that rejects duplicate object keys.
///
/// `dart:convert`'s `jsonDecode` silently keeps the last of duplicate keys, and
/// JavaScript's `JSON.parse` does the same. An attacker who can put duplicate
/// keys in a payload could then make the device show one value while the host
/// verifies another. This parser rejects duplicates (and trailing content,
/// unterminated strings, raw control characters and malformed numbers), so both
/// implementations agree on what a payload means.
library;

class StrictJsonException implements Exception {
  StrictJsonException(this.message);
  final String message;

  @override
  String toString() => 'StrictJsonException: $message';
}

/// Parse [text] as strict JSON.
Object? strictJsonParse(String text) => _Parser(text).parse();

const _whitespace = {0x20, 0x09, 0x0a, 0x0d};

class _Parser {
  _Parser(this.text);
  final String text;
  int _i = 0;

  int get _length => text.length;

  Never _fail(String message) => throw StrictJsonException('$message (at $_i)');

  Object? parse() {
    final value = _parseValue();
    _skipWhitespace();
    if (_i != _length) _fail('unexpected trailing content');
    return value;
  }

  void _skipWhitespace() {
    while (_i < _length && _whitespace.contains(text.codeUnitAt(_i))) {
      _i++;
    }
  }

  Object? _parseValue() {
    _skipWhitespace();
    if (_i >= _length) _fail('unexpected end of input');
    final ch = text.codeUnitAt(_i);
    if (ch == 0x7b) return _parseObject(); // {
    if (ch == 0x5b) return _parseArray(); // [
    if (ch == 0x22) return _parseString(); // "
    if (ch == 0x2d || (ch >= 0x30 && ch <= 0x39)) return _parseNumber();
    if (text.startsWith('true', _i)) {
      _i += 4;
      return true;
    }
    if (text.startsWith('false', _i)) {
      _i += 5;
      return false;
    }
    if (text.startsWith('null', _i)) {
      _i += 4;
      return null;
    }
    _fail('unexpected token "${text[_i]}"');
  }

  String _parseString() {
    _i++; // opening quote
    final buffer = StringBuffer();
    while (true) {
      if (_i >= _length) _fail('unterminated string');
      final ch = text.codeUnitAt(_i);
      if (ch == 0x22) {
        _i++;
        return buffer.toString();
      }
      if (ch == 0x5c) {
        _i++;
        if (_i >= _length) _fail('unterminated escape');
        final esc = text.codeUnitAt(_i);
        switch (esc) {
          case 0x22:
            buffer.write('"');
            _i++;
            break;
          case 0x5c:
            buffer.write(r'\');
            _i++;
            break;
          case 0x2f:
            buffer.write('/');
            _i++;
            break;
          case 0x62:
            buffer.write('\b');
            _i++;
            break;
          case 0x66:
            buffer.write('\f');
            _i++;
            break;
          case 0x6e:
            buffer.write('\n');
            _i++;
            break;
          case 0x72:
            buffer.write('\r');
            _i++;
            break;
          case 0x74:
            buffer.write('\t');
            _i++;
            break;
          case 0x75: // u
            final hex = text.substring(_i + 1, _i + 5);
            if (!RegExp(r'^[0-9a-fA-F]{4}$').hasMatch(hex)) {
              _fail('invalid \\u escape');
            }
            buffer.writeCharCode(int.parse(hex, radix: 16));
            _i += 5;
            break;
          default:
            _fail('invalid escape sequence');
        }
        continue;
      }
      if (ch < 0x20) _fail('unescaped control character');
      buffer.writeCharCode(ch);
      _i++;
    }
  }

  num _parseNumber() {
    final match = RegExp(
      r'-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?',
    ).matchAsPrefix(text, _i);
    if (match == null) _fail('invalid number');
    final raw = match.group(0)!;
    _i += raw.length;
    if (raw.contains('.') || raw.contains('e') || raw.contains('E')) {
      final value = double.tryParse(raw);
      if (value == null || !value.isFinite) _fail('invalid number');
      return value;
    }
    final value = int.tryParse(raw);
    if (value == null) _fail('invalid integer');
    return value;
  }

  List<Object?> _parseArray() {
    _i++; // [
    final out = <Object?>[];
    _skipWhitespace();
    if (_i < _length && text.codeUnitAt(_i) == 0x5d) {
      _i++;
      return out;
    }
    while (true) {
      out.add(_parseValue());
      _skipWhitespace();
      if (_i >= _length) _fail('unterminated array');
      final ch = text.codeUnitAt(_i);
      if (ch == 0x2c) {
        _i++;
        continue;
      }
      if (ch == 0x5d) {
        _i++;
        return out;
      }
      _fail('expected "," or "]"');
    }
  }

  Map<String, Object?> _parseObject() {
    _i++; // {
    final out = <String, Object?>{};
    final seen = <String>{};
    _skipWhitespace();
    if (_i < _length && text.codeUnitAt(_i) == 0x7d) {
      _i++;
      return out;
    }
    while (true) {
      _skipWhitespace();
      if (_i >= _length || text.codeUnitAt(_i) != 0x22) {
        _fail('expected object key string');
      }
      final key = _parseString();
      if (seen.contains(key)) _fail('duplicate object key "$key"');
      seen.add(key);
      _skipWhitespace();
      if (_i >= _length || text.codeUnitAt(_i) != 0x3a) {
        _fail('expected ":" after object key');
      }
      _i++;
      out[key] = _parseValue();
      _skipWhitespace();
      if (_i >= _length) _fail('unterminated object');
      final ch = text.codeUnitAt(_i);
      if (ch == 0x2c) {
        _i++;
        continue;
      }
      if (ch == 0x7d) {
        _i++;
        return out;
      }
      _fail('expected "," or "}"');
    }
  }
}
