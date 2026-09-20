/**
 * Strict JSON parser for security-critical payloads.
 *
 * `JSON.parse` is permissive in ways that are dangerous for a protocol that
 * crosses implementations: duplicate object keys silently collapse (last one
 * wins), and different engines may disagree on which duplicate wins. An
 * attacker who can craft a payload with duplicate keys can therefore make the
 * device display one value while the host verifies another.
 *
 * This parser rejects duplicate keys, trailing content, unterminated strings,
 * unescaped control characters, and non-finite/leading-zero numbers. It returns
 * the same shapes as `JSON.parse` for well-formed input, so callers can use it
 * as a drop-in for untrusted data.
 */

export class StrictJsonError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "StrictJsonError";
  }
}

const WHITESPACE = new Set([" ", "\t", "\n", "\r"]);
const NUMBER_RE = /-?(?:0|[1-9][0-9]*)(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?/;

/** Parse JSON, rejecting duplicate keys and malformed structure. */
export function strictJsonParse(text: string): unknown {
  if (typeof text !== "string") {
    throw new StrictJsonError("input must be a string");
  }
  let i = 0;
  const len = text.length;

  function fail(message: string): never {
    throw new StrictJsonError(`${message} (at offset ${i})`);
  }

  function skipWhitespace(): void {
    while (i < len && WHITESPACE.has(text[i] as string)) i += 1;
  }

  function parseString(): string {
    // assumes text[i] === '"'
    i += 1;
    let out = "";
    for (;;) {
      if (i >= len) fail("unterminated string");
      const ch = text[i] as string;
      if (ch === '"') {
        i += 1;
        return out;
      }
      if (ch === "\\") {
        i += 1;
        if (i >= len) fail("unterminated escape");
        const esc = text[i] as string;
        switch (esc) {
          case '"':
            out += '"';
            i += 1;
            break;
          case "\\":
            out += "\\";
            i += 1;
            break;
          case "/":
            out += "/";
            i += 1;
            break;
          case "b":
            out += "\b";
            i += 1;
            break;
          case "f":
            out += "\f";
            i += 1;
            break;
          case "n":
            out += "\n";
            i += 1;
            break;
          case "r":
            out += "\r";
            i += 1;
            break;
          case "t":
            out += "\t";
            i += 1;
            break;
          case "u": {
            const hex = text.slice(i + 1, i + 5);
            if (!/^[0-9a-fA-F]{4}$/.test(hex)) fail("invalid \\u escape");
            out += String.fromCharCode(parseInt(hex, 16));
            i += 5;
            break;
          }
          default:
            fail(`invalid escape sequence \\${esc}`);
        }
        continue;
      }
      // Raw control characters are not permitted in JSON strings.
      if (ch.charCodeAt(0) < 0x20) fail("unescaped control character");
      out += ch;
      i += 1;
    }
  }

  function parseNumber(): number {
    const match = NUMBER_RE.exec(text.slice(i));
    if (!match || match.index !== 0) fail("invalid number");
    const raw = match[0];
    i += raw.length;
    const value = Number(raw);
    if (!Number.isFinite(value)) fail("non-finite number");
    return value;
  }

  function parseArray(): unknown[] {
    i += 1; // consume '['
    const out: unknown[] = [];
    skipWhitespace();
    if (i < len && text[i] === "]") {
      i += 1;
      return out;
    }
    for (;;) {
      out.push(parseValue());
      skipWhitespace();
      if (i >= len) fail("unterminated array");
      const ch = text[i] as string;
      if (ch === ",") {
        i += 1;
        continue;
      }
      if (ch === "]") {
        i += 1;
        return out;
      }
      fail(`expected ',' or ']' but found '${ch}'`);
    }
  }

  function parseObject(): Record<string, unknown> {
    i += 1; // consume '{'
    const out: Record<string, unknown> = {};
    const seen = new Set<string>();
    skipWhitespace();
    if (i < len && text[i] === "}") {
      i += 1;
      return out;
    }
    for (;;) {
      skipWhitespace();
      if (i >= len || text[i] !== '"') fail("expected object key string");
      const key = parseString();
      if (seen.has(key)) fail(`duplicate object key "${key}"`);
      seen.add(key);
      skipWhitespace();
      if (i >= len || text[i] !== ":") fail("expected ':' after object key");
      i += 1; // consume ':'
      out[key] = parseValue();
      skipWhitespace();
      if (i >= len) fail("unterminated object");
      const ch = text[i] as string;
      if (ch === ",") {
        i += 1;
        continue;
      }
      if (ch === "}") {
        i += 1;
        return out;
      }
      fail(`expected ',' or '}' but found '${ch}'`);
    }
  }

  function parseValue(): unknown {
    skipWhitespace();
    if (i >= len) fail("unexpected end of input");
    const ch = text[i] as string;
    if (ch === "{") return parseObject();
    if (ch === "[") return parseArray();
    if (ch === '"') return parseString();
    if (ch === "-" || (ch >= "0" && ch <= "9")) return parseNumber();
    if (text.startsWith("true", i)) {
      i += 4;
      return true;
    }
    if (text.startsWith("false", i)) {
      i += 5;
      return false;
    }
    if (text.startsWith("null", i)) {
      i += 4;
      return null;
    }
    fail(`unexpected token '${ch}'`);
  }

  const value = parseValue();
  skipWhitespace();
  if (i !== len) fail("unexpected trailing content");
  return value;
}
