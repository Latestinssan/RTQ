/**
 * Deterministic canonical serialization.
 *
 * RTQ hashes inputs, policy contexts and ticket bodies. Two logically-equal
 * objects MUST produce byte-identical strings on every platform, otherwise an
 * attacker could substitute parameters by reordering object keys and watch the
 * authorization decision drift from the executed payload.
 *
 * `canonicalStringify` recursively sorts object keys (including nested
 * objects) and handles arrays, numbers, strings, booleans, null and undefined.
 * Non-finite numbers are rejected because `JSON.stringify` would silently
 * serialize them as `null`, which breaks determinism guarantees.
 */

export type CanonicalValue =
  | string
  | number
  | boolean
  | null
  | undefined
  | CanonicalValue[]
  | { [key: string]: CanonicalValue };

function stringifyValue(value: CanonicalValue, out: string[]): void {
  if (value === null || value === undefined) {
    out.push("null");
    return;
  }
  switch (typeof value) {
    case "string":
      out.push(JSON.stringify(value));
      return;
    case "number":
      if (!Number.isFinite(value)) {
        throw new TypeError(
          `cannot canonically serialize non-finite number: ${value}`,
        );
      }
      out.push(String(value));
      return;
    case "boolean":
      out.push(value ? "true" : "false");
      return;
    case "object":
      if (Array.isArray(value)) {
        out.push("[");
        for (let i = 0; i < value.length; i++) {
          if (i > 0) out.push(",");
          stringifyValue(value[i] as CanonicalValue, out);
        }
        out.push("]");
        return;
      }
      {
        const record = value as Record<string, unknown>;
        const keys = Object.keys(record).sort();
        out.push("{");
        for (let i = 0; i < keys.length; i++) {
          if (i > 0) out.push(",");
          out.push(JSON.stringify(keys[i]));
          out.push(":");
          stringifyValue(record[keys[i]] as CanonicalValue, out);
        }
        out.push("}");
        return;
      }
    default:
      throw new TypeError(
        `cannot canonically serialize value of type "${typeof value}"`,
      );
  }
}

/**
 * Canonically stringify a value with recursively sorted keys.
 * Throws on non-finite numbers and non-plain structures.
 */
export function canonicalStringify(value: unknown): string {
  // Every value type (including primitives) is serialized through the same
  // writer so booleans/numbers/strings cannot drift and so a serialized string
  // can be re-serialized deterministically (canonical is idempotent).
  const out: string[] = [];
  stringifyValue(value as CanonicalValue, out);
  return out.join("");
}

/**
 * Deep-freeze a value so a stored ticket body cannot be mutated in place.
 * Returns a frozen copy rather than mutating the caller's object when
 * `copy` is true (the default).
 */
export function deepFreeze<T>(input: T, copy = true): T {
  const target: unknown = copy ? structuredClone(input) : input;
  if (target !== null && typeof target === "object") {
    for (const key of Object.getOwnPropertyNames(target)) {
      const value = (target as Record<string, unknown>)[key];
      if (value !== null && typeof value === "object") {
        deepFreeze(value, false);
      }
    }
    Object.freeze(target);
  }
  return target as T;
}
