import type { Schema } from "./types";

/**
 * RTQ input schema validator.
 *
 * Deliberately small and dependency-free: the validation surface is part of
 * the security boundary and is kept auditable. Supports object/array/string/
 * number/boolean/null, enums, oneOf, and `any`. Rejects non-finite numbers,
 * prototype-pollution attempts, unknown keys (when flagged) and type errors.
 *
 * This is NOT a general JSON Schema implementation. Do not pass untrusted
 * schemas: capabilities are registered by trusted application code.
 */

export interface ValidationFailure {
  path: string;
  message: string;
}

export type ValidationResult =
  { valid: true } | { valid: false; errors: ValidationFailure[] };

function fail(
  errors: ValidationFailure[],
  path: string,
  message: string,
): void {
  errors.push({ path: path || "$", message });
}

function isSchema(value: unknown): value is Schema {
  return value !== null && typeof value === "object";
}

function assertSafeKey(
  key: string,
  errors: ValidationFailure[],
  path: string,
): void {
  if (key === "__proto__" || key === "constructor" || key === "prototype") {
    fail(errors, path, `unsafe object key "${key}"`);
  }
}

function validateArray(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  if (!Array.isArray(value)) {
    fail(errors, path, `expected array, got ${typeof value}`);
    return;
  }
  const min = typeof schema.minItems === "number" ? schema.minItems : undefined;
  const max = typeof schema.maxItems === "number" ? schema.maxItems : undefined;
  if (min !== undefined && value.length < min)
    fail(errors, path, `array shorter than minItems (${min})`);
  if (max !== undefined && value.length > max)
    fail(errors, path, `array longer than maxItems (${max})`);
  if (isSchema(schema.items)) {
    value.forEach((item, i) =>
      validateValue(item, schema.items as Schema, `${path}[${i}]`, errors),
    );
  }
}

function validateObject(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  if (value === null || typeof value !== "object" || Array.isArray(value)) {
    fail(
      errors,
      path,
      `expected object, got ${value === null ? "null" : typeof value}`,
    );
    return;
  }
  const properties = (schema.properties ?? {}) as Record<string, Schema>;
  const required = (schema.required ?? []) as string[];

  // Secure default: an object schema MUST declare either a "required" list or
  // an explicit additionalProperties policy. MCP-normalized schemas declare
  // `additionalProperties: false` even for tools with zero required arguments,
  // so this remains auditable without rejecting legitimate optional-only tools.
  const hasDeclaredRequired = Array.isArray(schema.required);
  const hasAdditionalPolicy = "additionalProperties" in schema;
  if (!hasDeclaredRequired && !hasAdditionalPolicy) {
    fail(
      errors,
      path,
      'object schema must declare a "required" list or an additionalProperties policy',
    );
  }

  if (hasDeclaredRequired) {
    for (const key of required) {
      if (!(key in (value as Record<string, unknown>))) {
        fail(errors, path, `missing required field "${key}"`);
      }
    }
  }

  const additional = schema.additionalProperties;
  for (const key of Object.keys(value as Record<string, unknown>)) {
    assertSafeKey(key, errors, path);
    if (key in properties) continue;
    if (additional === false) {
      fail(
        errors,
        `${path}.${key}`,
        "unexpected field (additionalProperties: false)",
      );
    } else if (isSchema(additional)) {
      validateValue(
        (value as Record<string, unknown>)[key],
        additional,
        `${path}.${key}`,
        errors,
      );
    }
  }

  for (const [key, subSchema] of Object.entries(properties)) {
    if (!(key in (value as Record<string, unknown>))) continue;
    validateValue(
      (value as Record<string, unknown>)[key],
      subSchema,
      `${path}.${key}`,
      errors,
    );
  }
}

function validateString(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  if (typeof value !== "string") {
    fail(errors, path, `expected string, got ${typeof value}`);
    return;
  }
  if (typeof schema.maxLength === "number" && value.length > schema.maxLength) {
    fail(errors, path, `string longer than maxLength (${schema.maxLength})`);
  }
  if (typeof schema.minLength === "number" && value.length < schema.minLength) {
    fail(errors, path, `string shorter than minLength (${schema.minLength})`);
  }
  if (Array.isArray(schema.enum) && !schema.enum.includes(value)) {
    fail(errors, path, `value not in enum [${schema.enum.join(", ")}]`);
  }
  if (typeof schema.pattern === "string") {
    try {
      if (!new RegExp(schema.pattern).test(value)) {
        fail(errors, path, `value does not match pattern ${schema.pattern}`);
      }
    } catch {
      fail(
        errors,
        path,
        `schema pattern "${schema.pattern}" is not a valid regular expression`,
      );
    }
  }
}

function validateNumber(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  if (typeof value !== "number" || !Number.isFinite(value)) {
    fail(errors, path, "expected a finite number");
    return;
  }
  if (schema.integer === true && !Number.isInteger(value)) {
    fail(errors, path, "expected an integer");
  }
  if (typeof schema.min === "number" && value < schema.min)
    fail(errors, path, `value below min (${schema.min})`);
  if (typeof schema.max === "number" && value > schema.max)
    fail(errors, path, `value above max (${schema.max})`);
}

function validateLiteral(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  const expected = schema.value;
  if (value !== expected) {
    fail(
      errors,
      path,
      `expected literal ${JSON.stringify(expected)}, got ${JSON.stringify(value)}`,
    );
  }
}

function validateOneOf(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  const variants = Array.isArray(schema.oneOf) ? schema.oneOf : [];
  if (variants.length === 0) {
    fail(errors, path, 'oneOf schema must declare a non-empty "oneOf" list');
    return;
  }
  const firstFailure: ValidationFailure[] = [];
  const matches: { errors: ValidationFailure[] }[] = [];
  for (const variant of variants) {
    const subErrors: ValidationFailure[] = [];
    validateValue(value, variant as Schema, path, subErrors);
    if (subErrors.length === 0) matches.push({ errors: subErrors });
    else if (firstFailure.length === 0) firstFailure.push(...subErrors);
  }
  if (matches.length !== 1) {
    fail(
      errors,
      path,
      `expected value matching exactly one of ${variants.length} oneOf variants (matched ${matches.length})`,
    );
  }
}

function validateEnum(
  value: unknown,
  schema: Schema,
  path: string,
  errors: ValidationFailure[],
): void {
  const values = Array.isArray(schema.enum) ? schema.enum : [];
  if (values.length === 0) {
    fail(errors, path, 'enum schema must declare a non-empty "enum" list');
    return;
  }
  const matches = values.some((v) => {
    try {
      return JSON.stringify(v) === JSON.stringify(value);
    } catch {
      return false;
    }
  });
  if (!matches) {
    fail(
      errors,
      path,
      `value not in enum [${values.map((v) => JSON.stringify(v)).join(", ")}]`,
    );
  }
}

export function validateValue(
  value: unknown,
  schema: Schema,
  path = "$",
  errors: ValidationFailure[] = [],
): void {
  if (!isSchema(schema)) {
    fail(errors, path, "invalid schema");
    return;
  }

  if (Array.isArray(schema.oneOf)) {
    validateOneOf(value, schema, path, errors);
    return;
  }
  if (Array.isArray(schema.enum) && schema.type === undefined) {
    validateEnum(value, schema, path, errors);
    return;
  }
  if ("value" in schema && schema.type === "literal") {
    validateLiteral(value, schema, path, errors);
    return;
  }

  const type = schema.type as string | undefined;
  switch (type) {
    case "any":
      return;
    case "string":
      validateString(value, schema, path, errors);
      return;
    case "number":
      validateNumber(value, schema, path, errors);
      return;
    case "boolean":
      if (typeof value !== "boolean")
        fail(errors, path, `expected boolean, got ${typeof value}`);
      return;
    case "null":
      if (value !== null) fail(errors, path, "expected null");
      return;
    case "array":
      validateArray(value, schema, path, errors);
      return;
    case "object":
      validateObject(value, schema, path, errors);
      return;
    default:
      fail(errors, path, `unsupported schema type "${type}"`);
  }
}

export function validateAgainstSchema(
  value: unknown,
  schema: Schema,
): ValidationResult {
  const errors: ValidationFailure[] = [];
  validateValue(value, schema, "$", errors);
  return errors.length === 0 ? { valid: true } : { valid: false, errors };
}
