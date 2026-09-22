# @rtq/crypto

**The cryptographic kernel RTQ trusts — deterministic, canonical, and
fail-closed.** `@rtq/crypto` provides the primitives the §46 security pipeline,
the §46 MCP credential vault, and the mobile approval host build on, all pinned
to a single canonical representation so RTQ can reason about *what was signed*
with byte-for-byte certainty — never a heuristic.

## Guarantees

- **Canonical serialization** (`canonicalStringify` / `canonicalize`) — one
  RTQ dialect for everything RTQ hashes/signs. Keys are canonical (sorted,
  non-NUL, non-duplicate), numbers conform to RTQ JSON grammar, and the
  canonical form is **idempotent** (canonical(canonical(x)) = canonical(x));
  hashing the same fact twice yields the same digest, or the fact didn't
  canonicalize and RTQ fails closed.
- **Deterministic hashing** — `sha256Hex` over canonical bytes; RTQ NEVER
  hashes "raw JSON as typed by the server" — it hashes the *normalized*
  tool/arguments/schema (§46 canonical form). Duplicate/inconsistent
  canonicalization → failure.
- **Ed25519 signatures** — `ed25519Sign` / `ed25519Verify` for host + device
  keys, with RTQ key-binding (fact signed = binding ticket + capability +
  arguments hash). Detection of a tampered/signed key, unsupported algo →
  deny (§46.21, §46.11 #2).
- **Credential protection** — `redactValue`/`redactCanonicalJson` ensure
  secret-shaped fields (`SECRET_FIELD_NAMES`: password, token, secret, key,
  credential...) are never written to audit/tickets (§46.27 #17–#19,
  §46.25 #28 #29). An unredactable path fails closed (denied, not "best
  effort").
- **Strict JSON + canonical key rules** — `strictJsonParse` rejects
  `__proto__`/`constructor`-whose keys, non-finite numbers, and depth beyond
  limits; a schema that can't be parsed safely is `incomplete` (§46.30
  #13–#17), never guessed.

## What's inside

- `canonicalStringify`, `canonicalize`, `canonicalizeJson`, `canonicalJson`
- `sha256Hex`, `hmacSha256Hex` (HMAC for idempotency/signature keys)
- `ed25519Sign`, `ed25519Verify`, `generateEd25519KeyPair`,
  `importEd25519PublicKey` — device + host key bindings
- `randomHex`, `inputHash`, `signString`, `verifySignatureString`,
  `computeArgumentHash` — ticket + approval binding digests
- `redactValue`, `redactCanonicalJson`, `SECRET_FIELD_NAMES` — secret-shaped
  key avoidance
- `strictJsonParse`, `canonicalize` strict-JSON dialect, `McpCredentialClass`

## Why canonicalization is security

RTQ's ticket hash, schema hash, and approval signature all depend on the
*exact* bytes being identical across server, policy, risk, and approval. If
JSON canonicalization were non-deterministic (key order, whitespace, number
lexeme), then the same "read_file" tool could hash differently between
authorize and execute — letting a ticket authorize one capability and be
replayed against another. Canonical, idempotent, fail-closed.

## License

Apache-2.0
