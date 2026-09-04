# Schema — the doctrine

This directory holds the "law" of SICA Accord: the frozen field sets and the
rule for how interfaces are derived from them.

## Field-set manifest (not JSON Schema)

A "schema" here is a **field-set manifest**: a list of the field *names* a
body must carry. Validation checks field-name set equality only — it does not
check field types, ranges, or values. The files use a `.fields.json` suffix
to make that contract honest. Field types and value constraints are out of
scope of this layer: the signer and verifier agree the *set* of fields, not a
type system on top of them.

## Schema freeze

A field set is a contract, not a convention: the signer and the verifier
agree the exact set of fields, and a body with any other field set fails
validation. Fields are filled, never invented.

`work_order.v1.fields.json` is the worked example used by the demo:

```json
{
  "schema_name": "work_order.v1",
  "version": "1",
  "frozen_fields": ["note", "schema_name", "schema_version", "seq", "target", "task_kind", "timestamp"]
}
```

`claim.v1.fields.json` is the field set for the exclusive-claim sketch
(see `validator/claim.py`).

## Schema-retrosynthesis

Interfaces are derived backward from what the final hop must act on, not
improvised per hop. The derivation goes:

1. Start from what the final hop must act on — the exact body it needs.
2. Write that body's field set as the frozen manifest.
3. Derive every upstream hand-off from that manifest, not from convenience.

The demo's body has exactly the fields the frozen manifest lists, and nothing
else. That is the whole point: the manifest is written first, and the chain is
built to match it.

## Canonical encoding — the full rule

The canonical encoding of a body is the one shared byte rule. It is pinned
here in full, independent of CPython, so another implementation can produce
byte-identical output from this specification alone. The golden vectors in
`canonical_golden.json` exercise every under-specified axis.

A body is a **parsed object** (not raw JSON text). The value is normalised to
plain JSON types, then serialised as:

```python
json.dumps(plain, sort_keys=True, separators=(",", ":"),
           ensure_ascii=True, allow_nan=False).encode("utf-8")
```

The complete rule:

- **Value domain.** A body may contain only: `object` (string-keyed mapping),
  `array`, `string`, `integer`, `boolean`, and `null`. **Floats are forbidden**
  — a governance contract uses integers and strings, never floats, and floats
  have no language-independent canonical form (Python's `repr` crosses from
  fixed to scientific notation, and `1` vs `1.0` differ). A float anywhere in
  the body (including `NaN` / `Infinity`) is rejected. This exclusion is
  **deliberate, not accidental**: pinning Python's float formatting is not
  portably specifiable, so floats are excluded outright rather than pinned —
  a reader should not "fix" this later.
- **Integer bound.** Integers must satisfy `|n| <= 2**53` (9,007,199,254,740,992),
  the exact range a JavaScript `Number` (IEEE 754 double) can represent. A
  larger integer is rejected: a foreign verifier parsing it loses precision and
  would compute different canonical bytes.
- **String mapping keys only.** A non-string key is rejected; it would
  otherwise collide with its string form (`{1: "a"}` vs `{"1": "a"}`).
- **Key sort domain.** Object keys are sorted by **Unicode code point**,
  ascending, recursively at every level. Sorting happens on the unescaped
  keys, before any escaping.
- **Compact separators.** `:` between key and value, `,` between members, no
  whitespace.
- **String escaping (RFC 8259 §7).** `"` -> `\"`, `\` -> `\\`, backspace
  (U+0008) -> `\b`, form feed (U+000C) -> `\f`, newline (U+000A) -> `\n`,
  carriage return (U+000D) -> `\r`, tab (U+0009) -> `\t`. Every other control
  character (U+0000-U+001F) -> `\u00XX`. Characters U+0080-U+FFFF ->
  `\uXXXX`. Characters above U+FFFF -> a **UTF-16 surrogate pair** (two
  `\uXXXX` escapes, high then low). This is exactly RFC 8259's string
  escaping, so any conforming encoder agrees byte-for-byte.
- **No Unicode normalisation.** NFC and NFD forms of the "same" string encode
  to different bytes. Callers must supply an agreed normal form.
- **Output is ASCII.** Because every non-ASCII character is escaped, the
  canonical text is pure ASCII, so the UTF-8 encoding is the identity.

The contract signs **parsed objects, not raw JSON text**. Duplicate keys in a
source document collapse at parse time (the last value wins) before anything
is hashed or signed. Two source texts that differ only in duplicate keys
yield the same signed object. If you need to detect duplicate-key input,
parse with duplicate-key rejection before constructing the object.

The hash of a body and every signature over it use this exact rule. Change
it and nothing verifies.
