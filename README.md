# jwks-ignore-unknown-keys

Test cases for checking that a JWT relying party ignores JWKs it doesn't
understand instead of rejecting the whole JWK Set (JWKS). This behavior is
recommended by RFC 7517, Section 5:

> Implementations SHOULD ignore JWKs within a JWK Set that use "kty"
> (key type) values that are not understood by them, that are missing
> required members, or for which values are out of the supported
> ranges.

RFC 7517 Section 5 says implementations SHOULD ignore keys "that use 'kty' (key type) values that are
not understood by them, that are missing required members, or for which values are out of the
supported ranges". Many libraries instead
fail closed on the first key they can't parse, which makes it unsafe to add new key types (for
example post-quantum AKP keys) to an existing JWKS.

## Layout

- `jwks/`: the test cases (JWK Sets, `cases.json`, tokens). See [`jwks/README.md`](jwks/README.md).
- `generate.py`: regenerates `jwks/`. Requires Python 3 and `cryptography`.
- `testdata/`: static inputs to `generate.py`:
  - `keys/`: private keys used to sign the tokens and build the odd entries. Test material only.
  - `vectors/`: vendored ML-DSA and composite ML-DSA public keys used for the AKP cases.

## Using the test cases

For each entry in `jwks/cases.json`, load the entry's `file` (a JWK Set) with the library under test
and verify the entry's `token` (`token.jwt` has `kid: rsa-1`; `token-nokid.jwt` has no `kid`). Both
paths are relative to `jwks/`. **Every case is expected to verify.** Each entry also has a
description and the RFC rule it exercises.

## Regenerating

```sh
python3 generate.py
```

Keys in `testdata/keys/` are reused, so the output is stable. Delete them to get fresh keys.
