# jwks-ignore-unknown-keys

Test cases for checking that a JWT relying party ignores JWKs it doesn't understand, instead of
rejecting the whole JWK Set.

RFC 7517 Section 5 says implementations SHOULD ignore keys "that use 'kty' (key type) values that are
not understood by them, that are missing required members, or for which values are out of the
supported ranges", and Section 4 says unknown JWK members MUST be ignored. Many libraries instead
fail closed on the first key they can't parse, which makes it unsafe to add new key types (for
example post-quantum AKP keys) to an existing JWKS.

## Layout

- `testdata/`: the test cases. See [`testdata/README.md`](testdata/README.md).
- `gen/generate.py`: regenerates `testdata/`. Requires Python 3 and `cryptography`.
- `gen/vectors/`: vendored ML-DSA and composite ML-DSA public keys used for the AKP cases.

## Using the test cases

Each file in `testdata/jwks/` is a JWK Set. Load it with the library under test and verify
`testdata/token.jwt` (RS256, `kid: rsa-1`). **Every case is expected to verify.** `testdata/cases.json`
lists the cases with a description and the RFC rule each one exercises.

## Regenerating

```sh
python3 gen/generate.py
```

Keys in `testdata/keys/` are reused, so the output is stable. Delete them to get fresh keys.
