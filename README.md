# jwt-ossification-tests

These fixtures test whether a JWT relying party can verify a token as its
issuer changes the contents of a JSON Web Key Set (JWKS). For example, an
issuer can publish ML-DSA public keys alongside an existing RSA signing key
while relying parties continue to verify RSA-signed tokens.

[RFC 7517 §5][jwks] recommends skipping individual JWKs with unsupported key
types, missing required members, or values outside the supported ranges.
[Sections 4][jwk] and [5][jwks] require ignoring unrecognized member names on
a JWK or on the set itself. [RFC 7515 Appendix D][selection] describes key
selection as application-specific.

## Running the fixtures

For each entry in [`cases.json`](cases.json), read the JWT at `token` and the
JWKS at `jwks`, then pass both to the verifier. These paths are relative to
the repository root and point into [`tokens/`](tokens/) and [`jwks/`](jwks/),
respectively. Report results by `name`, since several cases use the same JWKS
with different tokens. The `expected` value is `verify` when the signature and
configured claim checks should succeed, or `reject` when verification should
fail under the algorithm requirements or the fixture's selection policy.

Rejection cases also specify a `failure` reason.

- `no-eligible-key` means key selection yields zero candidates for the JWT.
- `signature-mismatch` means selection yields a key and the signature check
  fails with that key.
- `rsa-modulus-too-small` means the signing key's RSA modulus is smaller than
  the minimum required by the JWT's algorithm.
- `algorithm-not-accepted` means the JWT declares an algorithm outside the
  supported or permitted algorithms for verification with the supplied JWKS.

Check both the outcome and the reason when the verifier exposes them. An API
that exposes only success or failure can confirm rejection. Report the reason
as unobserved in that case.

Pass the complete JWKS to the verification API so the test exercises that
implementation's key selection. If the API only accepts a single key, report
which selection logic the test harness supplies. The selection cases exercise
a policy described in [RFC 7515 Appendix D][selection] that filters for the JWT's `kid`
when present and respects any declared JWK `alg`, `use`, or `key_ops`. A JWT
without `kid` can use a JWK that has one. Enable the selection policy being
tested and report it with the results. For claim checks, use issuer
`https://issuer.example` and audience `jwks-tolerance-test`.

Cases marked `"selection": "try-candidates"` exercise a verifier's candidate
retry policy. Skip candidates that fail to import and continue after a
signature mismatch. Stop when a key verifies the JWT or the eligible
candidates are exhausted. If a verifier reports ambiguity by default, use
its opt-in retry mode or supply that policy in the application. The expected
result is the outcome under the retry policy. The other fixtures exercise
ordinary verification.

## Coverage

| Prefix | What the fixture tests |
| --- | --- |
| `00` | RS256 verification with the signing key as the only member of the JWKS. |
| `A` | Pure ML-DSA and composite public keys alongside a traditional signing key. |
| `B01–B04` | Unknown `kty` values and members on unknown key types. |
| `B05` | An unknown `kty` shares the RS256 signer's `kid`, `alg`, and `use`. Skip the unknown type and verify with the RSA signer. |
| `C01–C06` | Unknown or unsupported `crv`, `alg`, or key material on unrelated keys. |
| `C07` | A 1024-bit RSA key matches the JWT's `kid` and `alg` and produces a valid PKCS #1 v1.5 signature. Reject because [RFC 7518 §3.3][rs256] requires a key of at least 2048 bits for RS256. |
| `D` | Required JWK members missing from unrelated keys. |
| `E` | Unrecognized `use` or `key_ops` on unrelated keys. |

### Curves and extension members

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `F01` | Verify | The JWKS for an ES256 token contains two EC keys with the same `kid`. Both omit JWK `alg`. Ignore the key declaring the unrecognized curve `P-999` and use the P-256 signer. |
| `F02` | Verify | The alternate key in F01 instead declares the supported curve `P-384`. Select the P-256 signer because ES256 requires P-256. |
| `G01` | Verify | The signing JWK contains an unrecognized member named with a URI and carrying a structured JSON value. Ignore the member and use the signing key. |
| `G02` | Verify | An unrecognized member named with a URI and carrying an object value appears on the JWKS itself. Ignore it and read the signing key from `keys`. |

### Basic key selection

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `H01` | Verify | Two RSA verification keys declare RS256 and have different IDs. Use the `kid` in the JWT to select the signer, which appears second. |
| `H02` | Verify | The JWT and the only RSA JWK both omit `kid`. Select the sole eligible key using the JWT's RS256 algorithm. |
| `H03` | Reject | The JWKS has the correct signing key material under a different `kid`. Reject because the JWT's explicit ID has no match. |
| `H04` | Reject | The only key matches the JWT's `kid` and algorithm. Its public key differs from the signer's, so signature verification fails. |
| `H05` | Reject | The signing JWK matches the RS256 token's `kid` and declares `alg: "RS384"`. Key selection yields `no-eligible-key`. |
| `H06` | Reject | The JWT's `kid` matches an EC key, which is incompatible with RS256. The RSA signing key has a different ID. Key selection yields `no-eligible-key`. |
| `H07` | Reject | The JWT supplies a `kid` and every JWK, including the signing key, omits it. Key selection yields `no-eligible-key`. |

### Selection from a mixed set and candidate retry

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `I01` | Verify | For an RS256 token without `kid`, skip an RSA key declared for RS384, an encryption-only RSA key, and an EC key. The signer is the sole eligible key and omits JWK `alg`. |
| `I02` | Reject | The same set declares `alg: "RS384"` on the signing key as well. The key material can verify the signature, yet no key is eligible for RS256. |
| `I03` | Verify with retry | Two RSA entries match the selection metadata. The first lacks `e` and fails to import. The retry policy skips it and verifies with the signer. |
| `I04` | Verify with retry | Both matching RSA entries import. The first fails signature verification, so the retry policy continues to the signer. |
| `I05` | Verify | Every key in the mixed set has a `kid`, including the signer. The JWT omits `kid`, so select the sole eligible key using the algorithm and key intent. |

### Shared key IDs

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `J01` | Verify | RSA and EC keys share `kid: "2026-01"` and both omit JWK `alg`. The RS256 token selects the RSA key by type. |
| `J02` | Verify | The ES256 token selects the P-256 EC key from the same set as J01. |
| `J03` | Verify | Two RSA keys share `kid: "2026-01"`. The RS256 token selects the key declaring `alg: "RS256"`. |
| `J04` | Verify | The RS384 token selects the other RSA key, which declares `alg: "RS384"`, from the same set as J03. |

### Algorithm and key intent

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `K01` | Verify | Two RSA keys share the signer's `kid` and both declare `use: "sig"`. Skip the key declaring an unrecognized URI as its `alg` and select the one declaring RS256. |
| `L01` | Verify | Two RSA keys share a `kid` and declare their intent with `use`. Skip `use: "enc"` and select `use: "sig"`. |
| `L02` | Verify | Replace `"enc"` in L01 with an unrecognized URI. Skip that key and select the signature key. |
| `L03` | Verify | Two RSA keys share a `kid` and declare their intent with `key_ops`. Skip `["encrypt"]` and select `["verify"]`. |
| `L04` | Verify | Replace `"encrypt"` in L03 with an unrecognized operation. The alternate key lacks `"verify"`, so select the signer. |
| `L05` | Verify | The alternate key declares `["verify", "verify"]`. Skip that key because its operation list contains a duplicate. Select the key with a single `"verify"` entry. |
| `L06` | Reject | The only JWK holds the correct signing key and declares `use: "enc"`. The declared intent rules it out for signature verification. |
| `L07` | Reject | The only JWK holds the correct signing key and declares `key_ops: ["encrypt"]`. The operation list does not include verification. |
| `L08` | Verify | The signer declares `"verify"` alongside a URI identifying a hypothetical related signature-verification operation. The verifier uses the recognized `"verify"` operation. |

[RFC 7517 §4.5][kid] recommends distinct `kid` values within a set and gives
different key types as one example where keys might share an identifier. The
repeated-`kid` cases specify which key is eligible for the JWT's algorithm.
[RFC 7517 §4.3][key-ops] recommends using `use` and `key_ops` separately and
permits extension operations. L08 exercises a policy that accepts a key for
its declared `verify` operation alongside a related extension operation.

### Algorithm acceptance

M01–M03 use a verification policy that requires a digital signature and
takes its keys from the public JWKS. [RFC 7519 §6][unsecured-jwt] defines an
Unsecured JWT with `alg: "none"` and an empty signature.
[RFC 7518 §3.6][unsecured-jws] requires explicit application permission to
accept an unsecured object. The `alg` value is case-sensitive under
[RFC 7515 §4.1.1][jws-alg].

| Case | Expected | What the fixture tests |
| --- | --- | --- |
| `M01` | Reject | The token declares `alg: "none"` and has an empty signature. The policy requires a digital signature. |
| `M02` | Reject | The token declares `alg: "NONE"` and has an empty signature. The uppercase spelling is an unrecognized algorithm. |
| `M03` | Reject | The token declares `alg: "nonE"` and has an empty signature. The mixed-case spelling is an unrecognized algorithm. |
| `M04` | Reject | The HS256 token's `kid` matches an RSA public key, and that key's PEM encoding is the MAC key. Key selection yields `no-eligible-key` before any MAC check. |

## Regenerating the fixtures

Run `python3 generate.py` with Python's `cryptography` package installed and
ML-DSA support available (tested with version 50). The generator uses the
synthetic private signing keys in `testdata/keys/` and the example public keys
in [`testdata/specs/`](testdata/specs/README.md). The private keys are public
test inputs for generating fixtures.

[hs256]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.2
[jwk]: https://www.rfc-editor.org/rfc/rfc7517.html#section-4
[jwks]: https://www.rfc-editor.org/rfc/rfc7517.html#section-5
[jws-alg]: https://www.rfc-editor.org/rfc/rfc7515.html#section-4.1.1
[key-ops]: https://www.rfc-editor.org/rfc/rfc7517.html#section-4.3
[kid]: https://www.rfc-editor.org/rfc/rfc7517.html#section-4.5
[rs256]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.3
[selection]: https://www.rfc-editor.org/rfc/rfc7515.html#appendix-D
[unsecured-jws]: https://www.rfc-editor.org/rfc/rfc7518.html#section-3.6
[unsecured-jwt]: https://www.rfc-editor.org/rfc/rfc7519.html#section-6
