# jwt-ossification-tests

Test cases for checking that a JWT relying party ignores JWKs it doesn't
understand instead of rejecting the whole JWK Set (JWKS). This behavior is
recommended by RFC 7517. For example, in Section 5:

> Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type)
> values that are not understood by them, that are missing required members, or
> for which values are out of the supported ranges.

Many implementations ignore this "SHOULD" and instead reject the entire JWKS
when it contains an unknown key type. This behavior makes it it difficult for
the identity providers to migrate to post-quantum. For example, an identity
provider that wants to add support for ML-DSA-44 (RFC 9964) would need to wait
for all of its relying parties to add support for the signature before adding
the public key to an existing JWKS.

This repository includes several test cases that exercise various ossification
issues in open source JWT libraries. Each file in `jwks/*.json` is a JWKS that
verifies `token.jwt`:

- `A01` through `A10`: These cases include JWK for a signature
    algorithm specified in RFC 9964 or draft-ietf-jose-pq-composite-sigs in the
    key set. These should be ignored by relying parties that don't yet support
    post-quantum.

- `B`: Unknown key types. These should be ignored by all
    relying parties since they're not real key types.

- `C`: Common key types (RSA and ECDSA) but have malformed
    parameters.

- `D`: Common key types with missing parameters.

- `E`: Unknown use or key operation.

Each JWKS also includes a JWK with a commonly supported key type that actually
issued `token.jwt`, which means an RFC-7517-compliant verifier would accept the
token with each JWKS.
