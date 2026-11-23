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
provider that wants to add support for ML-DSA (RFC 9964) or a composite scheme
(draft-ietf-jose-pq-composite-sigs) would need to wait for all of its relying
parties to add support for the signature before adding the public key to an
existing JWKS.

This repository includes several test cases (`jwks/`) that exercise various
ossification issues in open source JWT libraries.
