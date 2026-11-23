# Vendored specifications

The `A` cases use the example public keys published in these documents:

- `rfc9964.txt`: https://www.rfc-editor.org/rfc/rfc9964.txt (ML-DSA, Appendix
    A.1)

- `draft-ietf-jose-pq-composite-sigs-06.txt`:
    https://www.ietf.org/archive/id/draft-ietf-jose-pq-composite-sigs-06.txt
    (composite ML-DSA, Appendix A.1)

`generate.py` extracts each Appendix A.1 example from the text and verifies it:
the `kid` must be the RFC 9964 thumbprint of the key and the example JWS must
verify against `pub`. It then writes the JWK without `priv`.
