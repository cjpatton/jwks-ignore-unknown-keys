# Vendored test vectors

`draft-composite-sigs-testvectors.json` is `src/testvectors.json` from
https://github.com/lamps-wg/draft-composite-sigs at commit
`b9e2674c0072df66ea09abeabc1c1be5ef9baf29`, copied unmodified.

`generate.py` uses only the `pk` field of the pure ML-DSA and composite ML-DSA entries, as the
`pub` value of AKP keys (RFC 9964, draft-ietf-jose-pq-composite-sigs-06).

These are IETF Code Components: Copyright (c) IETF Trust and the persons identified as the document
authors, licensed under the Revised BSD License (see the upstream `license.txt`).
