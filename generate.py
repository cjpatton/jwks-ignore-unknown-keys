#!/usr/bin/env python3
"""Generate JWKS test cases for "relying party ignores what it doesn't understand".

Every case is a JWK Set containing one or more keys a typical library will not
understand, followed by the RSA key "rsa-1". token.jwt is signed by rsa-1 (RS256,
kid "rsa-1"), so it is expected to verify against every case.

Inputs live in testdata/: keys/ (cached so re-running produces stable output) and
specs/ (the RFC 9964 and draft-ietf-jose-pq-composite-sigs-06 text, whose example
keys are the A cases). Outputs are token.jwt and everything in jwks/.
"""

import base64
import hashlib
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    raise SystemExit("generate.py needs a version of cryptography with ML-DSA support (tested with 50)")

ROOT = Path(__file__).resolve().parent
TESTDATA = ROOT / "testdata"
KEYS = TESTDATA / "keys"
SPECS = TESTDATA / "specs"
OUT = ROOT / "jwks"

TOKEN_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "rsa-1"}
TOKEN_CLAIMS = {
    "iss": "https://issuer.example",
    "sub": "jwks-tolerance-test",
    "aud": "jwks-tolerance-test",
    "iat": 1767225600,  # 2026-01-01
    "exp": 4102444800,  # 2100-01-01
}

# A 512-bit RSA modulus for the C05 case. Modern cryptography libraries don't
# generate RSA moduli this small.
RSA_512_MODULUS = int(
    "d653a7633bf6313310cf76ddff0c18dc0e622bcd4e047469724758264b9a8324"
    "1158d8c21b27fb08606327be275d1f9ddae7767c2118e92179c6b464496728cb",
    16,
)

# ML-DSA parameter set -> (public key class, public key bytes, signature bytes) (FIPS 204)
MLDSA = {
    "ML-DSA-44": (mldsa.MLDSA44PublicKey, 1312, 2420),
    "ML-DSA-65": (mldsa.MLDSA65PublicKey, 1952, 3309),
    "ML-DSA-87": (mldsa.MLDSA87PublicKey, 2592, 4627),
}

# draft-ietf-jose-pq-composite-sigs-06 Tables 4 and 6: alg -> (ML-DSA, label, pre-hash, traditional)
COMPOSITE = {
    "ML-DSA-44-ES256": ("ML-DSA-44", "COMPSIG-MLDSA44-ECDSA-P256-SHA256", "sha256", ("ecdsa", ec.SECP256R1(), hashes.SHA256())),
    "ML-DSA-65-ES256": ("ML-DSA-65", "COMPSIG-MLDSA65-ECDSA-P256-SHA512", "sha512", ("ecdsa", ec.SECP256R1(), hashes.SHA256())),
    "ML-DSA-65-ES384": ("ML-DSA-65", "COMPSIG-MLDSA65-ECDSA-P384-SHA512", "sha512", ("ecdsa", ec.SECP384R1(), hashes.SHA384())),
    "ML-DSA-87-ES384": ("ML-DSA-87", "COMPSIG-MLDSA87-ECDSA-P384-SHA512", "sha512", ("ecdsa", ec.SECP384R1(), hashes.SHA384())),
    "ML-DSA-44-Ed25519": ("ML-DSA-44", "COMPSIG-MLDSA44-Ed25519-SHA512", "sha512", ("ed25519",)),
    "ML-DSA-65-Ed25519": ("ML-DSA-65", "COMPSIG-MLDSA65-Ed25519-SHA512", "sha512", ("ed25519",)),
    "ML-DSA-87-Ed448": ("ML-DSA-87", "COMPSIG-MLDSA87-Ed448-SHAKE256", "shake256", ("ed448",)),
}
COMPOSITE_PREFIX = b"CompositeAlgorithmSignatures2025"

# Order of the A cases.
AKP_ALGS = [*MLDSA, *COMPOSITE]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_int(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


def b64d(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def spec_appendix(path: Path, start: str, end: str) -> str:
    """Return the text between two section headings, without page headers and footers."""
    lines = [
        line for line in path.read_text(encoding="utf-8-sig").split("\n")
        if "\f" not in line
        and not re.search(r"\[Page \d+\]$", line)
        and not re.match(r"(RFC \d+|Internet-Draft) ", line)
    ]
    i = lines.index(start)
    j = lines.index(end, i)
    return "\n".join(lines[i + 1:j])


def json_objects(text: str) -> list:
    decoder, objs, i = json.JSONDecoder(), [], 0
    while (i := text.find("{", i)) != -1:
        obj, i = decoder.raw_decode(text, i)
        objs.append(obj)
    return objs


def unfold_rfc(text: str) -> str:
    """RFC 9964 wraps long strings at the margin with no marker: drop newlines inside strings."""
    out, in_str, escaped = [], False, False
    for ch in text:
        if in_str and ch == "\n":
            continue
        if ch == '"' and not escaped:
            in_str = not in_str
        escaped = ch == "\\" and not escaped
        out.append(ch)
    return "".join(out)


def unfold_rfc8792(text: str) -> str:
    """The draft uses RFC 8792 single-backslash wrapping: '\\' ends a folded line and the
    continuation's leading whitespace is removed (blank lines come from page breaks)."""
    return re.sub(r"\\\n[ \n]*", "", text)


def akp_thumbprint(jwk: dict) -> str:
    """RFC 9964 Section 6: RFC 7638 thumbprint over alg, kty and pub."""
    members = json.dumps({k: jwk[k] for k in ("alg", "kty", "pub")}, separators=(",", ":"), sort_keys=True)
    return b64u(hashlib.sha256(members.encode()).digest())


def verify_akp_jws(jwk: dict, jws: str):
    """Verify a JWS against an AKP key (RFC 9964 or draft-ietf-jose-pq-composite-sigs-06)."""
    head, body, sig = jws.split(".")
    alg, msg, sig, pub = jwk["alg"], f"{head}.{body}".encode(), b64d(sig), b64d(jwk["pub"])
    if json.loads(b64d(head))["alg"] != alg:
        raise ValueError("JWS alg does not match JWK alg")
    if alg in MLDSA:
        cls, pub_len, _ = MLDSA[alg]
        if len(pub) != pub_len:
            raise ValueError("wrong public key length")
        cls.from_public_bytes(pub).verify(sig, msg)
        return
    # Composite ML-DSA (draft-ietf-lamps-pq-composite-sigs): both components sign
    # M' = Prefix || Label || len(ctx) || ctx || PH(M), with ctx empty in JOSE; ML-DSA
    # uses the label as its context. Keys and signatures are ML-DSA || traditional.
    mldsa_alg, label, prehash, trad = COMPOSITE[alg]
    cls, pub_len, sig_len = MLDSA[mldsa_alg]
    ph = hashlib.shake_256(msg).digest(64) if prehash == "shake256" else hashlib.new(prehash, msg).digest()
    m_prime = COMPOSITE_PREFIX + label.encode() + b"\x00" + ph
    cls.from_public_bytes(pub[:pub_len]).verify(sig[:sig_len], m_prime, label.encode())
    trad_pub, trad_sig = pub[pub_len:], sig[sig_len:]
    if trad[0] == "ecdsa":
        ec.EllipticCurvePublicKey.from_encoded_point(trad[1], trad_pub).verify(trad_sig, m_prime, ec.ECDSA(trad[2]))
    elif trad[0] == "ed25519":
        ed25519.Ed25519PublicKey.from_public_bytes(trad_pub).verify(trad_sig, m_prime)
    else:
        ed448.Ed448PublicKey.from_public_bytes(trad_pub).verify(trad_sig, m_prime)


def spec_akp_keys() -> dict:
    """Extract the Appendix A.1 JOSE examples from RFC 9964 and the composite draft, check
    each one, and return alg -> public JWK exactly as published, minus "priv"."""
    examples = json_objects(unfold_rfc(spec_appendix(SPECS / "rfc9964.txt", "A.1.  JOSE", "A.2.  COSE")))
    examples += json_objects(unfold_rfc8792(spec_appendix(
        SPECS / "draft-ietf-jose-pq-composite-sigs-06.txt", "A.1.  JOSE", "A.2.  COSE")))
    keys = {}
    for ex in examples:
        jwk = {k: v for k, v in ex["jwk"].items() if k != "priv"}
        if jwk["kid"] != akp_thumbprint(jwk):
            raise SystemExit(f"{jwk['alg']}: kid is not the key's thumbprint; extraction is wrong")
        try:
            verify_akp_jws(jwk, ex["jws"])
        except (InvalidSignature, ValueError) as e:
            raise SystemExit(f"{jwk['alg']}: example JWS does not verify: {e!r}")
        keys[jwk["alg"]] = jwk
    if sorted(keys) != sorted(AKP_ALGS):
        raise SystemExit(f"expected examples for {AKP_ALGS}, found {list(keys)}")
    return keys


def load_or_create(name: str, factory):
    path = KEYS / f"{name}.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = factory()
    path.write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return key


def rsa_pub(key, **extra) -> dict:
    nums = key.public_key().public_numbers()
    return {"kty": "RSA", **extra, "n": b64u_int(nums.n), "e": b64u_int(nums.e)}


def ec_pub(key, crv: str, size: int, **extra) -> dict:
    nums = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": crv,
        **extra,
        "x": b64u(nums.x.to_bytes(size, "big")),
        "y": b64u(nums.y.to_bytes(size, "big")),
    }


def main():
    KEYS.mkdir(parents=True, exist_ok=True)
    OUT.mkdir(parents=True, exist_ok=True)
    for pattern in ("*.json", "*.jwt", "*.pem"):
        for old in OUT.glob(pattern):
            old.unlink()

    rsa1 = load_or_create("rsa-1", lambda: rsa.generate_private_key(65537, 2048))
    rsa_other = load_or_create("rsa-other", lambda: rsa.generate_private_key(65537, 2048))
    ec_p256 = load_or_create("ec-p256", lambda: ec.generate_private_key(ec.SECP256R1()))
    ec_k1 = load_or_create("ec-secp256k1", lambda: ec.generate_private_key(ec.SECP256K1()))
    ed448_key = load_or_create("ed448", ed448.Ed448PrivateKey.generate)

    rsa1_jwk = rsa_pub(rsa1, kid="rsa-1", use="sig", alg="RS256")

    token = sign_token(rsa1, TOKEN_HEADER)
    (ROOT / "token.jwt").write_text(token + "\n")

    # --- odd keys -----------------------------------------------------------
    akp = spec_akp_keys()

    akp_bad_len = dict(akp["ML-DSA-44"])
    akp_bad_len["kid"] = "akp-ml-dsa-44-bad-length"
    akp_bad_len["pub"] = b64u(b64d(akp["ML-DSA-44"]["pub"])[:-1])

    unknown_kty = {
        "kty": "https://example.com/jwk/kty/future",
        "kid": "unknown-kty",
        "use": "sig",
        "alg": "https://example.com/jws/alg/future",
        "k1": b64u(b"opaque future key material"),
    }
    # Modeled on TLS GREASE (RFC 8701): a meaningless kty, no use/alg, and members of
    # unexpected JSON types. Member names are deliberately unregistered so this
    # doesn't overlap with unknown_kty_bad_member below. Values are fixed so results
    # are reproducible.
    grease = {
        "kty": "GREASE-0a0a",
        "kid": "grease",
        "grease-a": "AAAA",
        "grease-b": 1,
        "grease-c": [True, None],
        "grease-d": {"e": "f"},
    }
    # Same as unknown_kty, plus "d" holding an object. "d" is registered (RSA/EC/OKP
    # private key) as a base64url string, but its meaning is defined per kty, so for
    # an unknown kty it is just another member. Parsers that decode registered
    # members before looking at kty reject it.
    unknown_kty_bad_member = {**unknown_kty, "kid": "unknown-kty-bad-member", "d": {"e": "f"}}
    kty_wrong_case = rsa_pub(rsa_other, kid="kty-lowercase", use="sig", alg="RS256")
    kty_wrong_case["kty"] = "rsa"

    ec_unknown_crv = ec_pub(ec_p256, "P-999", 32, kid="ec-unknown-crv", use="sig")
    okp_ed448 = {
        "kty": "OKP",
        "crv": "Ed448",
        "kid": "okp-ed448",
        "use": "sig",
        "alg": "EdDSA",
        "x": b64u(
            ed448_key.public_key().public_bytes(
                serialization.Encoding.Raw, serialization.PublicFormat.Raw
            )
        ),
    }
    ec_secp256k1 = ec_pub(ec_k1, "secp256k1", 32, kid="ec-secp256k1", use="sig", alg="ES256K")
    rsa_unknown_alg = rsa_pub(rsa_other, kid="rsa-unknown-alg", use="sig", alg="RS999")
    rsa_512 = {
        "kty": "RSA",
        "kid": "rsa-512",
        "use": "sig",
        "alg": "RS256",
        "n": b64u_int(RSA_512_MODULUS),
        "e": "AQAB",
    }

    rsa_missing_e = rsa_pub(rsa_other, kid="rsa-missing-e", use="sig", alg="RS256")
    del rsa_missing_e["e"]
    ec_missing_y = ec_pub(ec_p256, "P-256", 32, kid="ec-missing-y", use="sig", alg="ES256")
    del ec_missing_y["y"]

    # Unregistered value, written as a collision-resistant name per RFC 7517 Sections 4.2 and 4.3.
    unknown_op = "https://example.com/jwk/future"
    ec_unknown_use = ec_pub(ec_p256, "P-256", 32, kid="ec-unknown-use", use=unknown_op, alg="ES256")
    ec_unknown_key_ops = ec_pub(ec_p256, "P-256", 32, kid="ec-unknown-key-ops", alg="ES256")
    ec_unknown_key_ops["key_ops"] = [unknown_op]

    # Each case is the odd key(s) followed by rsa-1.
    cases = [("00-baseline", [])]  # harness sanity check
    for i, alg in enumerate(AKP_ALGS, start=1):
        cases.append((f"A{i:02d}-akp-{alg.lower()}", [akp[alg]]))
    cases += [
        ("B01-unknown-kty", [unknown_kty]),
        ("B02-kty-wrong-case", [kty_wrong_case]),  # kty is case-sensitive, so "rsa" is not RSA
        ("B03-grease", [grease]),
        ("B04-unknown-kty-registered-member", [unknown_kty_bad_member]),
        ("C01-ec-unknown-crv", [ec_unknown_crv]),
        ("C02-okp-ed448", [okp_ed448]),  # RFC 8037, often unsupported
        ("C03-ec-secp256k1", [ec_secp256k1]),  # RFC 8812, often unsupported
        ("C04-rsa-unknown-alg", [rsa_unknown_alg]),
        ("C05-rsa-512", [rsa_512]),  # below most minimum key sizes
        ("C06-akp-ml-dsa-44-bad-length", [akp_bad_len]),
        ("D01-rsa-missing-e", [rsa_missing_e]),
        ("D02-ec-missing-y", [ec_missing_y]),
        ("E01-ec-unknown-use", [ec_unknown_use]),
        ("E02-ec-unknown-key-ops", [ec_unknown_key_ops]),
    ]

    for case_id, odd in cases:
        jwks = {"keys": [*odd, rsa1_jwk]}
        (OUT / f"{case_id}.json").write_text(json.dumps(jwks, indent=2) + "\n")
        self_check(jwks, token)
    print(f"wrote {len(cases)} cases to {OUT.relative_to(ROOT)}")


def sign_token(key, header: dict) -> str:
    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(TOKEN_CLAIMS, separators=(",", ":")).encode())
    )
    sig = key.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    return signing_input + "." + b64u(sig)


def self_check(jwks: dict, token: str):
    """Confirm the token verifies against the rsa-1 entry in this set."""
    (signer,) = [k for k in jwks["keys"] if k.get("kid") == "rsa-1"]
    n = int.from_bytes(base64.urlsafe_b64decode(signer["n"] + "=="), "big")
    e = int.from_bytes(base64.urlsafe_b64decode(signer["e"] + "=="), "big")
    pub = rsa.RSAPublicNumbers(e, n).public_key()
    head, body, sig = token.split(".")
    try:
        pub.verify(
            base64.urlsafe_b64decode(sig + "=="),
            f"{head}.{body}".encode(),
            padding.PKCS1v15(),
            hashes.SHA256(),
        )
    except InvalidSignature:
        raise SystemExit("self-check failed: token does not verify against rsa-1")


if __name__ == "__main__":
    main()
