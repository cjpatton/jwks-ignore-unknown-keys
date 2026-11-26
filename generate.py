#!/usr/bin/env python3
"""Generate JWKS test cases for ignoring unsupported keys and selecting verification keys.

Inputs live under testdata/. The cached keys and deterministic signatures keep
the outputs stable. The A cases use public keys from the RFC 9964 and composite
signature draft examples under testdata/specs/. cases.json indexes all outputs.
"""

import base64
import hashlib
import hmac
import json
import re
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, padding, rsa, utils

try:
    from cryptography.hazmat.primitives.asymmetric import mldsa
except ImportError:
    raise SystemExit("generate.py needs a version of cryptography with ML-DSA support (tested with 50)")

ROOT = Path(__file__).resolve().parent
TESTDATA = ROOT / "testdata"
KEYS = TESTDATA / "keys"
SPECS = TESTDATA / "specs"
TOKEN_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "rsa-1"}
RSA_TOKEN = "tokens/rs256.jwt"
TOKEN_CLAIMS = {
    "iss": "https://issuer.example",
    "sub": "jwks-tolerance-test",
    "aud": "jwks-tolerance-test",
    "iat": 1767225600,  # 2026-01-01
    "exp": 4102444800,  # 2100-01-01
}
RSA_HASHES = {"RS256": hashes.SHA256, "RS384": hashes.SHA384}

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


def spki_pem(public_key) -> bytes:
    """RFC 7468 Section 13: "PUBLIC KEY" PEM, wrapped at 64 characters with a line feed after every line."""
    return public_key.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)


def ec_pub(key, crv: str, size: int, **extra) -> dict:
    nums = key.public_key().public_numbers()
    return {
        "kty": "EC",
        "crv": crv,
        **extra,
        "x": b64u(nums.x.to_bytes(size, "big")),
        "y": b64u(nums.y.to_bytes(size, "big")),
    }


def unrelated_key_cases(rsa_other, ec_p256, ec_k1, ed448_key):
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
    unknown_kty_same_kid = rsa_pub(rsa_other, kid="rsa-1", use="sig", alg="RS256")
    unknown_kty_same_kid["kty"] = unknown_kty["kty"]

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

    # The caller appends the rsa-1 public key to each set.
    cases = [(f"A{i:02d}-akp-{alg.lower()}", [akp[alg]]) for i, alg in enumerate(AKP_ALGS, start=1)]
    cases += [
        ("B01-unknown-kty", [unknown_kty]),
        ("B02-kty-wrong-case", [kty_wrong_case]),  # kty is case-sensitive, so "rsa" is not RSA
        ("B03-grease", [grease]),
        ("B04-unknown-kty-registered-member", [unknown_kty_bad_member]),
        ("B05-unknown-kty-same-kid", [unknown_kty_same_kid]),
        ("C01-ec-unknown-crv", [ec_unknown_crv]),
        ("C02-okp-ed448", [okp_ed448]),  # RFC 8037, often unsupported
        ("C03-ec-secp256k1", [ec_secp256k1]),  # RFC 8812, often unsupported
        ("C04-rsa-unknown-alg", [rsa_unknown_alg]),
        ("C05-rsa-512", [rsa_512]),  # below the RS256 minimum key size
        ("C06-akp-ml-dsa-44-bad-length", [akp_bad_len]),
        ("D01-rsa-missing-e", [rsa_missing_e]),
        ("D02-ec-missing-y", [ec_missing_y]),
        ("E01-ec-unknown-use", [ec_unknown_use]),
        ("E02-ec-unknown-key-ops", [ec_unknown_key_ops]),
    ]

    return cases


def add_selection_cases(add, rsa1, rsa_other, ec_p256, ec_p384, shared_kid):
    rsa_signer = rsa_pub(rsa1, kid="rsa-1", alg="RS256", use="sig")
    rsa_alternate = rsa_pub(rsa_other, kid="rsa-1", alg="RS256", use="sig")
    ec_signer = ec_pub(ec_p256, "P-256", 32, kid=shared_kid)
    ec_other_curve = ec_pub(ec_p384, "P-384", 48, kid=shared_kid)
    future = "https://example.com/jwk/future"

    # With no JWK alg and the same kid, the EC keys are distinguished by crv.
    add("F01-ec-unknown-crv-same-kid",
        [{**ec_other_curve, "crv": "P-999"}, ec_signer], "tokens/es256-shared-kid.jwt")
    add("F02-ec-other-crv-same-kid", [ec_other_curve, ec_signer], "tokens/es256-shared-kid.jwt")

    add("G01-unknown-jwk-member", [{**rsa_signer, future: {"values": [1, True, None]}}])
    add("G02-unknown-jwks-member", [rsa_signer], members={future: {"label": "2026-01"}})

    add("H01-kid-selects-signer", [{**rsa_alternate, "kid": "rsa-other"}, rsa_signer])
    add("H02-no-kid-single-key", [rsa_pub(rsa1)], "tokens/rs256-no-kid.jwt")
    signer_with_other_kid = {**rsa_signer, "kid": "rsa-other"}
    add("H03-wrong-kid", [signer_with_other_kid], failure="no-eligible-key")
    add("H04-wrong-signature", [rsa_alternate], failure="signature-mismatch", signer_present=False)
    add("H05-kid-incompatible-alg", [{**rsa_signer, "alg": "RS384"}], failure="no-eligible-key")
    add("H06-kid-incompatible-kty", [{**ec_signer, "kid": "rsa-1"}, signer_with_other_kid],
        failure="no-eligible-key")
    add("H07-kid-with-untagged-keys", [rsa_pub(rsa_other, alg="RS256"), rsa_pub(rsa1, alg="RS256")],
        failure="no-eligible-key")

    other_alg = {**rsa_alternate, "alg": "RS384"}
    encryption_key = rsa_pub(rsa_other, kid="encryption-key", use="enc")
    mixed = [other_alg, encryption_key, ec_signer]
    add("I01-no-kid-mixed-set", [*mixed, rsa_pub(rsa1)], "tokens/rs256-no-kid.jwt")
    add("I02-no-kid-no-compatible-key", [*mixed, rsa_pub(rsa1, alg="RS384")],
        "tokens/rs256-no-kid.jwt", failure="no-eligible-key")

    missing_e = {k: v for k, v in rsa_alternate.items() if k != "e"}
    add("I03-retry-after-import-failure", [missing_e, rsa_signer], selection="try-candidates")
    add("I04-retry-after-signature-mismatch", [rsa_alternate, rsa_signer], selection="try-candidates")
    add("I05-no-kid-mixed-set-tagged-signer", [*mixed, rsa_pub(rsa1, kid="signing-key")],
        "tokens/rs256-no-kid.jwt")

    rsa_shared = rsa_pub(rsa1, kid=shared_kid)
    different_kty = [rsa_shared, ec_signer]
    add("J01-shared-kid-different-kty-rs256", different_kty, "tokens/rs256-shared-kid.jwt",
        jwks_name="J01-shared-kid-different-kty")
    add("J02-shared-kid-different-kty-es256", different_kty, "tokens/es256-shared-kid.jwt",
        jwks_name="J01-shared-kid-different-kty")

    different_alg = [{**rsa_shared, "alg": "RS256"}, rsa_pub(rsa_other, kid=shared_kid, alg="RS384")]
    add("J03-shared-kid-different-alg-rs256", different_alg, "tokens/rs256-shared-kid.jwt",
        jwks_name="J03-shared-kid-different-alg")
    add("J04-shared-kid-different-alg-rs384", different_alg, "tokens/rs384-shared-kid.jwt",
        jwks_name="J03-shared-kid-different-alg")

    add("K01-rsa-unknown-alg-same-kid", [{**rsa_alternate, "alg": future}, rsa_signer])

    rsa_public = rsa_pub(rsa1, kid="rsa-1")
    rsa_other_public = rsa_pub(rsa_other, kid="rsa-1")
    use_signer = {**rsa_public, "use": "sig"}
    add("L01-use-encryption", [{**rsa_other_public, "use": "enc"}, use_signer])
    add("L02-use-unknown", [{**rsa_other_public, "use": future}, use_signer])

    ops_signer = {**rsa_public, "key_ops": ["verify"]}
    add("L03-key-ops-encryption", [{**rsa_other_public, "key_ops": ["encrypt"]}, ops_signer])
    add("L04-key-ops-unknown", [{**rsa_other_public, "key_ops": [future]}, ops_signer])
    add("L05-key-ops-duplicate-verify", [{**rsa_other_public, "key_ops": ["verify", "verify"]}, ops_signer])
    add("L06-signer-use-encryption", [{**rsa_public, "use": "enc"}], failure="no-eligible-key")
    add("L07-signer-key-ops-encryption", [{**rsa_public, "key_ops": ["encrypt"]}], failure="no-eligible-key")
    add("L08-signer-key-ops-extension",
        [{**rsa_public, "key_ops": ["verify", "https://example.com/jwk/key-ops/future-verify"]}])


def main():
    KEYS.mkdir(parents=True, exist_ok=True)
    rsa1 = load_or_create("rsa-1", lambda: rsa.generate_private_key(65537, 2048))
    rsa_other = load_or_create("rsa-other", lambda: rsa.generate_private_key(65537, 2048))
    rsa_1024 = load_or_create("rsa-1024", lambda: rsa.generate_private_key(65537, 1024))
    if rsa_1024.key_size != 1024:
        raise SystemExit("rsa-1024.pem must contain a 1024-bit RSA key")
    ec_p256 = load_or_create("ec-p256", lambda: ec.generate_private_key(ec.SECP256R1()))
    ec_p384 = load_or_create("ec-p384", lambda: ec.generate_private_key(ec.SECP384R1()))
    ec_k1 = load_or_create("ec-secp256k1", lambda: ec.generate_private_key(ec.SECP256K1()))
    ed448_key = load_or_create("ed448", ed448.Ed448PrivateKey.generate)

    shared_kid = "2026-01"
    no_kid = {"alg": "RS256", "typ": "JWT"}
    shared_header = {**no_kid, "kid": shared_kid}
    rsa_1024_token = "tokens/rs256-rsa-1024.jwt"
    unsigned_cases = {
        "M01-unsigned-none": ("tokens/unsigned-none.jwt", "none"),
        "M02-unsigned-uppercase-none": ("tokens/unsigned-uppercase-none.jwt", "NONE"),
        "M03-unsigned-mixed-case-none": ("tokens/unsigned-mixed-case-none.jwt", "nonE"),
    }
    hs256_token = "tokens/hs256.jwt"
    hs256_input = token_signing_input({**TOKEN_HEADER, "alg": "HS256"})
    hs256_mac = hmac.digest(spki_pem(rsa1.public_key()), hs256_input.encode(), "sha256")
    tokens = {
        RSA_TOKEN: sign_token(rsa1, TOKEN_HEADER),
        rsa_1024_token: sign_token(rsa_1024, {**TOKEN_HEADER, "kid": "rsa-1024"}),
        "tokens/rs256-no-kid.jwt": sign_token(rsa1, no_kid),
        "tokens/rs256-shared-kid.jwt": sign_token(rsa1, shared_header),
        "tokens/rs384-shared-kid.jwt": sign_token(rsa_other, {**shared_header, "alg": "RS384"}),
        "tokens/es256-shared-kid.jwt": sign_token(ec_p256, {**shared_header, "alg": "ES256"}),
        hs256_token: hs256_input + "." + b64u(hs256_mac),
    }
    for path, alg in unsigned_cases.values():
        tokens[path] = token_signing_input({**TOKEN_HEADER, "alg": alg}) + "."
    cases = []
    sets = {}

    def add_case(name, keys, token=RSA_TOKEN, *, jwks_name=None, failure=None,
                 selection=None, members=None, signer_present=True):
        path = f"jwks/{jwks_name or name}.json"
        jwks = {"keys": keys, **(members or {})}
        if path in sets and sets[path] != jwks:
            raise SystemExit(f"{name}: inconsistent contents for {path}")
        self_check(name, jwks, tokens[token], signer_present)
        sets[path] = jwks
        case = {"name": name, "token": token, "jwks": path, "expected": "reject" if failure else "verify"}
        if failure:
            case["failure"] = failure
        if selection:
            case["selection"] = selection
        cases.append(case)

    rsa_signer = rsa_pub(rsa1, kid="rsa-1", use="sig", alg="RS256")
    add_case("00-baseline", [rsa_signer])
    for name, other_keys in unrelated_key_cases(rsa_other, ec_p256, ec_k1, ed448_key):
        add_case(name, [*other_keys, rsa_signer])
    add_case("C07-rsa-1024-signing-key", [rsa_pub(rsa_1024, kid="rsa-1024", use="sig", alg="RS256")],
             rsa_1024_token, failure="rsa-modulus-too-small")
    add_selection_cases(add_case, rsa1, rsa_other, ec_p256, ec_p384, shared_kid)
    for name, (path, _) in unsigned_cases.items():
        add_case(name, [rsa_signer], path, jwks_name="00-baseline",
                 failure="algorithm-not-accepted", signer_present=False)
    add_case("M04-hs256-with-public-jwks", [rsa_pub(rsa1, kid="rsa-1", use="sig")], hs256_token,
             failure="no-eligible-key")

    outputs = {path: json.dumps(jwks, indent=2) for path, jwks in sets.items()}
    outputs.update(tokens)
    outputs["cases.json"] = json.dumps(sorted(cases, key=lambda case: case["name"]), indent=2)
    for path, value in outputs.items():
        output = ROOT / path
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(value + "\n", encoding="utf-8")
    print(f"wrote {len(cases)} cases using {len(sets)} JWK Sets and {len(tokens)} tokens")


def token_signing_input(header: dict) -> str:
    return (
        b64u(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(TOKEN_CLAIMS, separators=(",", ":")).encode())
    )


def sign_token(key, header: dict) -> str:
    signing_input = token_signing_input(header)
    alg = header["alg"]
    if alg == "ES256":
        der = key.sign(signing_input.encode(), ec.ECDSA(hashes.SHA256(), deterministic_signing=True))
        r, s = utils.decode_dss_signature(der)
        sig = r.to_bytes(32, "big") + s.to_bytes(32, "big")
    else:
        sig = key.sign(signing_input.encode(), padding.PKCS1v15(), RSA_HASHES[alg]())
    return signing_input + "." + b64u(sig)


def self_check(name: str, jwks: dict, token: str, signer_present: bool):
    """Check the signature against the fixture's key material independently of key selection."""
    head, body, sig = token.split(".")
    alg = json.loads(b64d(head))["alg"]
    msg, sig = f"{head}.{body}".encode(), b64d(sig)
    matching = 0
    for key in jwks["keys"]:
        try:
            if alg in RSA_HASHES and key["kty"] == "RSA":
                n, e = (int.from_bytes(b64d(key[part]), "big") for part in ("n", "e"))
                pub = rsa.RSAPublicNumbers(e, n).public_key()
                pub.verify(sig, msg, padding.PKCS1v15(), RSA_HASHES[alg]())
            elif alg == "ES256" and key["kty"] == "EC" and key["crv"] == "P-256":
                x, y = (int.from_bytes(b64d(key[part]), "big") for part in ("x", "y"))
                pub = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()).public_key()
                r, s = (int.from_bytes(part, "big") for part in (sig[:32], sig[32:]))
                pub.verify(utils.encode_dss_signature(r, s), msg, ec.ECDSA(hashes.SHA256()))
            elif alg == "HS256" and key["kty"] == "RSA":
                # M04: the MAC key is the PEM encoding of the RSA public key.
                n, e = (int.from_bytes(b64d(key[part]), "big") for part in ("n", "e"))
                pem = spki_pem(rsa.RSAPublicNumbers(e, n).public_key())
                if not hmac.compare_digest(sig, hmac.digest(pem, msg, "sha256")):
                    continue
            else:
                continue
        except (InvalidSignature, KeyError, ValueError):
            continue
        matching += 1
    if matching != int(signer_present):
        raise SystemExit(f"{name}: expected {int(signer_present)} keys matching the signature, got {matching}")


if __name__ == "__main__":
    main()
