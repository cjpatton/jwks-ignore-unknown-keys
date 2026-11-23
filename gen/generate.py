#!/usr/bin/env python3
"""Generate JWKS test cases for "relying party ignores what it doesn't understand".

Every case is a JWK Set containing one or more keys a typical library will not
understand, followed by the RSA key "rsa-1". The token in testdata/token.jwt is
signed by rsa-1 (RS256), so every case is expected to verify.

Keys are cached under testdata/keys/ so re-running produces stable output.
"""

import base64
import json
import secrets
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, padding, rsa

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "testdata"
KEYS = OUT / "keys"
JWKS_DIR = OUT / "jwks"
VECTORS = ROOT / "gen" / "vectors" / "draft-composite-sigs-testvectors.json"

TOKEN_HEADER = {"alg": "RS256", "typ": "JWT", "kid": "rsa-1"}
TOKEN_CLAIMS = {
    "iss": "https://issuer.example",
    "sub": "jwks-tolerance-test",
    "aud": "jwks-tolerance-test",
    "iat": 1767225600,  # 2026-01-01
    "exp": 4102444800,  # 2100-01-01
}

# draft-ietf-jose-pq-composite-sigs-06 JOSE alg -> lamps test vector tcId
AKP_ALGS = {
    "ML-DSA-44": "id-ML-DSA-44",
    "ML-DSA-65": "id-ML-DSA-65",
    "ML-DSA-87": "id-ML-DSA-87",
    "ML-DSA-44-ES256": "id-MLDSA44-ECDSA-P256-SHA256",
    "ML-DSA-65-ES256": "id-MLDSA65-ECDSA-P256-SHA512",
    "ML-DSA-65-ES384": "id-MLDSA65-ECDSA-P384-SHA512",
    "ML-DSA-87-ES384": "id-MLDSA87-ECDSA-P384-SHA512",
    "ML-DSA-44-Ed25519": "id-MLDSA44-Ed25519-SHA512",
    "ML-DSA-65-Ed25519": "id-MLDSA65-Ed25519-SHA512",
    "ML-DSA-87-Ed448": "id-MLDSA87-Ed448-SHAKE256",
}

# Expected serialized public key sizes (bytes), as a sanity check on the vectors.
AKP_PUB_LEN = {
    "ML-DSA-44": 1312,
    "ML-DSA-65": 1952,
    "ML-DSA-87": 2592,
    "ML-DSA-44-ES256": 1312 + 65,
    "ML-DSA-65-ES256": 1952 + 65,
    "ML-DSA-65-ES384": 1952 + 97,
    "ML-DSA-87-ES384": 2592 + 97,
    "ML-DSA-44-Ed25519": 1312 + 32,
    "ML-DSA-65-Ed25519": 1952 + 32,
    "ML-DSA-87-Ed448": 2592 + 57,
}


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_int(n: int) -> str:
    return b64u(n.to_bytes((n.bit_length() + 7) // 8, "big"))


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


def is_probable_prime(n: int, rounds: int = 40) -> bool:
    if n < 4:
        return n in (2, 3)
    if n % 2 == 0:
        return False
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(rounds):
        x = pow(secrets.randbelow(n - 3) + 2, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def rsa512_modulus() -> int:
    # cryptography refuses to generate keys this small, so build the modulus by hand.
    path = KEYS / "rsa-512.json"
    if path.exists():
        return int(json.loads(path.read_text())["n"], 16)
    primes = []
    while len(primes) < 2:
        p = secrets.randbits(256) | (1 << 255) | (1 << 254) | 1
        if is_probable_prime(p) and (p - 1) % 65537 != 0:
            primes.append(p)
    n = primes[0] * primes[1]
    path.write_text(json.dumps({"n": format(n, "x")}) + "\n")
    return n


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
    JWKS_DIR.mkdir(parents=True, exist_ok=True)

    rsa1 = load_or_create("rsa-1", lambda: rsa.generate_private_key(65537, 2048))
    rsa_other = load_or_create("rsa-other", lambda: rsa.generate_private_key(65537, 2048))
    ec_p256 = load_or_create("ec-p256", lambda: ec.generate_private_key(ec.SECP256R1()))
    ec_k1 = load_or_create("ec-secp256k1", lambda: ec.generate_private_key(ec.SECP256K1()))
    ed448_key = load_or_create("ed448", ed448.Ed448PrivateKey.generate)

    (OUT / "rsa-1.public.pem").write_bytes(
        rsa1.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

    rsa1_jwk = rsa_pub(rsa1, kid="rsa-1", use="sig", alg="RS256")
    (OUT / "rsa-1.public.jwk.json").write_text(json.dumps(rsa1_jwk, indent=2) + "\n")

    signing_input = (
        b64u(json.dumps(TOKEN_HEADER, separators=(",", ":")).encode())
        + "."
        + b64u(json.dumps(TOKEN_CLAIMS, separators=(",", ":")).encode())
    )
    sig = rsa1.sign(signing_input.encode(), padding.PKCS1v15(), hashes.SHA256())
    token = signing_input + "." + b64u(sig)
    (OUT / "token.jwt").write_text(token + "\n")

    # --- odd keys -----------------------------------------------------------
    vectors = {t["tcId"]: t for t in json.loads(VECTORS.read_text())["tests"]}
    akp = {}
    for alg, tc in AKP_ALGS.items():
        pub = base64.b64decode(vectors[tc]["pk"])
        assert len(pub) == AKP_PUB_LEN[alg], (alg, len(pub))
        akp[alg] = {
            "kty": "AKP",
            "kid": "akp-" + alg.lower(),
            "use": "sig",
            "alg": alg,
            "pub": b64u(pub),
        }

    akp_bad_len = dict(akp["ML-DSA-44"])
    akp_bad_len["kid"] = "akp-ml-dsa-44-bad-length"
    akp_bad_len["pub"] = b64u(base64.urlsafe_b64decode(akp["ML-DSA-44"]["pub"] + "==")[:-1])

    unknown_kty = {
        "kty": "https://example.com/jwk/kty/future",
        "kid": "unknown-kty",
        "use": "sig",
        "alg": "https://example.com/jws/alg/future",
        "k1": b64u(b"opaque future key material"),
    }
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
        "n": b64u_int(rsa512_modulus()),
        "e": "AQAB",
    }

    rsa_missing_e = rsa_pub(rsa_other, kid="rsa-missing-e", use="sig", alg="RS256")
    del rsa_missing_e["e"]
    ec_missing_y = ec_pub(ec_p256, "P-256", 32, kid="ec-missing-y", use="sig", alg="ES256")
    del ec_missing_y["y"]

    ec_unknown_use = ec_pub(ec_p256, "P-256", 32, kid="ec-unknown-use", use="pq-sig", alg="ES256")
    ec_unknown_key_ops = ec_pub(ec_p256, "P-256", 32, kid="ec-unknown-key-ops", alg="ES256")
    ec_unknown_key_ops["key_ops"] = ["verify", "future-op"]

    # --- rsa-1 with unknown members (RFC 7517 Section 4: MUST ignore) -------
    rsa1_uri_member = {**rsa1_jwk, "https://example.com/jwk/future-param": {"a": [1, 2], "b": None}}
    # Mirrors what WebCrypto exportKey("jwk") produces: ext + key_ops, no "use".
    rsa1_webcrypto = {k: v for k, v in rsa1_jwk.items() if k != "use"}
    rsa1_webcrypto.update({"ext": True, "key_ops": ["verify"]})
    # Mirrors Microsoft Entra ID's published JWKS.
    rsa1_entra = {
        **rsa1_jwk,
        "issuer": "https://login.microsoftonline.com/{tenantid}/v2.0",
        "cloud_instance_name": "microsoftonline.com",
    }
    # "pub" is registered by RFC 9964, but only for kty AKP.
    rsa1_pub_member = {**rsa1_jwk, "pub": b64u(b"not an RSA parameter")}

    set_member = {"https://example.com/jwks/future-param": {"rotation": "2026-11", "n": 3}}

    A = "RFC 7517 Section 5: SHOULD ignore keys with unsupported kty or out-of-range values"
    cases = [
        ("00-baseline", "Only rsa-1. Harness sanity check.", "baseline", [], rsa1_jwk, {}),
    ]
    for i, alg in enumerate(AKP_ALGS, start=1):
        kind = "pure ML-DSA (RFC 9964)" if alg.count("-") == 2 else "composite (draft-ietf-jose-pq-composite-sigs-06)"
        cases.append(
            (f"A{i:02d}-akp-{alg.lower()}", f"AKP {alg}, {kind}.", A, [akp[alg]], rsa1_jwk, {})
        )
    cases += [
        ("B01-unknown-kty", "kty is an unregistered collision-resistant name.", A, [unknown_kty], rsa1_jwk, {}),
        ("B02-kty-wrong-case", 'kty "rsa" (kty is case-sensitive, so this is not RSA).', A, [kty_wrong_case], rsa1_jwk, {}),
        ("C01-ec-unknown-crv", 'EC key with crv "P-999".', A, [ec_unknown_crv], rsa1_jwk, {}),
        ("C02-okp-ed448", "OKP Ed448 (RFC 8037), often unsupported.", A, [okp_ed448], rsa1_jwk, {}),
        ("C03-ec-secp256k1", "EC secp256k1 / ES256K (RFC 8812), often unsupported.", A, [ec_secp256k1], rsa1_jwk, {}),
        ("C04-rsa-unknown-alg", 'RSA key with alg "RS999".', A, [rsa_unknown_alg], rsa1_jwk, {}),
        ("C05-rsa-512", "RSA key with a 512-bit modulus (below most minimums).", A, [rsa_512], rsa1_jwk, {}),
        ("C06-akp-ml-dsa-44-bad-length", "AKP ML-DSA-44 with a 1311-byte pub (one byte short).", A, [akp_bad_len], rsa1_jwk, {}),
        ("D01-rsa-missing-e", 'RSA key missing required member "e".', A, [rsa_missing_e], rsa1_jwk, {}),
        ("D02-ec-missing-y", 'EC P-256 key missing required member "y".', A, [ec_missing_y], rsa1_jwk, {}),
        ("E01-member-uri-object", "rsa-1 carries an unknown collision-resistant member with an object value.",
         "RFC 7517 Section 4: unknown JWK members MUST be ignored", [], rsa1_uri_member, {}),
        ("E02-member-webcrypto", 'rsa-1 as exported by WebCrypto: "ext" and "key_ops", no "use".',
         "RFC 7517 Section 4: unknown JWK members MUST be ignored", [], rsa1_webcrypto, {}),
        ("E03-member-entra", 'rsa-1 with Entra ID\'s "issuer" and "cloud_instance_name".',
         "RFC 7517 Section 4: unknown JWK members MUST be ignored", [], rsa1_entra, {}),
        ("E04-member-pub-on-rsa", 'rsa-1 with "pub", a member registered only for kty AKP.',
         "RFC 7517 Section 4: unknown JWK members MUST be ignored", [], rsa1_pub_member, {}),
        ("E05-set-member", "JWK Set object carries an unknown top-level member.",
         "RFC 7517 Section 5: unknown JWK Set members MUST be ignored", [], rsa1_jwk, set_member),
        ("E06-ec-unknown-use", 'Valid EC key with use "pq-sig".',
         'RFC 7517 Section 4.2: other "use" values MAY be used', [ec_unknown_use], rsa1_jwk, {}),
        ("E07-ec-unknown-key-ops", 'Valid EC key with key_ops ["verify", "future-op"].',
         'RFC 7517 Section 4.3: other "key_ops" values MAY be used', [ec_unknown_key_ops], rsa1_jwk, {}),
    ]
    everything = list(akp.values()) + [
        unknown_kty, kty_wrong_case, ec_unknown_crv, okp_ed448, ec_secp256k1, rsa_unknown_alg,
        rsa_512, akp_bad_len, rsa_missing_e, ec_missing_y, ec_unknown_use, ec_unknown_key_ops,
    ]
    rsa1_everything = {**rsa1_uri_member, **rsa1_entra, **rsa1_pub_member}
    cases.append(
        ("Z01-everything", "All odd keys, then rsa-1 with all unknown members, plus the set member.",
         "All of the above", everything, rsa1_everything, set_member)
    )

    for old in JWKS_DIR.glob("*.json"):
        old.unlink()
    manifest = []
    for case_id, desc, rule, odd, signer, set_extra in cases:
        jwks = {"keys": [*odd, signer], **set_extra}
        path = JWKS_DIR / f"{case_id}.json"
        path.write_text(json.dumps(jwks, indent=2) + "\n")
        self_check(jwks, token)
        manifest.append({
            "id": case_id,
            "file": f"jwks/{case_id}.json",
            "description": desc,
            "rule": rule,
            "expect": "verify",
        })
    (OUT / "cases.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(f"wrote {len(manifest)} cases to {JWKS_DIR.relative_to(ROOT)}")


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
