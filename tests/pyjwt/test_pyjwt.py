"""Run the fixtures in cases.json against PyJWT.

Key selection uses PyJWT's own `PyJWKClient`, with `fetch_data` overridden to
return the fixture's JWKS instead of fetching it over HTTP. The verifier
accepts RS256, RS384, and ES256 and enables PyJWT's opt-in
`enforce_minimum_key_length` check.

PyJWT has no candidate retry mode, so for `"selection": "try-candidates"`
cases the harness supplies one: try every signing key whose `kid` matches the
JWT's `kid`, in JWKS order, until one verifies.

Cases where PyJWT disagrees with the expected result are marked as strict
xfails in KNOWN_FAILURES, so a fix upstream shows up as an XPASS.
"""

import json
import pathlib

import jwt
import pytest
from jwt import PyJWKClient
from jwt.exceptions import (
    InvalidAlgorithmError,
    InvalidKeyError,
    InvalidSignatureError,
    PyJWKClientError,
    PyJWKSetError,
    PyJWTError,
)

ROOT = pathlib.Path(__file__).resolve().parents[2]
CASES = json.loads((ROOT / "cases.json").read_text())

ALGORITHMS = ["RS256", "RS384", "ES256"]
ISSUER = "https://issuer.example"
AUDIENCE = "jwks-tolerance-test"

_FIRST_KID_MATCH = (
    "PyJWKClient.match_kid returns the first key with a matching kid and "
    "does not consider other candidates"
)
_NO_KID = (
    "PyJWKClient only selects keys by kid; it drops JWKs without kid and "
    "cannot select a key for a JWT without kid"
)
_KEY_OPS_IGNORED = "PyJWKClient filters on use but ignores key_ops"

# Expected outcome (verify/reject) differs from PyJWT's.
KNOWN_FAILURES = {
    "F02-ec-other-crv-same-kid": _FIRST_KID_MATCH,
    "H02-no-kid-single-key": _NO_KID,
    "I01-no-kid-mixed-set": _NO_KID,
    "I05-no-kid-mixed-set-tagged-signer": _NO_KID,
    "J02-shared-kid-different-kty-es256": _FIRST_KID_MATCH,
    "J04-shared-kid-different-alg-rs384": _FIRST_KID_MATCH,
    "L03-key-ops-encryption": f"{_KEY_OPS_IGNORED}; {_FIRST_KID_MATCH}",
    "L04-key-ops-unknown": f"{_KEY_OPS_IGNORED}; {_FIRST_KID_MATCH}",
    "L05-key-ops-duplicate-verify": f"{_KEY_OPS_IGNORED}; {_FIRST_KID_MATCH}",
    "L07-signer-key-ops-encryption": _KEY_OPS_IGNORED,
}

# Rejected as expected, but for a different reason.
KNOWN_REASON_MISMATCHES = {
    "M04-hs256-with-public-jwks": (
        "PyJWT selects the RSA key by kid, then rejects HS256 because it is "
        "not in the permitted algorithms (algorithm-not-accepted)"
    ),
}


class StaticJWKClient(PyJWKClient):
    def __init__(self, jwks):
        super().__init__("https://issuer.example/jwks", cache_jwk_set=False)
        self._jwks = jwks

    def fetch_data(self):
        return self._jwks


def _decode(token, key):
    return jwt.decode(
        token,
        key,
        algorithms=ALGORITHMS,
        audience=AUDIENCE,
        issuer=ISSUER,
        options={"enforce_minimum_key_length": True},
    )


def verify(case):
    token = (ROOT / case["token"]).read_text().strip()
    client = StaticJWKClient(json.loads((ROOT / case["jwks"]).read_text()))

    if case.get("selection") != "try-candidates":
        return _decode(token, client.get_signing_key_from_jwt(token))

    kid = jwt.get_unverified_header(token).get("kid")
    candidates = [k for k in client.get_signing_keys() if k.key_id == kid]
    if not candidates:
        raise PyJWKClientError(f'Unable to find a signing key that matches: "{kid}"')
    for key in candidates:
        try:
            return _decode(token, key)
        except PyJWTError as error:
            last_error = error
    raise last_error


def failure_reason(error):
    if isinstance(error, (PyJWKClientError, PyJWKSetError)):
        return "no-eligible-key"
    if isinstance(error, InvalidAlgorithmError):
        if "does not match the key's algorithm" in str(error):
            return "no-eligible-key"
        return "algorithm-not-accepted"
    if isinstance(error, InvalidSignatureError):
        return "signature-mismatch"
    if isinstance(error, InvalidKeyError) and "below the minimum" in str(error):
        return "rsa-modulus-too-small"
    return f"unclassified: {type(error).__name__}: {error}"


def _params(cases, known):
    return [
        pytest.param(
            case,
            id=case["name"],
            marks=(
                [pytest.mark.xfail(reason=known[case["name"]], strict=True)]
                if case["name"] in known
                else []
            ),
        )
        for case in cases
    ]


@pytest.mark.parametrize("case", _params(CASES, KNOWN_FAILURES))
def test_outcome(case):
    try:
        verify(case)
    except PyJWTError as error:
        outcome = f"reject ({failure_reason(error)})"
    else:
        outcome = "verify"
    assert outcome.split()[0] == case["expected"], outcome


@pytest.mark.parametrize(
    "case",
    _params(
        [
            c
            for c in CASES
            if c["expected"] == "reject" and c["name"] not in KNOWN_FAILURES
        ],
        KNOWN_REASON_MISMATCHES,
    ),
)
def test_failure_reason(case):
    with pytest.raises(PyJWTError) as excinfo:
        verify(case)
    assert failure_reason(excinfo.value) == case["failure"]
