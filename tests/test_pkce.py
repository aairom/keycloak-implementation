"""PKCE helpers against the RFC 7636 and OIDC Core test vectors."""
from keycloak_connector import pkce


def test_s256_challenge_matches_rfc7636_appendix_b():
    verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    assert pkce.challenge_s256(verifier) == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"


def test_verifier_length_and_uniqueness():
    a, b = pkce.generate_verifier(), pkce.generate_verifier()
    assert 43 <= len(a) <= 128 and a != b


def test_random_tokens_are_unique_and_url_safe():
    values = {pkce.random_token() for _ in range(50)}
    assert len(values) == 50 and all(v.replace("-", "").replace("_", "").isalnum() for v in values)


def test_half_hash_matches_oidc_core_example():
    # OIDC Core appendix A.3 example access token and its at_hash.
    token = "jHkWEdUXMU1BwAsC4vtUsZwnNvTIxEl0z9K3vx5KF0Y"  # nosecret: public test vector from the OIDC spec
    assert pkce.half_hash(token) == "77QmUPtjPfzWtF2AnpK9RQ"


def test_half_hash_follows_the_algorithm_size():
    assert len(pkce.half_hash("x", "RS256")) < len(pkce.half_hash("x", "RS384")) < len(pkce.half_hash("x", "RS512"))
    assert pkce.half_hash("x", "weird") == pkce.half_hash("x", "RS256")
