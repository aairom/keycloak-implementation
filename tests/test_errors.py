"""Exception hierarchy: one base class, informative messages that never carry secrets."""
import pytest

from keycloak_connector import errors


def test_every_error_derives_from_the_base():
    for cls in (errors.ConfigError, errors.DiscoveryError, errors.StateMismatchError, errors.AuthorizationError,
                errors.TokenError, errors.TokenValidationError, errors.RefreshError):
        assert issubclass(cls, errors.KeycloakConnectorError)


def test_authorization_error_carries_error_and_description():
    err = errors.AuthorizationError("access_denied", "user said no")
    assert (err.error, err.description) == ("access_denied", "user said no")
    assert "access_denied" in str(err) and "user said no" in str(err)
    assert str(errors.AuthorizationError("login_required")) == "authorization failed: login_required"


def test_token_error_message_has_status():
    err = errors.TokenError("invalid_grant", "expired", 400)
    assert err.status == 400 and "HTTP 400" in str(err) and "expired" in str(err)
    assert str(errors.TokenError("server_error")) == "token request failed: server_error"


def test_refresh_error_is_a_token_error_with_reauth_flag():
    err = errors.RefreshError("invalid_grant", status=400, reauth_required=True)
    assert isinstance(err, errors.TokenError) and err.reauth_required is True
    assert errors.RefreshError("x").reauth_required is False
    with pytest.raises(errors.TokenError):
        raise err
