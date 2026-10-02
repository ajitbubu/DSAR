import pytest
from pydantic import ValidationError

from idprivacy.domain.identity.otp import MockOtpProvider, build_otp_provider
from tests.conftest import make_settings


@pytest.mark.parametrize("env", ["staging", "production"])
def test_mock_otp_provider_refused_outside_dev(env: str) -> None:
    with pytest.raises(ValidationError, match="mock OTP provider"):
        make_settings(env=env)


def test_local_key_provider_refused_outside_dev() -> None:
    with pytest.raises(ValidationError, match="local key provider"):
        make_settings(env="production")


def test_build_otp_provider_second_guard_refuses_production() -> None:
    unsafe = make_settings().model_copy(update={"env": "production"})  # skips validation
    with pytest.raises(RuntimeError, match="only permitted in local/test"):
        build_otp_provider(unsafe)


def test_mock_otp_provider_allowed_in_test() -> None:
    assert isinstance(build_otp_provider(make_settings()), MockOtpProvider)


@pytest.mark.parametrize("algs", [["HS256"], ["none"], [], ["RS256", "HS512"]])
def test_symmetric_or_empty_jwt_algorithms_rejected(algs: list[str]) -> None:
    with pytest.raises(ValidationError, match="oidc_algorithms"):
        make_settings(oidc_algorithms=algs)


def test_master_key_required_for_local_key_provider() -> None:
    with pytest.raises(ValidationError, match="local_master_key"):
        make_settings(local_master_key=None)


def test_vault_key_provider_needs_address_and_token() -> None:
    with pytest.raises(ValidationError, match="vault_addr and vault_token"):
        make_settings(key_provider="vault")


def test_vault_key_provider_needs_https_outside_dev() -> None:
    with pytest.raises(ValidationError, match="must use https"):
        make_settings(
            env="production", key_provider="vault", vault_addr="http://vault:8200", vault_token="t"
        )


def test_vault_key_provider_accepted_in_dev() -> None:
    s = make_settings(key_provider="vault", vault_addr="http://vault:8200", vault_token="t")
    assert s.key_provider == "vault"
