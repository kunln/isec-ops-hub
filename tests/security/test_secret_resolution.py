from unittest.mock import MagicMock

from flocks.security import resolve_secret_refs, resolve_secret_value


def test_resolve_secret_value_derives_fofa_email_and_api_key_from_canonical_secret():
    secrets = MagicMock()
    secrets.get.side_effect = lambda key: {
        "fofa_key": "analyst@example.com:fofa-api-key",
    }.get(key)

    assert resolve_secret_value("fofa_email", secrets) == "analyst@example.com"
    assert resolve_secret_value("fofa_api_key", secrets) == "fofa-api-key"


def test_resolve_secret_value_prefers_real_fofa_split_secrets():
    secrets = MagicMock()
    secrets.get.side_effect = lambda key: {
        "fofa_key": "analyst@example.com:fofa-api-key",
        "fofa_email": "override@example.com",
        "fofa_api_key": "override-api-key",
    }.get(key)

    assert resolve_secret_value("fofa_email", secrets) == "override@example.com"
    assert resolve_secret_value("fofa_api_key", secrets) == "override-api-key"


def test_resolve_secret_refs_returns_empty_for_invalid_fofa_canonical_secret():
    secrets = MagicMock()
    secrets.get.side_effect = lambda key: {
        "fofa_key": "not-a-valid-compound-secret",
    }.get(key)

    assert resolve_secret_refs("email={secret:fofa_email}&key={secret:fofa_api_key}", secrets) == "email=&key="
