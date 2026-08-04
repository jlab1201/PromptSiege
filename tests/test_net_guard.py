
import pytest

from ui.net_guard import ALLOW_PRIVATE_ENV, validate_public_url


def test_accepts_public_https(monkeypatch):
    # Don't hit live DNS in a unit test — exercise the accept path via the
    # private-target flag instead.
    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
    assert validate_public_url("https://example.com") == "https://example.com"


def test_bare_domain_defaults_to_https(monkeypatch):
    # Flag set to skip live DNS; exercises the scheme-normalization path.
    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
    assert validate_public_url("example.com") == "https://example.com"
    # "://" check (not parsed.scheme) so host:port isn't misread as a scheme.
    assert validate_public_url("example.com:8080") == "https://example.com:8080"
    # Already-schemed URLs pass through unchanged.
    assert validate_public_url("http://example.com") == "http://example.com"


def test_rejects_file_scheme():
    with pytest.raises(ValueError):
        validate_public_url("file:///etc/passwd")


def test_rejects_cloud_metadata_ip():
    with pytest.raises(ValueError):
        validate_public_url("http://169.254.169.254/")


def test_rejects_loopback():
    with pytest.raises(ValueError):
        validate_public_url("http://127.0.0.1/")


def test_allows_private_when_flag_set(monkeypatch):
    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
    assert validate_public_url("http://127.0.0.1:8000/") == "http://127.0.0.1:8000/"


def test_still_rejects_bad_scheme_when_flag_set(monkeypatch):
    monkeypatch.setenv(ALLOW_PRIVATE_ENV, "1")
    with pytest.raises(ValueError):
        validate_public_url("file:///etc/passwd")
