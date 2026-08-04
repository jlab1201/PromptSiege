"""Every request field that reaches a network sink must be guarded.

host_page_url goes to page.goto() in the browser runner; base_url receives the
API key and the captured transcripts. They need *different* guards, and the
difference is the point: host_page_url gets the full SSRF check, base_url only
a scheme check, because a self-hosted judge on localhost is documented and
supported (README: "a self-hosted OpenAI-compat endpoint via base_url").
"""
import pytest
from pydantic import ValidationError

from ui.server import JudgeConfigBody, StartRunBody


def _start(**kw):
    return StartRunBody(target_url="https://example.com", **kw)


def test_host_page_url_rejects_file_scheme(monkeypatch):
    monkeypatch.setenv("PROMPTSIEGE_ALLOW_PRIVATE_TARGETS", "1")
    with pytest.raises(ValidationError):
        _start(host_page_url="file:///etc/passwd")


def test_host_page_url_rejects_cloud_metadata():
    # target_url is an IP literal on purpose: getaddrinfo parses it without a
    # DNS lookup, so this reaches the link-local branch offline. With a
    # hostname it passed for the wrong reason — target_url failed to resolve
    # first and the branch under test never ran.
    with pytest.raises(ValidationError) as exc:
        StartRunBody(
            target_url="https://1.1.1.1",
            host_page_url="http://169.254.169.254/latest/meta-data/",
        )
    assert [e["loc"] for e in exc.value.errors()] == [("host_page_url",)]
    assert "disallowed/private" in str(exc.value)


def test_host_page_url_empty_is_allowed(monkeypatch):
    # Optional field — the HTTP runner never sets it.
    monkeypatch.setenv("PROMPTSIEGE_ALLOW_PRIVATE_TARGETS", "1")
    assert _start(host_page_url="").host_page_url == ""


def test_host_page_url_accepts_a_normal_page(monkeypatch):
    monkeypatch.setenv("PROMPTSIEGE_ALLOW_PRIVATE_TARGETS", "1")
    assert _start(host_page_url="https://example.com/support").host_page_url


def test_base_url_rejects_file_scheme():
    with pytest.raises(ValidationError):
        JudgeConfigBody(api_key="k", base_url="file:///etc/passwd")


def test_base_url_still_allows_a_self_hosted_judge():
    # Documented feature — must NOT be blocked the way host_page_url is.
    body = JudgeConfigBody(api_key="k", base_url="http://localhost:11434/v1")
    assert body.base_url == "http://localhost:11434/v1"
