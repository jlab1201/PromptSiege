from ui.browser_profile import NAVIGATION, XHR, parse_custom


def test_fetch_dest_split():
    """Regression: XHR vs NAVIGATION must differ on Sec-Fetch-Dest."""
    assert XHR["Sec-Fetch-Dest"] == "empty"
    assert NAVIGATION["Sec-Fetch-Dest"] == "document"


def test_no_forbidden_headers():
    """Accept-Encoding and Connection must not appear (case-insensitive)."""
    nav_lower = {k.lower(): v for k, v in NAVIGATION.items()}
    xhr_lower = {k.lower(): v for k, v in XHR.items()}

    assert "accept-encoding" not in nav_lower
    assert "connection" not in nav_lower
    assert "accept-encoding" not in xhr_lower
    assert "connection" not in xhr_lower


def test_parse_custom_with_colons():
    """Colons in values are preserved; comments and blanks skipped."""
    result = parse_custom("Authorization: Bearer x\n\n# comment\nX-Foo: a: b\n")
    assert result == {"Authorization": "Bearer x", "X-Foo": "a: b"}


def test_parse_custom_empty():
    """Empty input yields empty dict."""
    assert parse_custom("") == {}
