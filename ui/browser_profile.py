"""One canonical Chrome identity, shared by every outbound request.

Navigation and XHR differ deliberately: a POST to a chat API carrying
`Sec-Fetch-Dest: document` is a stronger bot tell than sending no
Sec-Fetch-* headers at all.
"""

CHROME_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36"
)
SEC_CH_UA = '"Google Chrome";v="131", "Chromium";v="131", "Not_A Brand";v="24"'

# dict order == wire order in httpx
_COMMON = {
    "sec-ch-ua": SEC_CH_UA,
    "sec-ch-ua-mobile": "?0",
    "sec-ch-ua-platform": '"Windows"',
    "User-Agent": CHROME_UA,
    "Accept-Language": "en-US,en;q=0.9",
}

# Landing-page GETs.
NAVIGATION = {
    **_COMMON,
    "Upgrade-Insecure-Requests": "1",
    "Accept": (
        "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,"
        "image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7"
    ),
    "Sec-Fetch-Site": "none",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-User": "?1",
    "Sec-Fetch-Dest": "document",
}

# The chat POST.
XHR = {
    **_COMMON,
    "Accept": "*/*",
    "Sec-Fetch-Site": "same-origin",
    "Sec-Fetch-Mode": "cors",
    "Sec-Fetch-Dest": "empty",
}

# For engagements that need the traffic attributable in the client's logs.
HONEST = {"User-Agent": "PromptSiege/0.1.0"}

# Intentionally absent, all three would make us LESS realistic, not more:
#   Accept-Encoding - httpx sets it from installed decoders; hardcoding `br`
#                     without brotli installed yields undecodable bodies.
#   Connection      - h11 owns it, and it is illegal on HTTP/2.
#   DNT / Priority  - Chrome sends neither by default (Priority is an h2 frame).


def parse_custom(text: str) -> dict[str, str]:
    """Parse operator-supplied `Name: value` lines. Blank and `#` lines skipped."""
    headers: dict[str, str] = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        name, _, value = line.partition(":")
        name, value = name.strip(), value.strip()
        if name:
            headers[name] = value
    return headers
