"""Stop must take effect inside the adapter's poll loops.

The stop endpoint only sets cancel_event — it never calls task.cancel(). The
runner polls that event between prompts, but the adapter's own waits did not,
so Stop pressed mid-turn sat through a 45s reply wait, or up to ~130s of
open_widget polling. These assert the loops bail out immediately.
"""
import asyncio

import pytest

from ui.browser_adapters import AdaAdapter, _Cancelled


class _FakePage:
    """Records every sleep so a test can prove the loop never ran."""

    def __init__(self):
        self.sleeps = 0

    async def wait_for_timeout(self, _ms):
        self.sleeps += 1

    async def query_selector(self, _sel):
        return None  # frame never appears — the loop would run to its limit

    async def goto(self, _url, **_kw):
        return None


class _FakeFrame:
    async def evaluate(self, *_a, **_kw):
        return 0


def _adapter():
    a = AdaAdapter(_FakePage())
    a.chat_frame = _FakeFrame()
    return a


def test_wait_for_reply_returns_at_once_when_already_cancelled():
    a = _adapter()
    ev = asyncio.Event()
    ev.set()
    reply = asyncio.run(a.wait_for_reply(before_count=0, timeout_s=45, cancel=ev))
    assert reply.timed_out is True
    assert a.page.sleeps == 0, "cancelled wait still slept — Stop would hang the turn"


def test_wait_for_reply_without_cancel_still_polls():
    # Guard against "fixing" the hang by making the loop never run at all.
    a = _adapter()
    reply = asyncio.run(a.wait_for_reply(before_count=0, timeout_s=3, cancel=None))
    assert reply.timed_out is True
    assert a.page.sleeps == 3


def test_wait_for_reply_ignores_an_unset_event():
    a = _adapter()
    reply = asyncio.run(a.wait_for_reply(before_count=0, timeout_s=2, cancel=asyncio.Event()))
    assert reply.timed_out is True
    assert a.page.sleeps == 2


def test_open_widget_raises_cancelled_instead_of_half_opening():
    a = _adapter()
    ev = asyncio.Event()
    ev.set()
    with pytest.raises(_Cancelled):
        asyncio.run(a.open_widget("https://example.com/support", cancel=ev))
    assert a.page.sleeps == 0


def test_open_widget_without_cancel_still_fails_loudly():
    # No cancel: the button frame never appears, so it must raise the real
    # error rather than silently returning a half-open widget.
    a = _adapter()
    with pytest.raises(RuntimeError, match="button frame"):
        asyncio.run(a.open_widget("https://example.com/support", cancel=None))
