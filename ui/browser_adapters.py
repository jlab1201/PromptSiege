"""
Browser adapters for SaaS chatbot widgets.

Each adapter knows the DOM quirks of one chat-widget provider — where the
launcher button lives, which iframe holds the chat, what selector the input
uses, how to submit a message, and how to spot a fresh bot reply.

The base class defines the interface; per-provider subclasses implement it.
A registry maps platform keys (matching discover.py's classification) to
the right adapter so runner_browser can pick automatically.
"""
from __future__ import annotations

from asyncio import Event
from dataclasses import dataclass

from playwright.async_api import Frame, Page

from .browser_profile import CHROME_UA  # noqa: F401  (re-exported for runner_browser)


class _Cancelled(Exception):
    """Operator hit Stop mid-open. Raised instead of returning a half-open
    widget, which would make every later prompt fail confusingly."""


@dataclass
class ReplyResult:
    """One bot reply captured from the widget."""
    text: str            # what the bot said (joined message bubbles since last)
    bubble_count: int    # total message-bubble count after reply
    timed_out: bool      # True if we hit timeout without a new reply


class BrowserAdapter:
    """Base class — one instance drives one open chat session for a whole run."""

    name = "base"

    def __init__(self, page: Page) -> None:
        self.page = page
        self.chat_frame: Frame | None = None

    async def open_widget(self, host_page_url: str, cancel: Event | None = None) -> None:
        """Navigate to host page, click launcher, store the chat frame.

        ``cancel`` is polled inside the poll loops so Stop takes effect
        promptly — without it a click can sit through ~130s of waiting.
        """
        raise NotImplementedError

    async def send_message(self, text: str) -> None:
        """Type text into the chat input and submit."""
        raise NotImplementedError

    async def wait_for_reply(
        self, before_count: int, timeout_s: int = 45, cancel: Event | None = None,
    ) -> ReplyResult:
        """Wait for new bubble(s) to appear, return their joined text."""
        raise NotImplementedError

    async def current_bubble_count(self) -> int:
        """Total message bubbles currently in the chat. Used to detect new ones."""
        raise NotImplementedError


# ----------------------------------------------------------------------------
# Ada Chat Platform
# ----------------------------------------------------------------------------

class AdaAdapter(BrowserAdapter):
    """Ada widget: nested iframes ada-button-frame → ada-chat-frame."""

    name = "ada"

    BUTTON_FRAME_SEL = "iframe#ada-button-frame"
    CHAT_FRAME_SEL = "iframe#ada-chat-frame, iframe[id*='ada-chat']"
    INPUT_SELECTORS = (
        "textarea[aria-label*='message' i]",
        "textarea[placeholder*='message' i]",
        "textarea[placeholder*='type' i]",
        "[contenteditable='true']",
        "textarea",
    )
    BUBBLE_JS = (
        "() => document.querySelectorAll("
        "'[class*=\"message\" i], [class*=\"bubble\" i], [role=\"article\"], li'"
        ").length"
    )

    async def open_widget(self, host_page_url: str, cancel: Event | None = None) -> None:
        await self.page.goto(host_page_url, wait_until="networkidle", timeout=60_000)

        # Wait up to 40s for the button-frame to render visibly.
        btn_frame_el = None
        for _ in range(40):
            if cancel is not None and cancel.is_set():
                raise _Cancelled
            el = await self.page.query_selector(self.BUTTON_FRAME_SEL)
            if el and await el.is_visible():
                btn_frame_el = el
                break
            await self.page.wait_for_timeout(1_000)
        if not btn_frame_el:
            raise RuntimeError("Ada button frame never became visible")

        btn_frame = await btn_frame_el.content_frame()
        # Click the actual button inside the launcher frame.
        clicked = False
        for sel in ("button", "[role='button']", "div[onclick]"):
            b = await btn_frame.query_selector(sel)
            if b:
                await b.click()
                clicked = True
                break
        if not clicked:
            raise RuntimeError("no clickable element in Ada button frame")

        # Wait for the chat-frame to materialize.
        chat_frame_el = None
        for _ in range(30):
            if cancel is not None and cancel.is_set():
                raise _Cancelled
            el = await self.page.query_selector(self.CHAT_FRAME_SEL)
            if el and await el.is_visible():
                chat_frame_el = el
                break
            await self.page.wait_for_timeout(1_000)
        if not chat_frame_el:
            raise RuntimeError("Ada chat frame never appeared")

        self.chat_frame = await chat_frame_el.content_frame()
        # Let the greeting bubbles render before the first send.
        await self.page.wait_for_timeout(3_000)

    async def _input_handle(self):
        assert self.chat_frame is not None
        for sel in self.INPUT_SELECTORS:
            try:
                await self.chat_frame.wait_for_selector(sel, timeout=4_000, state="visible")
                el = await self.chat_frame.query_selector(sel)
                if el:
                    return el
            except Exception:
                continue
        return None

    async def send_message(self, text: str) -> None:
        assert self.chat_frame is not None
        input_el = await self._input_handle()
        if input_el is None:
            raise RuntimeError("Ada chat input not found")
        await input_el.click()
        await input_el.fill(text)
        await self.page.wait_for_timeout(300)
        # Submit via the textarea's parent form. Playwright's element.press("Enter")
        # doesn't fire React's synthetic onKeyDown handlers reliably; submitting
        # the form directly always works.
        await self.chat_frame.evaluate(
            """
            () => {
              const ta = document.querySelector(
                'textarea[aria-label*="message" i], '
                + 'textarea[placeholder*="message" i], '
                + 'textarea[placeholder*="type" i], textarea'
              );
              if (!ta) return;
              const form = ta.closest('form');
              if (form && typeof form.requestSubmit === 'function') {
                form.requestSubmit();
              } else if (form) {
                form.submit();
              } else {
                ta.dispatchEvent(new KeyboardEvent('keydown', {
                  key: 'Enter', code: 'Enter', keyCode: 13, which: 13, bubbles: true,
                }));
              }
            }
            """
        )

    async def current_bubble_count(self) -> int:
        assert self.chat_frame is not None
        return await self.chat_frame.evaluate(self.BUBBLE_JS)

    async def wait_for_reply(
        self, before_count: int, timeout_s: int = 45, cancel: Event | None = None,
    ) -> ReplyResult:
        assert self.chat_frame is not None
        # We sent our message (which becomes 1 bubble) and expect at least 1 more
        # from the bot. So target = before_count + 2 minimum.
        target = before_count + 2
        for _ in range(timeout_s):
            if cancel is not None and cancel.is_set():
                # Report what's there rather than raising: the caller's loop
                # checks cancel right after and ends the run cleanly.
                break
            await self.page.wait_for_timeout(1_000)
            now = await self.current_bubble_count()
            if now >= target:
                # Give a moment for the bubble's full text to render.
                await self.page.wait_for_timeout(2_000)
                text = await self._extract_recent_text(before_count)
                return ReplyResult(
                    text=text,
                    bubble_count=await self.current_bubble_count(),
                    timed_out=False,
                )
        text = await self._extract_recent_text(before_count)
        return ReplyResult(
            text=text,
            bubble_count=await self.current_bubble_count(),
            timed_out=True,
        )

    async def _extract_recent_text(self, since_count: int) -> str:
        """Pull text from message bubbles that appeared after since_count."""
        assert self.chat_frame is not None
        return await self.chat_frame.evaluate(
            """
            (since) => {
              const sels = ['[class*="message" i]','[class*="bubble" i]','[role="article"]','li'];
              const els = new Set();
              for (const s of sels)
                document.querySelectorAll(s).forEach(e => els.add(e));
              const arr = Array.from(els);
              const after = arr.slice(Math.max(0, since));
              return after.map(e => (e.innerText || '').trim())
                          .filter(t => t && t.length < 4000)
                          .join('\\n---\\n');
            }
            """,
            since_count,
        )


# ----------------------------------------------------------------------------
# Registry — discover.py's platform key -> adapter class
# ----------------------------------------------------------------------------

ADAPTERS: dict[str, type[BrowserAdapter]] = {
    "ada": AdaAdapter,
    # Future: "intercom": IntercomAdapter, "drift": DriftAdapter, "zendesk": ZendeskAdapter
}


def get_adapter(platform: str) -> type[BrowserAdapter] | None:
    return ADAPTERS.get(platform)
