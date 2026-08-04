import asyncio
from types import SimpleNamespace

import pytest

from ui.narrative import _RESP_CAP, _SAMPLES, build_payload, generate_narrative


def _records():
    return [
        {"id": "a", "category": "dan", "injection_outcome": "compromised",
         "prompt": "do X", "response": "ok here is X"},
        {"id": "b", "category": "dan", "injection_outcome": "refused",
         "prompt": "do Y", "response": "no"},
        {"id": "c", "category": "system_leak", "injection_outcome": "compromised",
         "prompt": "leak", "response": "system: ..."},
    ]


def test_payload_has_per_category_counts():
    p = build_payload({"target_url": "http://t"}, _records())
    assert p["per_category"]["dan"]["compromised"] == 1
    assert p["per_category"]["dan"]["refused"] == 1
    assert p["per_category"]["system_leak"]["compromised"] == 1


def test_payload_limits_sample_exchanges():
    many = [{"id": str(i), "category": "dan", "injection_outcome": "compromised",
             "prompt": "p", "response": "r"} for i in range(50)]
    p = build_payload({"target_url": "http://t"}, many)
    assert len(p["sample_compromised"]) == _SAMPLES


def test_payload_trims_long_responses():
    rec = [{"id": "a", "category": "dan", "injection_outcome": "compromised",
            "prompt": "p", "response": "x" * 5000}]
    p = build_payload({"target_url": "http://t"}, rec)
    assert len(p["sample_compromised"][0]["response"]) == _RESP_CAP


class _FakeClient:
    def __init__(self, payload):
        self._payload = payload
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    async def _create(self, **kwargs):
        msg = SimpleNamespace(content=self._payload)
        return SimpleNamespace(choices=[SimpleNamespace(message=msg)])


def test_generate_narrative_shapes_result():
    payload = '{"risk_level":"High","strengths":["refuses DAN"],' \
              '"weaknesses":["leaks system prompt"],"remediation":["add output filter"],' \
              '"atlas_refs":["AML.T0056"],"owasp_refs":["LLM07"]}'
    out = asyncio.run(generate_narrative(
        {"target_url": "http://t"},
        [{"id": "a", "category": "system_leak", "injection_outcome": "compromised",
          "prompt": "leak", "response": "system: secret"}],
        _FakeClient(payload), "gpt-4o-mini",
    ))
    assert out["risk_level"] == "High"
    assert out["model"] == "gpt-4o-mini"
    assert "generated_at" in out


def test_generate_narrative_falls_back_without_response_format():
    """Some openai-compat providers reject response_format with a 400;
    generate_narrative must retry once without it and still succeed."""
    import httpx
    import openai

    req = httpx.Request("POST", "https://api.example.com/v1/chat/completions")
    resp = httpx.Response(400, request=req, json={"error": {"message": "response_format not supported"}})
    bad_request = openai.BadRequestError("response_format not supported", response=resp, body=None)

    payload = '{"risk_level":"Low","strengths":[],"weaknesses":[],' \
              '"remediation":[],"atlas_refs":[],"owasp_refs":[]}'

    class _FlakyClient:
        def __init__(self):
            self.calls = 0
            self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

        async def _create(self, **kwargs):
            self.calls += 1
            if self.calls == 1:
                raise bad_request
            msg = SimpleNamespace(content=payload)
            return SimpleNamespace(choices=[SimpleNamespace(message=msg)])

    out = asyncio.run(generate_narrative(
        {"target_url": "http://t"},
        [{"id": "a", "category": "system_leak", "injection_outcome": "compromised",
          "prompt": "leak", "response": "system: secret"}],
        _FlakyClient(), "gpt-4o-mini",
    ))
    assert out["risk_level"] == "Low"


def test_generate_narrative_raises_on_malformed_json():
    with pytest.raises(ValueError):
        asyncio.run(generate_narrative(
            {"target_url": "http://t"},
            [{"id": "a", "category": "system_leak", "injection_outcome": "compromised",
              "prompt": "leak", "response": "system: secret"}],
            _FakeClient("not json at all"), "gpt-4o-mini",
        ))
