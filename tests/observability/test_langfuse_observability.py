import sys
import types

import flocks.utils.langfuse as lf


class _FakeParent:
    def __init__(self) -> None:
        self.last_span_payload = None
        self.last_generation_payload = None

    def span(self, **kwargs):
        self.last_span_payload = kwargs
        return {"kind": "span", "payload": kwargs}

    def generation(self, **kwargs):
        self.last_generation_payload = kwargs
        return {"kind": "generation", "payload": kwargs}


class _FakeTraceClient:
    def __init__(self):
        self.trace_payload = None

    def trace(self, **kwargs):
        self.trace_payload = kwargs
        return _FakeObservation("trace", kwargs)


class _FakeObservation:
    """Fake Langfuse observation with end/generation/span support."""

    def __init__(self, kind: str, payload: dict):
        self.kind = kind
        self.payload = payload
        self.end_payload = None

    def generation(self, **kwargs):
        return _FakeObservation("generation", kwargs)

    def span(self, **kwargs):
        return _FakeObservation("span", kwargs)

    def end(self, **kwargs):
        self.end_payload = kwargs


def test_create_span_uses_current_observation(monkeypatch):
    monkeypatch.setattr(lf, "_get_client", lambda: object())
    parent = _FakeParent()

    with lf.ObservationScope(parent):
        obs = lf.create_span(
            name="tool.read",
            input={"path": "/tmp/demo.txt"},
        )

    assert obs["kind"] == "span"
    assert parent.last_span_payload is not None
    assert parent.last_span_payload["name"] == "tool.read"


def test_create_generation_uses_current_observation(monkeypatch):
    monkeypatch.setattr(lf, "_get_client", lambda: object())
    parent = _FakeParent()

    with lf.ObservationScope(parent):
        obs = lf.create_generation(
            name="llm.stream",
            model="gpt-5",
            input=[{"role": "user", "content": "hello"}],
        )

    assert obs["kind"] == "generation"
    assert parent.last_generation_payload is not None
    assert parent.last_generation_payload["name"] == "llm.stream"


def test_create_trace_forwards_tags(monkeypatch):
    client = _FakeTraceClient()
    monkeypatch.setattr(lf, "_get_client", lambda: client)

    obs = lf.create_trace(
        name="SessionRunner.step",
        session_id="s1",
        tags=["session:s1", "step:2", "session_step:s1:2"],
        input={"step": 2},
    )

    assert obs.kind == "trace"
    assert client.trace_payload is not None
    assert client.trace_payload["tags"] == ["session:s1", "step:2", "session_step:s1:2"]


def test_initialize_supports_langfuse_base_url(monkeypatch):
    class _FakeLangfuseClient:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

    fake_module = types.SimpleNamespace(Langfuse=_FakeLangfuseClient)
    monkeypatch.setitem(sys.modules, "langfuse", fake_module)

    monkeypatch.setenv("LANGFUSE_PUBLIC_KEY", "pk-test")
    monkeypatch.setenv("LANGFUSE_SECRET_KEY", "sk-test")
    monkeypatch.setenv("LANGFUSE_BASE_URL", "https://cloud.langfuse.com")
    monkeypatch.delenv("LANGFUSE_HOST", raising=False)
    monkeypatch.delenv("LANGFUSE_BASEURL", raising=False)
    monkeypatch.setenv("FLOCKS_LANGFUSE_ENABLED", "true")

    lf._initialized = False
    lf._client = None
    lf.initialize()

    assert lf._client is not None
    assert lf._client.kwargs["host"] == "https://cloud.langfuse.com"


def test_noop_when_not_configured():
    """Verify all operations are safe no-ops when Langfuse is not configured."""
    prev_client = lf._client
    prev_init = lf._initialized
    try:
        lf._client = None
        lf._initialized = True

        trace = lf.create_trace(name="test", session_id="s1")
        assert isinstance(trace, lf._NoopObservation)

        gen = lf.create_generation(parent=trace, name="gen", model="m")
        assert isinstance(gen, lf._NoopObservation)

        span = lf.create_span(parent=gen, name="sp")
        assert isinstance(span, lf._NoopObservation)

        lf.end_observation(gen, output="done", usage={"prompt_tokens": 10})
        lf.end_observation(trace, output="ok")

        assert not lf.is_active()
    finally:
        lf._client = prev_client
        lf._initialized = prev_init


def test_end_observation_passes_usage(monkeypatch):
    """Verify usage dict is forwarded correctly to observation.end()."""
    client = _FakeTraceClient()
    monkeypatch.setattr(lf, "_get_client", lambda: client)

    trace_obs = lf.create_trace(name="t", session_id="s")
    gen_obs = lf.create_generation(parent=trace_obs, name="g", model="m")
    usage = {"prompt_tokens": 100, "completion_tokens": 50}
    lf.end_observation(gen_obs, output="result", usage=usage)

    assert gen_obs.end_payload is not None
    assert gen_obs.end_payload.get("usage") == usage
    assert gen_obs.end_payload.get("output") == "result"


def test_scope_end_is_idempotent():
    """Calling end() twice on a scope should not raise."""
    noop = lf._NoopObservation("test")
    scope = lf.ObservationScope(noop)
    scope.end(output="first")
    scope.end(output="second")


def test_sanitize_truncates_long_strings():
    long_str = "a" * 10000
    result = lf._sanitize_payload(long_str)
    assert len(result) < 10000
    assert "truncated" in result


def test_observation_scope_exception_handling():
    """ObservationScope.__exit__ should end the observation on exception."""

    class _TrackingObs:
        def __init__(self):
            self.ended = False
            self.end_kwargs = {}

        def end(self, **kwargs):
            self.ended = True
            self.end_kwargs = kwargs

    obs = _TrackingObs()
    try:
        with lf.ObservationScope(obs):
            raise ValueError("test error")
    except ValueError:
        pass

    assert obs.ended
    assert obs.end_kwargs.get("level") == "ERROR"
