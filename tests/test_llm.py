"""Tests for llm.py: verify 429 and 503 trigger backoff, not crashes."""
import time
import unittest.mock as mock

import pytest

import llm


class _FakeError(Exception):
    """Simulates a provider HTTP error with a status code."""
    def __init__(self, status_code: int):
        super().__init__(f"Error code: {status_code} - rate limited")
        self.status_code = status_code


def _patched_complete(provider_fn, call_results):
    """Run llm.complete() with a fake provider that returns items from call_results in order.
    call_results: list of (Exception | str); Exception is raised, str is returned.
    """
    calls = iter(call_results)

    def fake_provider(system, user, json_schema):
        result = next(calls)
        if isinstance(result, Exception):
            raise result
        return result

    with mock.patch.dict(llm._PROVIDERS, {llm.PROVIDER: fake_provider}):
        with mock.patch.object(llm, "_rate_limit"):  # bypass RPM limiter
            with mock.patch.object(time, "sleep") as mock_sleep:
                return llm.complete("sys", "user"), mock_sleep


def test_429_retried_and_succeeds():
    result, mock_sleep = _patched_complete(None, [_FakeError(429), "OK"])
    assert result == "OK"
    assert mock_sleep.call_count == 1
    wait = mock_sleep.call_args[0][0]
    assert wait >= 1  # exponential backoff: 2^0 = 1s


def test_503_retried_and_succeeds():
    result, mock_sleep = _patched_complete(None, [_FakeError(503), "response"])
    assert result == "response"
    assert mock_sleep.call_count == 1


def test_429_three_times_raises_not_crashes():
    with pytest.raises(_FakeError):
        _patched_complete(None, [_FakeError(429), _FakeError(429), _FakeError(429)])


def test_non_retryable_error_raises_immediately():
    class _AuthError(Exception):
        status_code = 401
    with pytest.raises(_AuthError):
        _patched_complete(None, [_AuthError()])


def test_second_retry_uses_longer_backoff():
    _, mock_sleep = _patched_complete(None, [_FakeError(429), _FakeError(503), "done"])
    assert mock_sleep.call_count == 2
    waits = [c[0][0] for c in mock_sleep.call_args_list]
    assert waits[1] > waits[0]  # second wait is longer (2^1 > 2^0)


def test_fence_stripping():
    assert llm._strip_fences('```json\n{"a": 1}\n```') == '{"a": 1}'
    assert llm._strip_fences("plain text") == "plain text"
    assert llm._strip_fences("```\nresult\n```") == "result"


def test_status_code_extraction():
    assert llm._status_code(_FakeError(429)) == 429
    assert llm._status_code(_FakeError(503)) == 503
    assert llm._status_code(ValueError("oops")) is None
