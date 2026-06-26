from unittest.mock import MagicMock, patch

import pytest
import requests

from arango_cve_processor.tools.nvd import RATE_LIMIT_WINDOW, fetch_nvd_api


def make_mock_response(
    status_code=200, total_results=2, results_per_page=1, start_index=0
):
    match_id = f"criteria-{start_index}"
    return MagicMock(
        status_code=status_code,
        reason="OK" if status_code == 200 else "Error",
        json=MagicMock(
            return_value={
                "totalResults": total_results,
                "resultsPerPage": results_per_page,
                "matchStrings": [
                    {"matchString": {"matchCriteriaId": match_id}},
                ],
            }
        ),
        url=f"https://mocked.url/api?startIndex={start_index}",
        request=MagicMock(headers={}),
    )


def test_fetch_nvd_success():
    with patch("requests.Session.get") as mock_get, patch("time.sleep") as mock_sleep:

        # Simulate 2 pages (0 and 1)
        mock_get.side_effect = [
            make_mock_response(start_index=0),
            make_mock_response(start_index=1),
        ]

        results = list(fetch_nvd_api("", {}))

        assert len(results) == 2  # 2 pages
        assert all(isinstance(group, dict) for group in results)
        assert mock_sleep.call_count == 1  # 1 sleep between 2 pages


def test_fetch_nvd_with_backoff():
    with patch("requests.Session.get") as mock_get, patch("time.sleep") as mock_sleep:

        # Simulate a connection error first, then success
        mock_get.side_effect = [
            requests.ConnectionError(),
            make_mock_response(start_index=0),
            make_mock_response(start_index=1),
        ]

        results = list(fetch_nvd_api("", {}))

        assert len(results) == 2
        assert mock_sleep.call_count >= 2  # One for backoff, one for pagination
        # First sleep is backoff, second is rate limit
        # first_sleep_duration = RATE_LIMIT_WINDOW / 2
        # second_sleep_duration = RATE_LIMIT_WINDOW / cpematch_manager.requests_per_window
        assert mock_sleep.call_count == 2


@pytest.mark.parametrize(
    "api_key,api_key_env,expected",
    [
        [None, None, None],
        ["arg", None, "arg"],
        ["arg", "env", "arg"],
        [None, "env", "env"],
    ],
)
def test_fetch_nvd_uses_api_key(api_key, api_key_env, expected, monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    if api_key_env:
        monkeypatch.setenv("NVD_API_KEY", api_key_env)

    patched_session = requests.Session()
    monkeypatch.setattr(requests, "Session", MagicMock(return_value=patched_session))
    monkeypatch.setattr(
        patched_session,
        "get",
        MagicMock(
            side_effect=[
                make_mock_response(start_index=0),
                make_mock_response(start_index=1),
            ]
        ),
    )
    with patch("time.sleep") as mock_sleep:

        # Simulate a connection error first, then success
        results = list(fetch_nvd_api("", {}, api_key=api_key))
    assert patched_session.headers.get("apiKey") == expected
