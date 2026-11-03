import pytest
from unittest.mock import patch, MagicMock
from prometheus.config import Settings


def test_config_plain_strings():
    s = Settings(github_token='token_plain_test', gemini_api_key='gemini_token_123')
    assert s.github_token == 'token_plain_test'
    assert s.gemini_api_key == 'gemini_token_123'


def test_config_empty_strings_convert_to_none():
    s = Settings(github_token='   ', gemini_api_key='')
    assert s.github_token is None
    assert s.gemini_api_key is None


def test_config_secret_manager_resolution():
    with patch('google.cloud.secretmanager.SecretManagerServiceClient') as mock_sm:
        mock_client = MagicMock()
        mock_resp = MagicMock()
        mock_resp.payload.data.decode.return_value = 'live-secret-val-456'
        mock_client.access_secret_version.return_value = mock_resp
        mock_sm.return_value = mock_client

        s = Settings(
            github_token='sm://prometheus-github-token',
            gemini_api_key='secretmanager://projects/my-proj/secrets/gemini-token/versions/2'
        )
        assert s.github_token == 'live-secret-val-456'
        assert s.gemini_api_key == 'live-secret-val-456'


def test_config_secret_manager_fallback_on_error():
    with patch('google.cloud.secretmanager.SecretManagerServiceClient', side_effect=Exception('SM Down')):
        s = Settings(github_token='sm://prometheus-github-token')
        assert s.github_token == 'sm://prometheus-github-token'
