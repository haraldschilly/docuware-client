"""Tests for ConnectedAppAuthenticator (client_credentials grant)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import httpx
import pytest

from docuware import errors
from docuware.auth import ConnectedAppAuthenticator

IDENTITY_URL = "https://acme.docuware.cloud/DocuWare/Identity"
TOKEN_EP = f"{IDENTITY_URL}/connect/token"


def _make_conn():
    """Create a minimal mock Connection."""
    conn = MagicMock()
    conn.session = MagicMock(spec=httpx.Client)
    conn.make_url = lambda path: path if path.startswith("http") else f"https://acme.docuware.cloud{path}"
    return conn


def _ok_response(json_data):
    resp = MagicMock(spec=httpx.Response)
    resp.status_code = 200
    resp.text = ""
    return resp


class TestConnectedAppAuthenticator:
    def setup_method(self):
        self.auth = ConnectedAppAuthenticator(
            client_id="my-app-id",
            client_secret="my-app-secret",
        )

    def _patch_requests(self, conn):
        """Patch the conn.session.get and conn.session.post to simulate the 3-step flow."""
        identity_info = {"IdentityServiceUrl": IDENTITY_URL}
        oidc_config = {"token_endpoint": TOKEN_EP}
        token_response = {"access_token": "at_cc_123", "token_type": "Bearer", "expires_in": 3600}

        call_count = {"get": 0, "post": 0}

        def mock_get(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            if call_count["get"] == 0:
                resp.text = __import__("json").dumps(identity_info)
            else:
                resp.text = __import__("json").dumps(oidc_config)
            call_count["get"] += 1
            return resp

        def mock_post(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = __import__("json").dumps(token_response)
            call_count["post"] += 1
            return resp

        conn.session.get = mock_get
        conn.session.post = mock_post
        return call_count

    def test_login_sets_bearer_token(self):
        conn = _make_conn()
        self._patch_requests(conn)

        self.auth.login(conn)

        assert self.auth.token == "at_cc_123"
        assert conn.session.auth is not None
        assert conn.session.auth.token == "at_cc_123"

    def test_authenticate_refreshes_token(self):
        conn = _make_conn()
        self._patch_requests(conn)

        result = self.auth.authenticate(conn)

        assert self.auth.token == "at_cc_123"
        assert result is conn.session

    def test_posts_client_credentials_grant(self):
        conn = _make_conn()
        self._patch_requests(conn)

        posted_data = {}
        original_post = conn.session.post

        def capture_post(url, **kwargs):
            posted_data.update(kwargs.get("data", {}))
            return original_post(url, **kwargs)

        conn.session.post = capture_post
        self.auth.login(conn)

        assert posted_data["grant_type"] == "client_credentials"
        assert posted_data["client_id"] == "my-app-id"
        assert posted_data["client_secret"] == "my-app-secret"
        assert posted_data["scope"] == "docuware.platform"

    def test_custom_scope(self):
        auth = ConnectedAppAuthenticator(
            client_id="cid",
            client_secret="csec",
            scope="docuware.platform openid",
        )
        conn = _make_conn()

        identity_info = {"IdentityServiceUrl": IDENTITY_URL}
        oidc_config = {"token_endpoint": TOKEN_EP}
        token_response = {"access_token": "at", "token_type": "Bearer", "expires_in": 3600}

        call_count = {"get": 0}
        posted_data = {}

        def mock_get(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            if call_count["get"] == 0:
                resp.text = __import__("json").dumps(identity_info)
            else:
                resp.text = __import__("json").dumps(oidc_config)
            call_count["get"] += 1
            return resp

        def mock_post(url, **kwargs):
            posted_data.update(kwargs.get("data", {}))
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = __import__("json").dumps(token_response)
            return resp

        conn.session.get = mock_get
        conn.session.post = mock_post

        auth.login(conn)
        assert posted_data["scope"] == "docuware.platform openid"

    def test_raises_account_error_on_400(self):
        conn = _make_conn()
        identity_info = {"IdentityServiceUrl": IDENTITY_URL}
        oidc_config = {"token_endpoint": TOKEN_EP}

        call_count = {"get": 0}

        def mock_get(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            if call_count["get"] == 0:
                resp.text = __import__("json").dumps(identity_info)
            else:
                resp.text = __import__("json").dumps(oidc_config)
            call_count["get"] += 1
            return resp

        def mock_post(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 400
            resp.text = '{"error": "invalid_client"}'
            return resp

        conn.session.get = mock_get
        conn.session.post = mock_post

        with pytest.raises(errors.AccountError, match="invalid client_id or client_secret"):
            self.auth.login(conn)

    def test_raises_account_error_on_missing_token(self):
        conn = _make_conn()
        identity_info = {"IdentityServiceUrl": IDENTITY_URL}
        oidc_config = {"token_endpoint": TOKEN_EP}
        empty_response = {"token_type": "Bearer"}

        call_count = {"get": 0}

        def mock_get(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            if call_count["get"] == 0:
                resp.text = __import__("json").dumps(identity_info)
            else:
                resp.text = __import__("json").dumps(oidc_config)
            call_count["get"] += 1
            return resp

        def mock_post(url, **kwargs):
            resp = MagicMock(spec=httpx.Response)
            resp.status_code = 200
            resp.text = __import__("json").dumps(empty_response)
            return resp

        conn.session.get = mock_get
        conn.session.post = mock_post

        with pytest.raises(errors.AccountError, match="No access token received"):
            self.auth.login(conn)

    def test_logoff_clears_token(self):
        conn = _make_conn()
        self._patch_requests(conn)

        self.auth.login(conn)
        assert self.auth.token is not None

        self.auth.logoff(conn)
        assert self.auth.token is None

    def test_logoff_noop_without_token(self):
        conn = _make_conn()
        self.auth.logoff(conn)  # should not raise
        assert self.auth.token is None
