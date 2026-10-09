from __future__ import annotations

import importlib.util
import io
import json
import sys
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch


ROOT = Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "scripts/cloudflare/verify_product_oauth_server.py"
SPEC = importlib.util.spec_from_file_location("ordax_oauth_metadata", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
oauth = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(oauth)

ISSUER = "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1"
ORIGIN = "https://jhfphsjptrpmtnzkpwud.supabase.co"


def metadata() -> dict:
    return {
        "issuer": ISSUER,
        "authorization_endpoint": f"{ISSUER}/oauth/authorize",
        "token_endpoint": f"{ISSUER}/oauth/token",
        "registration_endpoint": f"{ISSUER}/oauth/clients",
        "code_challenge_methods_supported": ["S256"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "response_types_supported": ["code"],
        "token_endpoint_auth_methods_supported": ["none", "client_secret_basic"],
    }


class OAuthMetadataReadinessTests(unittest.TestCase):
    def test_canonical_public_pkce_dcr_metadata_passes(self):
        self.assertEqual(oauth.validate_metadata(metadata(), ISSUER), [])

    def test_wrong_or_malformed_issuer_fails_closed(self):
        for issuer in (
            "https://other.invalid/auth/v1",
            "http://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1",
            "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/extra",
            "https://jhfphsjptrpmtnzkpwud.supabase.co.evil.invalid/auth/v1",
        ):
            with self.subTest(issuer=issuer):
                self.assertNotEqual(oauth.validate_metadata(metadata(), issuer), [])
        data = metadata()
        data["issuer"] = "https://other.supabase.co/auth/v1"
        self.assertIn("issuer does not match", " ".join(oauth.validate_metadata(data, ISSUER)))

    def test_metadata_cannot_inject_redirect_or_cross_origin_endpoints(self):
        for field in ("authorization_endpoint", "token_endpoint", "registration_endpoint"):
            for value in (
                "http://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/oauth/token",
                "https://evil.invalid/auth/v1/oauth/token",
                "https://jhfphsjptrpmtnzkpwud.supabase.co.evil.invalid/auth/v1/oauth/token",
                "https://jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/oauth/token?secret=x",
                "https://user@jhfphsjptrpmtnzkpwud.supabase.co/auth/v1/oauth/token",
                None,
            ):
                with self.subTest(field=field, value=value):
                    data = metadata()
                    data[field] = value
                    self.assertTrue(any(field in error for error in oauth.validate_metadata(data, ISSUER)))

    def test_public_pkce_dcr_and_authorization_code_are_required(self):
        for field, value in (
            ("registration_endpoint", None),
            ("code_challenge_methods_supported", ["plain"]),
            ("grant_types_supported", ["refresh_token"]),
            ("response_types_supported", ["token"]),
            ("token_endpoint_auth_methods_supported", ["client_secret_basic"]),
        ):
            with self.subTest(field=field):
                data = metadata()
                data[field] = value
                self.assertNotEqual(oauth.validate_metadata(data, ISSUER), [])

    def test_response_must_be_object(self):
        self.assertNotEqual(oauth.validate_metadata([], ISSUER), [])

    def test_oversized_response_is_rejected_before_parsing(self):
        class OversizedResponse:
            status = 200

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self, limit):
                self.limit = limit
                return b"x" * limit

        response = OversizedResponse()
        class Opener:
            def open(self, *_args, **_kwargs):
                return response

        with patch.object(oauth.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(SystemExit, "exceeds the maximum"):
                oauth._read_metadata(f"{ORIGIN}/.well-known/oauth-authorization-server/auth/v1")
        self.assertEqual(response.limit, oauth.MAX_DISCOVERY_BYTES + 1)

    def test_invalid_json_is_rejected(self):
        class Response:
            status = 200
            def __enter__(self):
                return self
            def __exit__(self, *_args):
                return False
            def read(self, _limit):
                return b"{invalid"

        class Opener:
            def open(self, *_args, **_kwargs):
                return Response()

        with patch.object(oauth.urllib.request, "build_opener", return_value=Opener()):
            with self.assertRaisesRegex(SystemExit, "not valid JSON"):
                oauth._read_metadata(f"{ORIGIN}/.well-known/oauth-authorization-server/auth/v1")

    def test_http_redirects_are_not_followed(self):
        handler = oauth._NoRedirectHandler()
        self.assertIsNone(handler.redirect_request(None, None, 302, "redirect", {}, "https://evil.invalid"))

    def test_cli_does_not_equate_advertisement_with_live_client_registration(self):
        url = f"{ORIGIN}/.well-known/oauth-authorization-server/auth/v1"
        with patch.object(oauth, "_read_metadata", return_value=metadata()) as reader:
            with patch.object(sys, "argv", ["oauth-readiness", ISSUER]):
                output = io.StringIO()
                with redirect_stdout(output):
                    self.assertEqual(oauth.main(), 0)
        reader.assert_called_once_with(url)
        self.assertIn("DCR advertised", output.getvalue())
        self.assertIn("not exercised", output.getvalue())

    def test_cli_rejects_a_different_supabase_project(self):
        legacy = "https://eobcxuyvhkvdmkbaihwh.supabase.co/auth/v1"
        with patch.object(sys, "argv", ["oauth-readiness", legacy]):
            with self.assertRaisesRegex(SystemExit, "differs from the canonical"):
                oauth.main()

    def test_canonical_issuer_matches_committed_foundation(self):
        self.assertEqual(oauth._canonical_project_issuer(), ISSUER)

    def test_cli_disallows_foreign_discovery_url(self):
        with patch.object(sys, "argv", ["oauth-readiness", ISSUER, "https://evil.invalid/.well-known/oauth"]):
            with self.assertRaisesRegex(SystemExit, "must match the canonical issuer"):
                oauth.main()


if __name__ == "__main__":
    unittest.main()
