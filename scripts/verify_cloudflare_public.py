from __future__ import annotations

import argparse
import os

import httpx


def run(base_url: str) -> None:
    base_url = base_url.rstrip("/")
    with httpx.Client(timeout=httpx.Timeout(20.0), follow_redirects=False) as client:
        health = client.get(f"{base_url}/health")
        health.raise_for_status()
        body = health.json()
        if body.get("service") != "ordax-control-plane-v3":
            raise RuntimeError("unexpected service health")
        if body.get("product_auth_configured") is not True:
            raise RuntimeError("product authentication is not configured")

        resource = client.get(f"{base_url}/.well-known/oauth-protected-resource")
        resource.raise_for_status()
        metadata = resource.json()
        scopes = metadata.get("scopes_supported")
        if not isinstance(scopes, list) or not {"openid", "email", "offline_access"}.issubset(scopes):
            raise RuntimeError("protected-resource scopes are incomplete")
        servers = metadata.get("authorization_servers")
        if not isinstance(servers, list) or len(servers) != 1:
            raise RuntimeError("protected-resource authorization server is invalid")
        issuer = str(servers[0]).rstrip("/")

        discovery = client.get(f"{issuer}/.well-known/openid-configuration")
        discovery.raise_for_status()
        oidc = discovery.json()
        if oidc.get("issuer") != issuer:
            raise RuntimeError("OIDC issuer mismatch")
        methods = oidc.get("code_challenge_methods_supported")
        if not isinstance(methods, list) or "S256" not in methods:
            raise RuntimeError("OIDC provider does not advertise PKCE S256")
        endpoint = oidc.get("userinfo_endpoint")
        if not isinstance(endpoint, str) or not endpoint.startswith("https://"):
            raise RuntimeError("OIDC userinfo endpoint is invalid")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--base-url",
        default=os.environ.get(
            "ORDAX_E2E_CONTROL_PLANE_URL",
            "https://ordax-control-plane-v3.ordax-ac1ca1b50d09.workers.dev",
        ),
    )
    args = parser.parse_args()
    run(args.base_url)
    print("cloudflare-v3 public verification OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
