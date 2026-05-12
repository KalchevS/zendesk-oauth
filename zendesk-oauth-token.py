#!/usr/bin/env python3
"""
Zendesk OAuth Token Creator (Cross-platform)
Works on Windows, macOS, and Linux. No external dependencies.

This script helps users generate OAuth access tokens for the Zendesk API,
primarily for use with the zendesk-mcp server (https://github.com/KalchevS/zendesk-mcp).

Tokens are created via standard OAuth 2.0 flows and auto-refresh when used
with the MCP server, so users don't need to manually rotate credentials.

Supports:
  1. Quick Token — Client Credentials flow (no browser)
  2. Browser Login — Authorization Code flow (opens browser)
  3. Refresh Token — renew an expired access token
  4. List Tokens — view all tokens in account (admin)
  5. Revoke Token — delete a token (admin)

Usage:
    python get-token.py                          # Interactive menu
    python get-token.py --admin                  # Admin menu (list/revoke)
    python get-token.py client-creds             # Quick token
    python get-token.py auth-code                # Browser login
    python get-token.py refresh                  # Refresh token
    python get-token.py list                     # List all tokens (admin)
    python get-token.py revoke TOKEN_ID          # Revoke a token (admin)
"""

# ─── Standard library imports (no pip install needed) ─────────────────────────

import argparse          # CLI argument parsing
import base64            # Basic auth header encoding
import getpass           # Hidden password/secret input
import json              # JSON parsing for API responses
import os                # File system operations
import platform          # OS detection for file permissions
import sys               # Exit codes and stderr
import webbrowser        # Open browser for OAuth approval
from http.server import HTTPServer, BaseHTTPRequestHandler  # Local callback server
from urllib.parse import urlparse, parse_qs                 # URL parsing
import urllib.request    # HTTP requests (no requests/httpx needed)
import urllib.error      # HTTP error handling


# ─── Config persistence ───────────────────────────────────────────────────────
# The script saves credentials to disk so users don't re-enter them every time.
# Priority order: CLI flags > .env file > saved JSON config > interactive prompt.
# All saved files use chmod 600 on Unix to protect secrets.

CONFIG_FILE = os.path.join(os.path.expanduser("~"), ".zendesk-oauth-config.json")  # Saved credentials
TOKEN_FILE = os.path.join(os.path.expanduser("~"), ".zendesk-token")               # Last created token
ENV_FILE = os.path.join(os.getcwd(), ".env")                                       # Project .env file


def load_env_file(path=None):
    """Parse a .env file into a dict. Handles KEY=VALUE, quotes, and comments."""
    env_path = path or ENV_FILE
    env = {}
    if not os.path.exists(env_path):
        return env
    with open(env_path, "r") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            # Strip surrounding quotes
            if len(value) >= 2 and value[0] == value[-1] and value[0] in ('"', "'"):
                value = value[1:-1]
            env[key] = value
    return env


def load_config():
    """Load config from .env file (priority) then fall back to saved JSON config."""
    config = {}

    # Load saved JSON config as base
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                config = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass

    # Override with .env file values if present
    env = load_env_file()
    env_mapping = {
        "ZENDESK_SUBDOMAIN": "subdomain",
        "ZENDESK_CLIENT_ID": "client_id",
        "ZENDESK_CLIENT_SECRET": "client_secret",
        "ZENDESK_SCOPE": "scope",
        "ZENDESK_REDIRECT_URI": "redirect_uri",
        "ZENDESK_EMAIL": "email",
        "ZENDESK_API_TOKEN": "api_token",
    }
    for env_key, config_key in env_mapping.items():
        if env_key in env and env[env_key]:
            config[config_key] = env[env_key]

    if env:
        print(f"  Loaded .env from: {ENV_FILE}")

    return config


def save_config(config):
    """Save config to disk with restricted permissions."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)
    # Restrict permissions on Unix-like systems
    if platform.system() != "Windows":
        os.chmod(CONFIG_FILE, 0o600)


def save_token(token_data, subdomain):
    """Save token to disk for easy reuse."""
    output = {
        "subdomain": subdomain,
        "access_token": token_data.get("access_token", ""),
        "token_type": token_data.get("token_type", "bearer"),
        "scope": token_data.get("scope", ""),
        "expires_in": token_data.get("expires_in"),
        "refresh_token": token_data.get("refresh_token"),
    }
    with open(TOKEN_FILE, "w") as f:
        json.dump(output, f, indent=2)
    if platform.system() != "Windows":
        os.chmod(TOKEN_FILE, 0o600)


# ─── Input helpers ────────────────────────────────────────────────────────────
# Utilities for cleaning user input and prompting for missing values.
# clean_subdomain() handles when users paste a full URL instead of just "mycompany".

def clean_subdomain(value):
    """Extract subdomain from full URL or plain input."""
    value = value.strip()
    if "zendesk.com" in value:
        # Handle https://mycompany.zendesk.com or mycompany.zendesk.com
        value = value.replace("https://", "").replace("http://", "")
        value = value.split(".zendesk.com")[0]
    return value


def prompt_value(label, current="", secret=False):
    """Prompt for a value, showing current default."""
    if secret:
        hint = "(saved)" if current else ""
        value = getpass.getpass(f"{label} [{hint}]: ") if current else getpass.getpass(f"{label}: ")
    else:
        if current:
            value = input(f"{label} [{current}]: ").strip()
        else:
            value = input(f"{label}: ").strip()
    return value or current


# ─── API call ─────────────────────────────────────────────────────────────────
# Core HTTP functions for the OAuth token endpoint (POST /oauth/tokens).
# request_token() handles all three grant types: client_credentials,
# authorization_code, and refresh_token.
# test_token() validates a token works by calling /api/v2/users/me.

def request_token(subdomain, payload):
    """POST to /oauth/tokens and return parsed response."""
    url = f"https://{subdomain}.zendesk.com/oauth/tokens"

    data = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err = json.loads(body)
            print(f"\n✗ Failed: {err.get('error', 'unknown')} - {err.get('error_description', body)}")
        except json.JSONDecodeError:
            print(f"\n✗ Failed (HTTP {e.code}): {body}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\n✗ Connection error: {e.reason}")
        sys.exit(1)


def test_token(subdomain, access_token):
    """Test the token against /api/v2/users/me.json."""
    url = f"https://{subdomain}.zendesk.com/api/v2/users/me.json"
    req = urllib.request.Request(url, headers={"Authorization": f"Bearer {access_token}"})

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            user = data.get("user", {})
            print(f"  ✓ Authenticated as: {user.get('name', '?')} ({user.get('email', '?')})")
            return True
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        print(f"  ✗ Token test failed (HTTP {e.code}): {body[:200]}")
        return False
    except urllib.error.URLError as e:
        print(f"  ✗ Connection error: {e.reason}")
        return False


# ─── Management API (list/show/revoke) ────────────────────────────────────────
# Admin-only endpoints that use Basic auth (email + API token) instead of OAuth.
# These let admins view all tokens in the account, inspect details, and revoke.
# The API token here is NOT the OAuth token — it's from Admin Center > APIs > API tokens.
#
# Key endpoints used:
#   GET  /api/v2/oauth/tokens.json       — list all tokens
#   GET  /api/v2/oauth/tokens/{id}.json  — show one token
#   DELETE /api/v2/oauth/tokens/{id}.json — revoke a token
#   GET  /api/v2/oauth/clients.json      — list OAuth clients (for name resolution)
#   GET  /api/v2/users/show_many.json    — resolve user IDs to names

def build_basic_auth_header(email, api_token):
    """Build Basic auth header using email/token:api_token."""
    credentials = f"{email}/token:{api_token}"
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("utf-8")
    return f"Basic {encoded}"


def api_request(subdomain, email, api_token, path, method="GET"):
    """Make an authenticated request to the Zendesk API."""
    url = f"https://{subdomain}.zendesk.com{path}"
    auth_header = build_basic_auth_header(email, api_token)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
        },
        method=method,
    )

    try:
        with urllib.request.urlopen(req) as resp:
            if resp.status == 204:
                return None
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        body = e.read().decode("utf-8")
        try:
            err = json.loads(body)
            print(f"\n✗ API error (HTTP {e.code}): {err.get('error', err.get('description', body))}")
        except json.JSONDecodeError:
            print(f"\n✗ API error (HTTP {e.code}): {body[:300]}")
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\n✗ Connection error: {e.reason}")
        sys.exit(1)


def resolve_user_names(subdomain, email, api_token, user_ids):
    """Fetch user names for a list of user IDs. Returns a dict of {id: name}."""
    if not user_ids:
        return {}

    # Deduplicate and remove None/empty values
    unique_ids = list(set(uid for uid in user_ids if uid))
    if not unique_ids:
        return {}

    # Zendesk supports fetching multiple users: GET /api/v2/users/show_many.json?ids=1,2,3
    ids_param = ",".join(str(uid) for uid in unique_ids)
    url = f"https://{subdomain}.zendesk.com/api/v2/users/show_many.json?ids={ids_param}"
    auth_header = build_basic_auth_header(email, api_token)

    req = urllib.request.Request(
        url,
        headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
        },
        method="GET",
    )

    try:
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            users = data.get("users", [])
            return {u["id"]: u.get("name", u.get("email", f"User {u['id']}")) for u in users}
    except Exception:
        return {}


def resolve_client_names(subdomain, email, api_token, client_ids=None):
    """Fetch OAuth client names. Returns a dict of {id: name} with both int and str keys.
    
    First tries listing all clients. For any IDs not found in the list,
    falls back to fetching them individually (handles global/external clients).
    """
    auth_header = build_basic_auth_header(email, api_token)
    result = {}

    # Step 1: Fetch all local clients via list endpoint
    try:
        url = f"https://{subdomain}.zendesk.com/api/v2/oauth/clients.json"
        req = urllib.request.Request(url, headers={
            "Authorization": auth_header,
            "Content-Type": "application/json",
        }, method="GET")
        with urllib.request.urlopen(req) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            for c in data.get("clients", []):
                name = c.get("name") or c.get("identifier") or f"Client {c['id']}"
                result[c["id"]] = name
                result[str(c["id"])] = name
    except Exception:
        pass

    # Step 2: For any client_ids not found, try fetching individually
    if client_ids:
        missing = [cid for cid in client_ids if cid and cid not in result and str(cid) not in result]
        for cid in set(missing):
            try:
                url = f"https://{subdomain}.zendesk.com/api/v2/oauth/clients/{cid}.json"
                req = urllib.request.Request(url, headers={
                    "Authorization": auth_header,
                    "Content-Type": "application/json",
                }, method="GET")
                with urllib.request.urlopen(req) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    c = data.get("client", {})
                    name = c.get("name") or c.get("identifier") or f"Client {cid}"
                    result[cid] = name
                    result[str(cid)] = name
            except urllib.error.HTTPError as e:
                # Global clients may not be accessible — show as "External App (ID: X)"
                result[cid] = f"External App (ID: {cid})"
                result[str(cid)] = f"External App (ID: {cid})"
            except Exception:
                result[cid] = f"Unknown (ID: {cid})"
                result[str(cid)] = f"Unknown (ID: {cid})"

    return result


def flow_list_tokens(args):
    """List all OAuth tokens in the account."""
    print("\n=== List OAuth Tokens ===")
    print("  Requires admin email + API token (not OAuth token).\n")

    config = load_config()

    subdomain = clean_subdomain(args.subdomain or prompt_value("Zendesk subdomain", config.get("subdomain", "")))
    email = args.email or prompt_value("Admin email", config.get("email", ""))
    api_token = args.api_token or prompt_value("API token", config.get("api_token", ""), secret=True)

    if not all([subdomain, email, api_token]):
        print("✗ Subdomain, email, and API token are required.")
        sys.exit(1)

    # Save for reuse
    config.update({"subdomain": subdomain, "email": email, "api_token": api_token})
    save_config(config)

    # If running interactively (no CLI flags), ask whether to filter by current client
    filter_client_id = getattr(args, "filter_client_id", None)
    show_all = getattr(args, "all", False)

    if not filter_client_id and not show_all:
        # Fetch all OAuth clients dynamically and let user pick
        auth_header = build_basic_auth_header(email, api_token)
        clients_list = []
        try:
            url = f"https://{subdomain}.zendesk.com/api/v2/oauth/clients.json"
            req = urllib.request.Request(url, headers={
                "Authorization": auth_header,
                "Content-Type": "application/json",
            }, method="GET")
            with urllib.request.urlopen(req) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                clients_list = data.get("clients", [])
        except Exception:
            pass

        saved_client_id = config.get("client_id", "")

        if clients_list:
            print("  Show tokens for:")
            print("    0) All tokens in account")
            for idx, c in enumerate(clients_list):
                name = c.get("name") or c.get("identifier") or "?"
                marker = " ← yours" if c.get("identifier") == saved_client_id else ""
                print(f"    {idx+1}) {name}{marker}")
            print("")
            try:
                scope_choice = input(f"  Choice [0-{len(clients_list)}]: ").strip()
            except (EOFError, KeyboardInterrupt):
                scope_choice = "0"

            if scope_choice.isdigit() and 1 <= int(scope_choice) <= len(clients_list):
                selected_client = clients_list[int(scope_choice) - 1]
                filter_client_id = selected_client["id"]
                show_all = True
                print(f"  Filtering by: {selected_client.get('name')} (ID: {filter_client_id})\n")
            else:
                show_all = True
        else:
            show_all = True

    # Build query params
    path = "/api/v2/oauth/tokens.json"
    params = []
    if show_all:
        params.append("all=true")
    if filter_client_id:
        params.append(f"client_id={filter_client_id}")
    if params:
        path += "?" + "&".join(params)

    print("  Fetching tokens...\n")
    data = api_request(subdomain, email, api_token, path)

    tokens = data.get("tokens", [])
    if not tokens:
        print("  No OAuth tokens found.")
        return

    # Resolve user IDs to human-readable names
    user_ids = [t.get("user_id") for t in tokens]
    user_names = resolve_user_names(subdomain, email, api_token, user_ids)

    # Resolve client IDs to client names
    client_ids = [t.get("client_id") for t in tokens]
    client_names = resolve_client_names(subdomain, email, api_token, client_ids)

    print(f"  Found {len(tokens)} token(s):\n")

    for i, t in enumerate(tokens):
        token_id = t.get("id", "—")
        token_val = t.get("token", "—")
        scopes = ", ".join(t.get("scopes", [])) or "—"
        created = t.get("created_at", "—")
        expires = t.get("expires_at") or "never"
        used_at = t.get("used_at") or "never"
        uid = t.get("user_id")
        user_display = user_names.get(uid, str(uid or "—"))
        cid = t.get("client_id")
        client_display = client_names.get(cid) or client_names.get(str(cid)) or str(cid or "—")

        print(f"  {i+1}) [{token_id}] \033[1m{token_val}\033[0m")
        print(f"       Client:  {client_display}")
        print(f"       User:    {user_display}")
        print(f"       Scope:   {scopes}")
        print(f"       Created: {created}")
        print(f"       Expires: {expires}")
        print(f"       Used:    {used_at}")
        if i < len(tokens) - 1:
            print("")

    # Number each token for easy selection
    print("")
    print("  ─────────────────────────────────────")
    print("  Actions:")
    print("    s) Show details of a token")
    print("    r) Revoke a token")
    print("    q) Back / quit")
    print("")

    try:
        action = input("  Action [s/r/q]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print("")
        return

    if action in ("s", "r"):
        pick = input(f"  Enter token number (1-{len(tokens)}): ").strip()
        if not pick.isdigit() or not (1 <= int(pick) <= len(tokens)):
            print("  ✗ Invalid selection.")
            return
        selected = tokens[int(pick) - 1]

        if action == "s":
            _show_token_details(selected, subdomain, email, api_token)
        elif action == "r":
            tid = selected.get("id")
            token_preview = selected.get("token", "?")
            uid = selected.get("user_id")
            uname = user_names.get(uid, str(uid or "?"))
            try:
                confirm = input(f"  Revoke [{tid}] {token_preview} (user: {uname})? (y/n) [n]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                confirm = "n"
            if confirm in ("y", "yes"):
                api_request(subdomain, email, api_token, f"/api/v2/oauth/tokens/{tid}.json", method="DELETE")
                print(f"\n  ✓ Token {tid} revoked.\n")
            else:
                print("  Cancelled.")


def _show_token_details(t, subdomain, email, api_token):
    """Display full details of a single token dict."""
    uid = t.get("user_id")
    user_names = resolve_user_names(subdomain, email, api_token, [uid]) if uid else {}
    user_display = user_names.get(uid, str(uid or "—"))

    cid = t.get("client_id")
    client_names = resolve_client_names(subdomain, email, api_token, [cid]) if cid else {}
    client_display = client_names.get(cid) or client_names.get(str(cid)) or str(cid or "—")

    print("\n" + "─" * 50)
    print(f"  ID:                       {t.get('id', '—')}")
    print(f"  Token (truncated):        \033[1m{t.get('token', '—')}\033[0m")
    print(f"  Client:                   {client_display} (ID: {cid})")
    print(f"  Scopes:                   {', '.join(t.get('scopes', []))}")
    print(f"  User:                     {user_display} (ID: {uid})")
    print(f"  Created:                  {t.get('created_at', '—')}")
    print(f"  Expires:                  {t.get('expires_at', 'never')}")
    print(f"  Refresh Token:            {t.get('refresh_token', '—')}")
    print(f"  Refresh Token Expires:    {t.get('refresh_token_expires_at', 'never')}")
    print(f"  Last Used:                {t.get('used_at', 'never')}")
    print("─" * 50)
    print("")


def flow_revoke_token(args):
    """Revoke an OAuth token."""
    print("\n=== Revoke OAuth Token ===\n")

    config = load_config()

    subdomain = clean_subdomain(args.subdomain or prompt_value("Zendesk subdomain", config.get("subdomain", "")))
    email = args.email or prompt_value("Admin email", config.get("email", ""))
    api_token = args.api_token or prompt_value("API token", config.get("api_token", ""), secret=True)
    token_id = args.token_id or input("  Token ID to revoke: ").strip()

    if not all([subdomain, email, api_token, token_id]):
        print("✗ All values are required.")
        sys.exit(1)

    config.update({"subdomain": subdomain, "email": email, "api_token": api_token})
    save_config(config)

    # Confirm
    if token_id.lower() == "current":
        path = "/api/v2/oauth/tokens/current.json"
        desc = "the CURRENT token"
    else:
        path = f"/api/v2/oauth/tokens/{token_id}.json"
        desc = f"token ID {token_id}"

    try:
        confirm = input(f"  Are you sure you want to revoke {desc}? (y/n) [n]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        confirm = "n"

    if confirm not in ("y", "yes"):
        print("  Cancelled.")
        return

    api_request(subdomain, email, api_token, path, method="DELETE")
    print(f"\n  ✓ Token {token_id} has been revoked.\n")


# ─── Display results ──────────────────────────────────────────────────────────
# After a token is created, display_result() shows:
#   - The access token (bold green) and refresh token (bold yellow)
#   - The ready-to-paste .env block for the zendesk-mcp server
#   - A curl example for manual testing
#   - Option to test the token immediately

def display_result(data, subdomain):
    """Display and save the token response."""
    token = data.get("access_token", "")
    expires = data.get("expires_in", "N/A")
    scope = data.get("scope", "N/A")
    refresh = data.get("refresh_token")

    print("\n" + "═" * 50)
    print("  ✓ TOKEN CREATED SUCCESSFULLY")
    print("═" * 50)
    print("")
    print("  Your access token:")
    print("")
    print(f"  \033[1;32m{token}\033[0m")
    print("")
    print(f"  Scope:         {scope}")
    print(f"  Expires In:    {expires} seconds")
    if refresh:
        print("")
        print("  Your refresh token:")
        print("")
        print(f"  \033[1;33m{refresh}\033[0m")
    print("")
    print("─" * 50)

    save_token(data, subdomain)
    print(f"  Saved to: {TOKEN_FILE}")

    # Show MCP server configuration
    print(f"\n  ┌─────────────────────────────────────────────────┐")
    print(f"  │  For zendesk-mcp server, add to your .env:      │")
    print(f"  └─────────────────────────────────────────────────┘")
    print(f"")
    print(f"  ZD_SUBDOMAIN={subdomain}")
    print(f"  ZD_OAUTH_ACCESS_TOKEN={token}")
    if refresh:
        print(f"  ZD_OAUTH_REFRESH_TOKEN={refresh}")
    # Read saved config for client_id/secret without re-printing "Loaded .env"
    _cfg = {}
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, "r") as f:
                _cfg = json.load(f)
        except (json.JSONDecodeError, IOError):
            pass
    if _cfg.get("client_id"):
        print(f"  ZD_OAUTH_CLIENT_ID={_cfg['client_id']}")
    if _cfg.get("client_secret"):
        print(f"  ZD_OAUTH_CLIENT_SECRET={_cfg['client_secret']}")

    print(f"\n  Usage with curl:")
    print(f"    curl https://{subdomain}.zendesk.com/api/v2/users/me.json \\")
    print(f'      -H "Authorization: Bearer {token}"')

    # Offer to test
    print("")
    try:
        answer = input("  Test the token now? (y/n) [y]: ").strip().lower()
    except (EOFError, KeyboardInterrupt):
        answer = "n"
    if answer in ("", "y", "yes"):
        test_token(subdomain, token)

    print("")


# ─── OAuth redirect server ────────────────────────────────────────────────────
# For the Browser Login (authorization code) flow, we need a local HTTP server
# to capture the OAuth callback from Zendesk after the user approves access.
#
# Flow:
#   1. User clicks "approve" in browser
#   2. Zendesk redirects to http://localhost:PORT/oauth/callback?code=XXX
#   3. Our server captures the code and shows a "processing" page
#   4. Script exchanges the code for tokens
#   5. Browser auto-refreshes to /result showing the token + MCP config
#
# The server handles any path (not just /oauth/callback) so it works
# regardless of what redirect URI is configured in Admin Center.

class _OAuthCallbackHandler(BaseHTTPRequestHandler):
    """Handles the OAuth redirect callback on any path."""
    auth_code = None
    token_result = None  # Will be set after token exchange

    def do_GET(self):
        parsed = urlparse(self.path)
        params = parse_qs(parsed.query)

        # Check if this is the result page request
        if parsed.path == "/result" and _OAuthCallbackHandler.token_result:
            self._serve_result_page()
            return

        code = params.get("code", [""])[0]

        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        # Show a "processing" page that auto-redirects to /result
        html = (
            "<html><head><meta http-equiv='refresh' content='3;url=/result'></head>"
            "<body style='font-family:sans-serif;text-align:center;padding:50px;'>"
            "<h2>&#10003; Authorization Received</h2>"
            "<p style='color:#666;'>Exchanging code for token... please wait.</p>"
            "<p style='font-size:24px;'>&#8987;</p>"
            "</body></html>"
        )
        self.wfile.write(html.encode())
        _OAuthCallbackHandler.auth_code = code

    def _serve_result_page(self):
        """Serve the token result page after exchange is complete."""
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.end_headers()

        r = _OAuthCallbackHandler.token_result
        token = r.get("access_token", "")
        refresh = r.get("refresh_token", "")
        scope = r.get("scope", "")
        expires = r.get("expires_in", "N/A")
        subdomain = r.get("_subdomain", "")
        client_id = r.get("_client_id", "")
        client_secret = r.get("_client_secret", "")

        # Build .env block for MCP server
        env_lines = f"ZD_SUBDOMAIN={subdomain}\nZD_OAUTH_ACCESS_TOKEN={token}"
        if refresh:
            env_lines += f"\nZD_OAUTH_REFRESH_TOKEN={refresh}"
        if client_id:
            env_lines += f"\nZD_OAUTH_CLIENT_ID={client_id}"
        if client_secret:
            env_lines += f"\nZD_OAUTH_CLIENT_SECRET={client_secret}"

        html = (
            "<html><head><style>"
            "body{font-family:system-ui,sans-serif;max-width:700px;margin:40px auto;padding:20px;background:#1a1a2e;color:#eee;}"
            "h2{color:#4ade80;}"
            ".token-box{background:#0d1117;border:1px solid #30363d;border-radius:8px;padding:16px;margin:16px 0;word-break:break-all;font-family:monospace;font-size:13px;}"
            ".label{color:#8b949e;font-size:12px;text-transform:uppercase;margin-bottom:4px;}"
            ".value{color:#58a6ff;font-weight:bold;font-size:15px;}"
            ".env-box{background:#0d1117;border:2px solid #4ade80;border-radius:8px;padding:16px;margin:16px 0;font-family:monospace;font-size:13px;white-space:pre-wrap;}"
            ".copy-btn{background:#238636;color:#fff;border:none;padding:8px 16px;border-radius:6px;cursor:pointer;font-size:13px;margin-top:8px;}"
            ".copy-btn:hover{background:#2ea043;}"
            ".info{color:#8b949e;font-size:13px;}"
            "</style></head><body>"
            "<h2>&#10003; Token Created Successfully</h2>"
            f"<div class='token-box'><div class='label'>Access Token</div><div class='value'>{token}</div></div>"
            f"<p class='info'>Scope: {scope} &nbsp;|&nbsp; Expires in: {expires}s</p>"
        )

        if refresh:
            html += f"<div class='token-box'><div class='label'>Refresh Token</div><div class='value' style='color:#facc15;'>{refresh}</div></div>"

        html += (
            "<h3 style='color:#4ade80;margin-top:32px;'>For zendesk-mcp server (.env):</h3>"
            f"<div class='env-box' id='env-block'>{env_lines}</div>"
            "<button class='copy-btn' onclick=\"navigator.clipboard.writeText(document.getElementById('env-block').innerText);this.textContent='Copied!'\">Copy to clipboard</button>"
            "<p class='info' style='margin-top:24px;'>You can close this window now.</p>"
            "</body></html>"
        )
        self.wfile.write(html.encode())

    def log_message(self, format, *args):
        pass  # Suppress logs


def wait_for_auth_code(port=8080, host="localhost", timeout=120):
    """Start a local server and wait for the OAuth callback."""
    server = HTTPServer((host, port), _OAuthCallbackHandler)
    server.timeout = timeout
    _OAuthCallbackHandler.auth_code = None
    _OAuthCallbackHandler.token_result = None

    print(f"  Listening on http://{host}:{port} ...")
    server.handle_request()  # Handle the callback request
    server.server_close()

    return _OAuthCallbackHandler.auth_code


def serve_result_page(port=8080, host="localhost", token_data=None, timeout=30):
    """Serve the token result page in the browser after exchange."""
    _OAuthCallbackHandler.token_result = token_data
    server = HTTPServer((host, port), _OAuthCallbackHandler)
    server.timeout = timeout
    server.handle_request()  # Handle the /result auto-redirect
    server.server_close()


# ─── Flows ────────────────────────────────────────────────────────────────────
# Each flow_* function implements one token creation method.
# All flows:
#   - Load config from .env / saved JSON
#   - Prompt for any missing values
#   - Save config for next time
#   - Request max token lifetime (172800s = 2 days)
#   - Display results with MCP server config
#
# Token expiration notes (Zendesk enforced limits):
#   - Access token: max 172800s (2 days), refreshed automatically by MCP server
#   - Refresh token: 30 days, resets each time it's used
#   - As long as MCP server is used once every 30 days, tokens renew forever

def flow_client_credentials(args):
    """Client Credentials flow — no user interaction needed."""
    print("\n=== Quick Token (ID + Secret) ===")
    print("  No browser needed. Uses your Client ID and Secret directly.\n")

    config = load_config()

    subdomain = clean_subdomain(args.subdomain or prompt_value("Zendesk subdomain", config.get("subdomain", "")))
    client_id = args.client_id or prompt_value("Client ID", config.get("client_id", ""))
    client_secret = args.client_secret or prompt_value("Client Secret", config.get("client_secret", ""), secret=True)
    scope = args.scope or config.get("scope", "read write")

    if not all([subdomain, client_id, client_secret]):
        print("✗ Subdomain, Client ID, and Client Secret are all required.")
        sys.exit(1)

    # Save config for next time
    save_config({"subdomain": subdomain, "client_id": client_id, "client_secret": client_secret, "scope": scope})

    # Always request max lifetime (2 days)
    expires_in = 172800

    payload = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "expires_in": expires_in,
    }

    print(f"\n  Requesting token (expires in {expires_in}s / 2 days)...")

    data = request_token(subdomain, payload)

    display_result(data, subdomain)


def flow_authorization_code(args):
    """Authorization Code flow — opens browser for user approval."""
    print("\n=== Browser Login ===")
    print("  Opens your browser to log in and approve access.\n")

    config = load_config()

    subdomain = clean_subdomain(args.subdomain or prompt_value("Zendesk subdomain", config.get("subdomain", "")))
    client_id = args.client_id or prompt_value("Client ID", config.get("client_id", ""))
    client_secret = args.client_secret or prompt_value("Client Secret", config.get("client_secret", ""), secret=True)
    redirect_uri = args.redirect_uri or prompt_value("Redirect URI", config.get("redirect_uri", "http://localhost:8080/oauth/callback"))
    scope = args.scope or config.get("scope", "read write")

    if not all([subdomain, client_id, client_secret]):
        print("✗ Subdomain, Client ID, and Client Secret are all required.")
        sys.exit(1)

    save_config({
        "subdomain": subdomain,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scope": scope,
    })

    # Build authorization URL
    encoded_scope = scope.replace(" ", "+")
    auth_url = (
        f"https://{subdomain}.zendesk.com/oauth/authorizations/new"
        f"?response_type=code"
        f"&redirect_uri={redirect_uri}"
        f"&client_id={client_id}"
        f"&scope={encoded_scope}"
    )

    print(f"\n  Authorization URL:\n  {auth_url}\n")

    # Determine host and port from redirect_uri for the local callback server
    try:
        parsed_uri = urlparse(redirect_uri)
        host = parsed_uri.hostname or "localhost"
        port = parsed_uri.port or 8080
    except Exception:
        host = "localhost"
        port = 8080

    # Open browser
    print("  Opening browser...")
    webbrowser.open(auth_url)

    # Wait for callback
    code = wait_for_auth_code(port=port, host=host)

    if not code:
        # Fallback: ask user to paste manually
        print("\n  Didn't receive callback automatically.")
        code = input("  Paste the authorization code here: ").strip()

    if not code:
        print("✗ No authorization code received.")
        sys.exit(1)

    print(f"\n  Received code: {code[:12]}...")
    print("  Exchanging for tokens...")

    data = request_token(subdomain, {
        "grant_type": "authorization_code",
        "code": code,
        "client_id": client_id,
        "client_secret": client_secret,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "expires_in": 172800,
    })

    # Serve result page in browser (attach metadata for the HTML template)
    data["_subdomain"] = subdomain
    data["_client_id"] = client_id
    data["_client_secret"] = client_secret
    try:
        serve_result_page(port=port, host=host, token_data=data)
    except Exception:
        pass  # Browser might not request /result, that's fine

    display_result(data, subdomain)


def flow_refresh_token(args):
    """Refresh Token flow — renew an expired access token."""
    print("\n=== Refresh Token ===")
    print("  Renew an expired token without logging in again.\n")

    config = load_config()

    subdomain = clean_subdomain(args.subdomain or prompt_value("Zendesk subdomain", config.get("subdomain", "")))
    client_id = args.client_id or prompt_value("Client ID", config.get("client_id", ""))
    client_secret = args.client_secret or prompt_value("Client Secret", config.get("client_secret", ""), secret=True)

    # Try to load refresh token from saved token file
    saved_refresh = ""
    if os.path.exists(TOKEN_FILE):
        try:
            with open(TOKEN_FILE, "r") as f:
                saved = json.load(f)
                saved_refresh = saved.get("refresh_token", "") or ""
        except (json.JSONDecodeError, IOError):
            pass

    refresh_token = args.refresh_token or prompt_value("Refresh token", saved_refresh)

    if not all([subdomain, client_id, client_secret, refresh_token]):
        print("✗ All values are required.")
        sys.exit(1)

    save_config({"subdomain": subdomain, "client_id": client_id, "client_secret": client_secret, "scope": config.get("scope", "read write")})

    print("\n  Refreshing token...")

    data = request_token(subdomain, {
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": client_id,
        "client_secret": client_secret,
        "expires_in": 172800,
    })

    display_result(data, subdomain)


# ─── Main ─────────────────────────────────────────────────────────────────────
# Entry point. Handles:
#   - CLI subcommands (client-creds, auth-code, refresh, list, revoke)
#   - Interactive menu (no args) with user-friendly option names
#   - --admin flag shows admin-only options (list/revoke)
#   - --env-file flag to specify a custom .env path

def main():
    parser = argparse.ArgumentParser(
        description="Zendesk OAuth Token Creator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python get-token.py                        Interactive menu
  python get-token.py --admin                Admin menu (list/revoke)
  python get-token.py client-creds           Quick token (no browser)
  python get-token.py auth-code              Browser login
  python get-token.py refresh                Refresh an expired token
  python get-token.py list --all             List all tokens (admin)
  python get-token.py revoke 12345           Revoke a token (admin)
  python get-token.py client-creds -s myco -i ID -c SECRET
  python get-token.py client-creds --env-file /path/to/.env
        """,
    )
    parser.add_argument("--env-file", "-e", default="", help="Path to .env file (default: .env in current directory)")
    parser.add_argument("--admin", action="store_true", help="Show admin options (list, revoke tokens)")

    subparsers = parser.add_subparsers(dest="flow")

    # Token creation flows
    for name, help_text in [
        ("client-creds", "Client Credentials flow (backend/daemon apps)"),
        ("auth-code", "Authorization Code flow (user-facing apps)"),
        ("refresh", "Refresh Token flow (renew expired token)"),
    ]:
        sub = subparsers.add_parser(name, help=help_text)
        sub.add_argument("--subdomain", "-s", default="", help="Zendesk subdomain")
        sub.add_argument("--client-id", "-i", default="", help="OAuth Client ID")
        sub.add_argument("--client-secret", "-c", default="", help="OAuth Client Secret")
        sub.add_argument("--scope", default="", help="Token scope (default: 'read write')")
        sub.add_argument("--env-file", "-e", default="", help="Path to .env file")
        if name == "auth-code":
            sub.add_argument("--redirect-uri", "-r", default="", help="Redirect URI")
        if name == "refresh":
            sub.add_argument("--refresh-token", "-t", default="", help="Refresh token")

    # Token management flows (list, show, revoke)
    sub_list = subparsers.add_parser("list", help="List all OAuth tokens (admin)")
    sub_list.add_argument("--subdomain", "-s", default="", help="Zendesk subdomain")
    sub_list.add_argument("--email", default="", help="Admin email address")
    sub_list.add_argument("--api-token", default="", help="Zendesk API token")
    sub_list.add_argument("--all", action="store_true", help="Show tokens for all users (admin only)")
    sub_list.add_argument("--filter-client-id", default=None, help="Filter by OAuth client ID")
    sub_list.add_argument("--env-file", "-e", default="", help="Path to .env file")

    sub_revoke = subparsers.add_parser("revoke", help="Revoke an OAuth token")
    sub_revoke.add_argument("token_id", nargs="?", default="", help="Token ID to revoke (or 'current')")
    sub_revoke.add_argument("--subdomain", "-s", default="", help="Zendesk subdomain")
    sub_revoke.add_argument("--email", default="", help="Admin email address")
    sub_revoke.add_argument("--api-token", default="", help="Zendesk API token")
    sub_revoke.add_argument("--env-file", "-e", default="", help="Path to .env file")

    args = parser.parse_args()

    # If a custom .env file is specified, override the default path
    env_file = getattr(args, "env_file", "")
    if env_file:
        global ENV_FILE
        ENV_FILE = os.path.abspath(env_file)

    if args.flow == "client-creds":
        flow_client_credentials(args)
    elif args.flow == "auth-code":
        flow_authorization_code(args)
    elif args.flow == "refresh":
        flow_refresh_token(args)
    elif args.flow == "list":
        if not hasattr(args, "all"):
            args.all = True
        if not hasattr(args, "filter_client_id"):
            args.filter_client_id = None
        flow_list_tokens(args)
    elif args.flow == "revoke":
        flow_revoke_token(args)
    else:
        # Interactive menu
        admin_mode = getattr(args, "admin", False)

        print("\n╔══════════════════════════════════════════════╗")
        print("║     Zendesk OAuth Token Creator             ║")
        print("╚══════════════════════════════════════════════╝\n")

        if admin_mode:
            print("  1) List Tokens        (view all tokens in account)")
            print("  2) Revoke Token       (delete a token)")
            print("  3) Exit\n")

            try:
                choice = input("  Choice [1-3]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("")
                sys.exit(0)

            class Args:
                subdomain = ""
                email = ""
                api_token = ""
                token_id = ""
                all = True
                filter_client_id = None

            a = Args()

            if choice == "1":
                flow_list_tokens(a)
            elif choice == "2":
                flow_revoke_token(a)
            else:
                sys.exit(0)
        else:
            print("  1) Quick Token        (ID + Secret only, no browser)")
            print("  2) Browser Login      (opens browser, you approve access)")
            print("  3) Refresh Token      (renew an expired token)")
            print("  4) Exit\n")

            try:
                choice = input("  Choice [1-4]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print("")
                sys.exit(0)

            class Args:
                subdomain = ""
                client_id = ""
                client_secret = ""
                scope = ""
                redirect_uri = ""
                refresh_token = ""

            a = Args()

            if choice == "1":
                flow_client_credentials(a)
            elif choice == "2":
                flow_authorization_code(a)
            elif choice == "3":
                flow_refresh_token(a)
            else:
                sys.exit(0)


if __name__ == "__main__":
    main()
