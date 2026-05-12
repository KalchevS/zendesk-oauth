# zendesk-oauth-token

> Cross-platform CLI tool to create, manage, and rotate OAuth access tokens for the Zendesk API.

Works with any Zendesk integration that needs OAuth tokens — MCP servers, custom apps, scripts, CI/CD pipelines, or anything that calls the Zendesk API.

**Zero dependencies** — runs on Python 3.6+ standard library only. Works on macOS, Windows, and Linux.

---

## Features

- **Quick Token** — generate an OAuth token using Client ID + Secret (no browser)
- **Browser Login** — full OAuth authorization code flow with local callback server
- **Auto-refresh** — tokens include refresh credentials for automatic renewal
- **Browser result page** — after Browser Login, shows a styled page with copy-to-clipboard
- **Ready-to-use output** — prints the `.env` block you need for your Zendesk integration
- **Admin tools** — list all tokens, inspect details, revoke (requires admin role)
- **Config persistence** — remembers your subdomain/credentials between runs
- **`.env` file support** — reads credentials from `.env` so you never type them twice

---

## Prerequisites

| Requirement | Details |
|-------------|---------|
| Python | 3.6 or higher ([download](https://www.python.org/downloads/)) |
| Zendesk OAuth client | Created in Admin Center → Apps and integrations → APIs → OAuth clients |
| Client ID & Secret | Shown when you create the OAuth client |

> **Important:** Set your OAuth client type to **Confidential** for the Quick Token flow to work.

---

## Installation

```bash
git clone https://github.com/KalchevS/zendesk-oauth.git
cd zendesk-oauth
cp .env.example .env
# Edit .env with your values
```

No `pip install` needed — the script uses only Python's standard library.

---

## Quick Start

```bash
python zendesk-oauth-token.py
```

```
╔══════════════════════════════════════════════╗
║     Zendesk OAuth Token Creator             ║
╚══════════════════════════════════════════════╝

  1) Quick Token        (ID + Secret only, no browser)
  2) Browser Login      (opens browser, you approve access)
  3) Refresh Token      (renew an expired token)
  4) Exit
```

Pick option 1, enter your details (or let it read from `.env`), and you'll get:

```
══════════════════════════════════════════════════
  ✓ TOKEN CREATED SUCCESSFULLY
══════════════════════════════════════════════════

  Your access token:

  a1b2c3d4e5f6...

  Scope:         read write
  Expires In:    172800 seconds

  Your refresh token:

  x7y8z9...

  ┌─────────────────────────────────────────────────┐
  │  For zendesk-mcp server, add to your .env:      │
  └─────────────────────────────────────────────────┘

  ZD_SUBDOMAIN=mycompany
  ZD_OAUTH_ACCESS_TOKEN=a1b2c3d4e5f6...
  ZD_OAUTH_REFRESH_TOKEN=x7y8z9...
  ZD_OAUTH_CLIENT_ID=my_client
  ZD_OAUTH_CLIENT_SECRET=secret123
```

---

## Configuration

### `.env` file

```bash
cp .env.example .env
```

```env
# Required for token creation
ZENDESK_SUBDOMAIN=mycompany
ZENDESK_CLIENT_ID=your_client_id_here
ZENDESK_CLIENT_SECRET=your_client_secret_here
ZENDESK_SCOPE=read write
# ZENDESK_REDIRECT_URI=http://localhost:8080/oauth/callback

# Required for admin commands (list/revoke)
ZENDESK_EMAIL=admin@example.com
ZENDESK_API_TOKEN=your_api_token_here
```

### Priority order

The script resolves values in this order (first match wins):

1. Command-line flags (`--subdomain`, `--client-id`, etc.)
2. `.env` file in the current directory (or custom path via `--env-file`)
3. Saved config at `~/.zendesk-oauth-config.json` (auto-saved after first run)
4. Interactive prompt

### Custom `.env` path

```bash
python zendesk-oauth-token.py client-creds --env-file ~/projects/myapp/.env
```

---

## Usage

### Interactive mode (recommended)

```bash
python zendesk-oauth-token.py              # User menu
python zendesk-oauth-token.py --admin      # Admin menu (list/revoke)
```

### CLI subcommands

| Command | Description |
|---------|-------------|
| `client-creds` | Quick Token — no browser, uses ID + Secret |
| `auth-code` | Browser Login — opens browser for approval |
| `refresh` | Refresh Token — renew an expired token |
| `list` | List all tokens in account (admin) |
| `revoke TOKEN_ID` | Revoke a specific token (admin) |

### Examples

```bash
# Quick token with all values from .env
python zendesk-oauth-token.py client-creds

# Fully non-interactive (for CI/scripts)
python zendesk-oauth-token.py client-creds \
  --subdomain mycompany \
  --client-id my_client \
  --client-secret my_secret

# Browser login
python zendesk-oauth-token.py auth-code

# Refresh an expired token
python zendesk-oauth-token.py refresh

# List all tokens (admin)
python zendesk-oauth-token.py list --all

# Revoke a token (admin)
python zendesk-oauth-token.py revoke 12345678
```

---

## Token Creation Methods

### 1. Quick Token (`client-creds`)

Best for: automated setups, CI/CD, backend services.

- Uses OAuth 2.0 Client Credentials grant
- No browser interaction needed
- Requires OAuth client to be **Confidential** type
- Token is associated with the OAuth client creator

### 2. Browser Login (`auth-code`)

Best for: user-specific access, first-time setup.

- Opens browser → user logs in → approves access
- Script runs a local server to capture the callback
- After token exchange, browser shows a result page with:
  - Token values (styled, easy to read)
  - Copy-to-clipboard `.env` block
- Works with any redirect URI configured in your OAuth client

### 3. Refresh Token (`refresh`)

Best for: manual token renewal (most Zendesk MCP servers do this automatically).

- Exchanges a refresh token for a new access + refresh token pair
- No browser needed
- Reads the saved refresh token from `~/.zendesk-token` if available

---

## Using with Zendesk MCP Servers

Most Zendesk MCP servers authenticate via OAuth Bearer tokens. After creating a token with this script, configure your MCP server's `.env` with the output values:

```env
# Common environment variable names used by Zendesk MCP servers:
ZENDESK_SUBDOMAIN=mycompany
ZENDESK_OAUTH_TOKEN=your_access_token

# If your MCP server supports auto-refresh (recommended):
ZENDESK_REFRESH_TOKEN=your_refresh_token
ZENDESK_CLIENT_ID=your_client_id
ZENDESK_CLIENT_SECRET=your_client_secret
```

> **Note:** Variable names may differ between MCP server implementations. Check your server's documentation for the exact names. The script outputs all the values you need — just map them to the right variable names.

### Using with any Zendesk API integration

The OAuth token works with any tool that calls the Zendesk API:

```bash
# curl
curl https://mycompany.zendesk.com/api/v2/users/me.json \
  -H "Authorization: Bearer YOUR_ACCESS_TOKEN"

# Python
headers = {"Authorization": "Bearer YOUR_ACCESS_TOKEN"}

# JavaScript
headers: { "Authorization": "Bearer YOUR_ACCESS_TOKEN" }
```

---

## Token Expiration

| Token | Lifetime | Renewal |
|-------|----------|---------|
| Access token | 2 days (max allowed by Zendesk) | Use refresh token to renew |
| Refresh token | 30 days | Resets every time it's used |

**In practice:** As long as the token is refreshed at least once every 30 days (most MCP servers do this automatically), access renews indefinitely. If unused for 30+ days, run this script again.

> Zendesk deprecated password-based API auth in January 2026. OAuth tokens are now the recommended authentication method. See [Zendesk docs](https://developer.zendesk.com/documentation/api-basics/authentication/refresh-token/).

---

## Admin Commands

Requires Zendesk admin role + API token (from Admin Center → APIs → API tokens).

```bash
python zendesk-oauth-token.py --admin
```

```
  1) List Tokens        (view all tokens in account)
  2) Revoke Token       (delete a token)
  3) Exit
```

### List tokens

Shows all tokens with:
- Token ID and value (truncated for security)
- OAuth client name (fetched dynamically from the API)
- User name (resolved from user ID)
- Scopes, creation date, expiration, last used

Interactive actions after listing:
- `s` — show full details of a token
- `r` — revoke a token
- `q` — quit

### Filter by client

When listing interactively, the script fetches all OAuth clients and lets you pick:

```
  Show tokens for:
    0) All tokens in account
    1) My App ← yours
    2) Third Party Integration

  Choice [0-2]:
```

---

## File Structure

```
zendesk-oauth/
├── zendesk-oauth-token.py   # Main script (single file, no dependencies)
├── .env.example             # Template for credentials
├── .gitignore               # Excludes .env from version control
└── README.md                # This file
```

### Saved files

| File | Location | Purpose |
|------|----------|---------|
| `.zendesk-oauth-config.json` | `~/` | Saved credentials (reused between runs) |
| `.zendesk-token` | `~/` | Last created token (JSON) |

Both files are `chmod 600` on macOS/Linux (owner-only access).

---

## Security

- Credentials are never logged or printed beyond what's needed
- `.env` is gitignored — secrets stay local
- Saved config files use restricted permissions (600)
- Token values in admin list view are truncated (Zendesk API limitation)
- The local callback server only handles one request then shuts down
- No data is sent to any third party — all communication is directly with your Zendesk instance
- Store tokens in environment variables, not in code ([Zendesk recommendation](https://support.zendesk.com/hc/en-us/articles/4408882184986))

---

## Troubleshooting

### "redirect_uri mismatch" error

The redirect URI in the script must **exactly match** what's configured in your OAuth client in Admin Center. Check for:
- `localhost` vs `127.0.0.1`
- Trailing slash differences
- Port mismatch

Set it in your `.env`:
```env
ZENDESK_REDIRECT_URI=http://localhost:8080/oauth/callback
```

### "invalid_client" or "unauthorized_client" error

Your OAuth client must be set to **Confidential** type for the Quick Token (client credentials) flow.

### Token expires too quickly

The script requests the maximum allowed lifetime (2 days / 172800 seconds). If you're getting shorter expiry, it's enforced by your Zendesk account settings. Use the refresh token flow to renew.

### Admin commands return 403

The `list` and `revoke` commands require:
- Zendesk **admin** role
- An **API token** (not OAuth token) — from Admin Center → APIs → API tokens
- Set via `ZENDESK_EMAIL` and `ZENDESK_API_TOKEN` in `.env`

---

## License

MIT
