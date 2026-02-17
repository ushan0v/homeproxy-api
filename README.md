# HomeProxy API

`HomeProxy API` is a lightweight OpenWrt service for fast, batch route decisions based on your **real HomeProxy/sing-box runtime config**.

It answers: for each domain, would routing go to `proxy`, `direct`, or `block`, and by which rule.

## What It Does

- Runs local HTTP API on router (`/check`, `/match`, `/stats`, `/healthz`)
- Uses current HomeProxy-generated sing-box config (`/var/run/homeproxy/sing-box-c.json` by default)
- Supports batch checks (5-20+ domains per request)
- Returns:
  - class: `proxy` / `direct` / `block`
  - outbound display name (not only system tag)
  - matched rule index + rule name
- Supports two runtime modes:
  - `default`: in-memory cache (faster responses)
  - `eco`: cold-run per request (lower RAM usage)
- Loads only rule-sets that are actually used in active routing rules
- Supports rule-sets from:
  - `remote` (from HomeProxy `cache.db`)
  - `local` (from configured file path)
- Integrates with LuCI page (`Services -> HomeProxy API`)
- Can force-enable sing-box `clash_api` with empty secret (tokenless) on configurable port

## API Endpoints

### `POST /check`

Batch route resolution (recommended).

Request:

```json
{
  "domains": ["google.com", "youtube.com", "cdn.example.org"],
  "inbound": "redirect-in",
  "network": "tcp",
  "port": 443
}
```

Response shape:

```json
{
  "mode": "default",
  "results": [
    {
      "input": "google.com",
      "normalized": "google.com",
      "inputType": "domain",
      "class": "direct",
      "outbound": "direct",
      "outboundTag": "direct",
      "matched": true,
      "ruleIndex": 4,
      "ruleName": "my-direct-rule",
      "actionType": "route"
    }
  ]
}
```

### `GET /check`

Simple query mode:

```sh
curl "http://192.168.1.1:7878/check?q=google.com,youtube.com"
```

### `GET /match`

Shows which rule-set tags contain a domain/IP:

```sh
curl "http://192.168.1.1:7878/match?q=google.com"
```

### `GET /stats`

Service/runtime stats:

```sh
curl "http://192.168.1.1:7878/stats"
```

### `GET /healthz`

Health check:

```sh
curl "http://192.168.1.1:7878/healthz"
```

## LuCI UI

Menu: `Services -> HomeProxy API`

Settings:

- `Enable service`
- `Enable autostart`
- `Working mode` (`default` / `eco`)
- `HomeProxy API port` (default `7878`)
- `Clash API port` (default `9090`)
- `CORS allow-origin`

Tools:

- `Logs`
- `Uninstall` (removes service + LuCI files)

## Installation (OpenWrt)

### Quick install from GitHub

```sh
wget -O - https://raw.githubusercontent.com/ushan0v/homeproxy-api/main/install.sh | sh
```

Or:

```sh
curl -fsSL https://raw.githubusercontent.com/ushan0v/homeproxy-api/main/install.sh | sh
```

### Installer behavior

`install.sh`:

- detects device architecture
- picks matching prebuilt binary from `dist/`
- checks dependencies:
  - HomeProxy installed (`/etc/init.d/homeproxy`)
  - sing-box installed (`/usr/bin/sing-box` or in `PATH`)
- installs service + LuCI files
- enables service + autostart
- enables `clash_api` with:
  - `external_controller=0.0.0.0:<clash_api_port>`
  - empty secret
  - mode `Rule`

Environment overrides (optional):

- `HPA_REPO_OWNER`
- `HPA_REPO_NAME`
- `HPA_REPO_REF`
- `HPA_BASE_URL`

Example:

```sh
HPA_REPO_OWNER=myfork HPA_REPO_NAME=homeproxy-api HPA_REPO_REF=dev sh install.sh
```

## Cross-Compilation

Build all common Linux targets:

```sh
./scripts/build-release.sh
```

Builds are saved to `dist/`.

Included targets:

- `amd64`
- `386`
- `arm64`
- `armv7`
- `armv6`
- `armv5`
- `mips-softfloat`
- `mips-hardfloat`
- `mipsle-softfloat`
- `mipsle-hardfloat`
- `mips64`
- `mips64le`
- `riscv64`

## Security Notes

- If API is reachable outside LAN, set restrictive firewall rules.
- `clash_api` is configured without token by design for local tooling speed.
- Keep router management UI/API on trusted networks only.

## Service Files (on router)

- Binary: `/usr/bin/homeproxy-api`
- Init: `/etc/init.d/homeproxy-api`
- Config: `/etc/config/homeproxy-api`
- LuCI view: `/www/luci-static/resources/view/services/homeproxy-api.js`
- Menu: `/usr/share/luci/menu.d/luci-app-homeproxy-api.json`
- ACL: `/usr/share/rpcd/acl.d/luci-app-homeproxy-api.json`

## Development

Build local binary:

```sh
go build -o homeproxy-api .
```

Run directly:

```sh
./homeproxy-api -listen 0.0.0.0:7878 -config /var/run/homeproxy/sing-box-c.json -db /var/run/homeproxy/cache.db -mode default
```
