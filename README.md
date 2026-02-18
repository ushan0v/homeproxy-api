# HomeProxy API

`HomeProxy API` is a lightweight OpenWrt service that provides fast HTTP API access to:

- domain route checks (`proxy` / `direct` / `block`) using current HomeProxy + sing-box runtime
- HomeProxy routing rules read/update via UCI
- fast rules-only apply (hot reload) without full HomeProxy restart
- HomeProxy service control/status

## Features

- Batch route checks: `POST /check`
- Rule-set match lookup: `GET /match`
- Runtime stats: `GET /stats`
- Health check: `GET /healthz`
- Routing rules API:
  - list rules: `GET /rules`
  - create rule: `POST /rules/create`
  - delete rule: `POST /rules/delete`
  - update one rule config (UCI only, no apply): `POST /rules/update`
  - apply rule changes via sing-box hot reload: `POST /rules/hot-reload`
- Routing metadata API:
  - list routing nodes: `GET /routing/nodes`
  - list rule sets: `GET /rulesets`
- Network devices API:
  - list DHCP leases/devices: `GET /devices`
- HomeProxy service API:
  - status: `GET /homeproxy/status`
  - start: `POST /homeproxy/start`
  - stop: `POST /homeproxy/stop`
  - restart: `POST /homeproxy/restart`
- LuCI page: `Services -> HomeProxy API`

## API

All responses are JSON.

Optional auth:

- by default token auth is disabled (empty token in config)
- if token is set, every endpoint requires a valid token in one of:
  - `Authorization: Bearer <token>`
  - `X-Access-Token: <token>`
  - query param `access_token=<token>` (or `token=<token>`)

### `GET /healthz`

```sh
curl http://127.0.0.1:7878/healthz
```

### `POST /check`

Batch route decision for domains.

```json
{
  "domains": ["google.com", "youtube.com", "cdn.example.org"],
  "inbound": "redirect-in",
  "network": "tcp",
  "port": 443
}
```

Response contains per-domain:

- `class`: `proxy` / `direct` / `block`
- `outbound`: outbound display name
- `outboundTag`: sing-box outbound tag
- matched rule metadata (`ruleIndex`, `ruleName`, `actionType`, `ruleExpr`)

### `GET /match?q=...`

Rule-set match inspection:

```sh
curl "http://127.0.0.1:7878/match?q=google.com"
```

### `GET /stats`

Runtime internals:

```sh
curl "http://127.0.0.1:7878/stats"
```

### `GET /rules`

Returns all HomeProxy `routing_rule` sections in **priority order** (top-to-bottom as in LuCI) with:

- internal id: section name (`id`)
- generated rule tag (`tag` => `cfg-<id>-rule`)
- rule name (`label` fallback to section id)
- selected rule-sets (with id/tag/name)
- Host/IP fields:
  - `domain`
  - `domainSuffix`
  - `domainKeyword`
  - `domainRegex`
  - `ipCidr`
  - `sourceIpCidr`
- Port fields:
  - `sourcePort`
  - `sourcePortRange`
  - `port`
  - `portRange`
- outbound/action summary:
  - `action`
  - `class` (`proxy/direct/block/...`)
  - outbound `tag`, `name`, `uciTag` when available

```sh
curl http://127.0.0.1:7878/rules
```

### `POST /rules/update`

Updates one routing rule in UCI (name, outbound, and/or list fields), but does **not** apply runtime changes.

Request:

```json
{
  "tag": "cfg-abc123-rule",
  "name": "My rule name",
  "outbound": {
    "class": "proxy",
    "node": "Proxy"
  },
  "config": {
    "ruleSet": ["my_ruleset_1", "my_ruleset_2"],
    "domain": ["example.com"],
    "domainSuffix": ["google.com"],
    "domainKeyword": ["cdn"],
    "domainRegex": ["^api\\..*"],
    "ipCidr": ["1.1.1.0/24"],
    "sourceIpCidr": ["192.168.1.0/24"],
    "sourcePort": ["443"],
    "sourcePortRange": ["10000:20000"],
    "port": ["80", "443"],
    "portRange": ["8080:8090"]
  }
}
```

Notes:

- `tag` may be either generated rule tag (`cfg-...-rule`) or raw section id.
- snake_case aliases are also accepted (for example `rule_set`, `source_ip_cidr`, `port_range`).
- `name` (or alias `label`) updates rule display name.
- `outbound.class` supports `direct`, `block`, `proxy`.
- for `proxy`, set `outbound.node` to routing node section id (for example `Proxy`).
- only list fields explicitly present in `config` are replaced.

### `POST /rules/create`

Creates a new `routing_rule` section.

```json
{
  "id": "api_rule_1",
  "name": "API rule",
  "enabled": true,
  "outbound": {
    "class": "direct"
  },
  "config": {
    "domain": ["example.com"],
    "ruleSet": ["ads"]
  }
}
```

### `POST /rules/delete`

Deletes one `routing_rule` by `id` or `tag`.

```json
{
  "id": "api_rule_1"
}
```

### `GET /routing/nodes`

Returns HomeProxy `routing_node` sections (id, display name, enabled state, source node, outbound tag).

```sh
curl http://127.0.0.1:7878/routing/nodes
```

### `GET /rulesets`

Returns HomeProxy `ruleset` sections (id/tag/name/type/format/url/path/update interval).

```sh
curl http://127.0.0.1:7878/rulesets
```

### `GET /devices`

Returns devices from router DHCP leases (`/tmp/dhcp.leases`) with hostname, local IP, MAC, client id and lease expiry.

```sh
curl http://127.0.0.1:7878/devices
```

### `POST /rules/hot-reload`

Fast apply path for routing changes:

1. regenerate HomeProxy client config (`generate_client.uc`)
2. validate config (`sing-box check --config /var/run/homeproxy/sing-box-c.json`)
3. call `ubus service signal` for HomeProxy client instance (`homeproxy/sing-box-c`, `SIGHUP`)

```sh
curl -X POST http://127.0.0.1:7878/rules/hot-reload
```

This avoids full HomeProxy service restart and avoids firewall/network reinit done by `/etc/init.d/homeproxy reload`.

### HomeProxy service control API

Status:

```sh
curl http://127.0.0.1:7878/homeproxy/status
```

Start / Stop / Restart:

```sh
curl -X POST http://127.0.0.1:7878/homeproxy/start
curl -X POST http://127.0.0.1:7878/homeproxy/stop
curl -X POST http://127.0.0.1:7878/homeproxy/restart
```

## LuCI

Menu: `Services -> HomeProxy API`

Settings:

- `Enable service`
- `Enable autostart`
- `Working mode` (`default` / `eco`)
- `HomeProxy API port`
- `Access token` (optional)
- `Generate token` button (fills token field automatically)

Tools:

- `Logs`
- `Uninstall` (removes HomeProxy API service + LuCI files)

## Installation (OpenWrt)

```sh
wget -O - https://raw.githubusercontent.com/ushan0v/homeproxy-api/main/install.sh | sh
```

or

```sh
curl -fsSL https://raw.githubusercontent.com/ushan0v/homeproxy-api/main/install.sh | sh
```

Installer behavior:

- checks dependencies (`homeproxy`, `sing-box`)
- detects architecture and installs matching prebuilt binary from `dist/`
- installs init/UCI/LuCI files
- enables + starts `homeproxy-api`
- enables autostart

Optional environment overrides:

- `HPA_REPO_OWNER`
- `HPA_REPO_NAME`
- `HPA_REPO_REF`
- `HPA_BASE_URL`

## Cross Compilation

Build all common Linux targets:

```sh
./scripts/build-release.sh
```

Targets:

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

## Local Development

Build:

```sh
go build -o homeproxy-api .
```

Run:

```sh
./homeproxy-api -listen 0.0.0.0:7878 -config /var/run/homeproxy/sing-box-c.json -db /var/run/homeproxy/cache.db -mode default -access-token "your-token"
```

## Security Notes

- API can control routing rules and HomeProxy service; restrict access to trusted LAN only.
- Configure `Access token` if API is reachable by untrusted clients.
- If you expose the API beyond LAN, enforce firewall ACL and reverse-proxy auth.
- Keep LuCI/rpcd protected with strong credentials.
