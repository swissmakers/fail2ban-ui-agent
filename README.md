# fail2ban-ui-agent

## Abstract

**fail2ban-ui-agent** is a small HTTP service that runs on a host where **Fail2ban** is installed. It exposes a JSON REST API secured by a shared secret so **Fail2ban-UI** can drive the same operations as local or SSH connectors (jails, filters, ban/unban, reload, logpath checks, and callbacks via a poller). This document summarizes behavior, the API surface, runtime configuration, the **integrated container image** built on **LinuxServer.io**’s prebuilt **fail2ban** image.

**Audience:** Operators and integrators using the Fail2ban-UI **agent** connector; developers extending or packaging the agent.

**NOTE:** Treat this component as **development-oriented** until you harden secrets, TLS, and network exposure for your environment.

## Table of contents

1. [Introduction](#1-introduction)
2. [Architecture and Fail2ban-UI integration](#2-architecture-and-fail2ban-ui-integration)
   1. [Callbacks](#21-callbacks)
   2. [Health supervision](#22-health-supervision)
3. [HTTP API](#3-http-api)
   1. [Authentication](#31-authentication)
   2. [Public endpoints](#32-public-endpoints)
   3. [Protected endpoints](#33-protected-endpoints)
   4. [Error codes](#34-error-codes)
4. [Environment variables](#4-environment-variables)
5. [Build and run (host binary)](#5-build-and-run-host-binary)
6. [Command-line interface](#6-command-line-interface)
7. [Integrated container image (LinuxServer Fail2ban)](#7-integrated-container-image-linuxserver-fail2ban)
8. [Packaging](#8-packaging)
9. [License](#9-license)
10. [Additional resources](#10-additional-resources)



## 1. Introduction

Remote control plane for Fail2ban on a single host, consumed by Fail2ban-UI’s `Agent-Connector`.

The agent does **not** replace Fail2ban; it requires a working **fail2ban** daemon and appropriate permissions to manage jails and configuration files. Every `fail2ban-client` call runs with `-c <AGENT_FAIL2BAN_CONFIG_DIR>`, so the agent always talks to the daemon that owns that configuration tree.


## 2. Architecture and Fail2ban-UI integration

**Overview**

1. Fail2ban-UI connects to the agent using the server URL and **agent secret** pre-configured per Fail2ban server.
2. All management traffic uses the **v1 API** with header `X-F2B-Token` (see [Section 3](#3-http-api)).
3. Fail2ban-UI polls **`GET /v1/health`** to show the server health and to detect a stale callback configuration.
4. Configuration files are replaced atomically. The previous content of a changed file is kept as a private `<file>.f2bui.bak`, so a failed write never leaves a truncated jail or filter behind.

### 2.1. Callbacks

Fail2ban-UI records bans and unbans that happen on the host. For agent-managed hosts, the agent reports them:

1. Fail2ban-UI pushes its callback URL, callback secret and server ID with **`PUT /v1/callback/config`**. The agent stores them in `${AGENT_FAIL2BAN_CONFIG_DIR}/fail2ban-ui-agent.id` (mode `0600`).
2. A **poller** compares the banned IPs of every jail each `AGENT_CALLBACK_POLL_INTERVAL` and POSTs each change to Fail2ban-UI’s **`/api/ban`** or **`/api/unban`**, authenticated with **`X-Callback-Secret`**.
3. Each change gets a stable **`X-Callback-Event-ID`**. When Fail2ban-UI is unreachable, the agent keeps up to 1000 events for one hour and retries them in order with exponential backoff (up to 5 minutes). Fail2ban-UI discards duplicates by event ID, so a retry never records a ban twice.
4. The agent compares only jails that exist in both snapshots. A reload that briefly removes a jail does not flood Fail2ban-UI with unbans.
5. When a server is removed from Fail2ban-UI, it calls **`DELETE /v1/callback/config?serverId=<id>`**. The agent deletes the store only if it still belongs to that server.

**Precedence:** the store pushed by Fail2ban-UI always wins. The `AGENT_CALLBACK_*` variables are only a fallback for hosts that Fail2ban-UI has not configured yet, or after the store was deleted.

**IMPORTANT:** The poller-based callback path is the only supported model for agent connectors; please do not try to copy `ui-custom-action` scripts on agent-managed hosts.

### 2.2. Health supervision

The agent pings Fail2ban every `AGENT_HEALTH_INTERVAL` so that protection resumes without an operator when the daemon hangs or dies:

1. After `AGENT_HEALTH_MAX_RETRIES` failed pings in a row, the agent reloads Fail2ban (`AGENT_HEALTH_AUTO_RELOAD`).
2. If Fail2ban still does not answer, later attempts restart it through `systemctl`, `service` or `rc-service` (`AGENT_HEALTH_AUTO_RESTART`). Without a service manager, the agent falls back to a reload.
3. The wait between attempts doubles each time (up to 30 minutes). After 5 attempts the agent stops remediating until a ping succeeds again, so a broken configuration cannot cause a restart loop.
4. When systemd reports `fail2ban` as `inactive`, an administrator stopped it on purpose. The agent then does not restart it.


## 3. HTTP API

Base URL is `http(s)://<host>:<AGENT_PORT>` (default port **9700** unless overridden).

### 3.1. Authentication

| Scope | Requirement |
|-------|-------------|
| **`/v1/*`** | Header **`X-F2B-Token: <AGENT_SECRET>`** must match the agent’s configured secret (constant-time compare on the server). |
| **`/healthz`**, **`/readyz`** | No token. The responses contain no details. |

Responses are **JSON**. Errors include an `"error"` string and, where the caller can act on it, a machine-readable `"code"` (see [Section 3.4](#34-error-codes)). Request bodies are limited to 5 MiB.

### 3.2. Public endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness: always `200 {"status":"ok"}` while the agent process serves requests |
| `GET` | `/readyz` | Readiness: `200 {"ready":true}` or `503 {"ready":false}`. Ready means the last check is recent, Fail2ban answered `pong`, the config directory is writable, and `fail2ban-client` and `fail2ban-regex` are installed |

### 3.3. Protected endpoints

All of the following require **`X-F2B-Token`**.

**Health**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v1/health` | Readiness checks, agent and Fail2ban versions, running jails, supervisor state and callback status. The callback block carries a `fingerprint` (HMAC-SHA256 of server ID, callback URL and callback secret, keyed with the agent secret) instead of the secret, so Fail2ban-UI can detect a stale configuration |

**Callback configuration**

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/v1/callback/config` | Body: `serverId`, `callbackUrl`, `callbackSecret`, optional `callbackHostname`. The URL must be `http(s)://host[:port][/path]` without credentials, query or fragment |
| `DELETE` | `/v1/callback/config?serverId=<id>` | Delete the store if it belongs to `<id>`. Returns `{"ok":true,"cleared":true}`, or `cleared:false` with `reason` `server_mismatch` or `not_configured` |

**Fail2ban service actions**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/actions/reload` | Reload Fail2ban; returns `{"ok":true,"output":...}` |
| `POST` | `/v1/actions/restart` | Restart Fail2ban; returns `{"ok":true,"mode":"restart"}`, or `"mode":"reload"` when no service manager could restart it |
| `POST` | `/v1/actions/validate` | Test the configuration with `fail2ban-client -t`: `200 {"ok":true,"output":...}`, or `422` with `code` `config_invalid` and the test output |

Reload, restart and validate run one at a time and finish even if the caller disconnects.

**Jails**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v1/jails` | List jails from `fail2ban-client` (runtime-oriented) |
| `GET` | `/v1/jails/all` | Broader jail listing for "Manage jails" UI |
| `GET` | `/v1/jails/{jail}` | Banned IPs / counts for a jail |
| `POST` | `/v1/jails/{jail}/ban` | Ban an IP |
| `POST` | `/v1/jails/{jail}/unban` | Unban an IP |
| `GET` | `/v1/jails/{jail}/config` | Read jail config (with `.local` / `.conf` fallback semantics) |
| `PUT` | `/v1/jails/{jail}/config` | Write jail config |
| `POST` | `/v1/jails` | Create jail; adds the `[jail]` section header when the content lacks it |
| `DELETE` | `/v1/jails/{jail}` | Delete `jail.d/{jail}.local` and `jail.d/{jail}.conf` |
| `POST` | `/v1/jails/update-enabled` | Map of jail name -> enabled flag |
| `POST` | `/v1/jails/test-logpath` | Test log path pattern |
| `POST` | `/v1/jails/test-logpath-with-resolution` | Resolve `%(var)s` style log paths then test |
| `GET` | `/v1/jails/check-integrity` | `jail.local` presence / managed / legacy UI-action markers |
| `POST` | `/v1/jails/ensure-structure` | Write the managed `jail.local` from the optional JSON `content`. Returns `{"ok":true,"skipped":false}`; a `jail.local` that neither the agent nor Fail2ban-UI wrote is never touched (`skipped:true`, `reason:"unmanaged"`) |

Jail and filter names use letters, digits, `_` and `-` and must not start with `-`. The jail names `DEFAULT`, `INCLUDES`, `all` and `check-integrity` are reserved (case-insensitive).

**Filters**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v1/filters` | List filter names |
| `GET` | `/v1/filters/{name}` | Read filter config |
| `PUT` | `/v1/filters/{name}` | Write filter `.local` |
| `POST` | `/v1/filters` | Create filter |
| `DELETE` | `/v1/filters/{name}` | Delete `filter.d/{name}.local` and `filter.d/{name}.conf` |
| `POST` | `/v1/filters/test` | Run `fail2ban-regex`; returns `{"output","filterPath","exitCode"}` for every completed run, `500` only when it could not run. Files named in the filter’s `[INCLUDES]` are copied from `filter.d` (with their `.local` files, up to 3 levels) so unsaved filter content is tested exactly as Fail2ban would load it |

### 3.4. Error codes

| Code | Status | Meaning |
|------|--------|---------|
| `auth_invalid_token` | 401 | Missing or wrong `X-F2B-Token` |
| `invalid_name` | 400 | Jail or filter name rejected |
| `invalid_ip` | 400 | Not an IP address or CIDR |
| `not_found` | 404 | Jail or filter file does not exist |
| `callback_invalid` | 400 | Callback configuration or `serverId` rejected |
| `logpath_invalid` | 400 | Logpath is not absolute, contains `..` or unsupported characters |
| `logpath_unresolved` | 422 | A `%(var)s` in the logpath is not defined in the configuration |
| `logpath_inaccessible` | 422 | The agent may not read the logpath directory |
| `config_invalid` | 422 | `fail2ban-client -t` rejected the configuration |


## 4. Environment variables

The agent refuses to start when a variable has an invalid value (port, duration, boolean, path) and lists every problem at once.

| Variable | Default | Description |
|----------|-------------------|-------------|
| `AGENT_BIND_ADDRESS` | `0.0.0.0` | Listen address (IP) |
| `AGENT_PORT` | `9700` | Listen port |
| `AGENT_SECRET` | *(empty)* | **Required.** At least 16 characters and not a placeholder such as `change-me`. Generate one with `openssl rand -hex 32` |
| `AGENT_TLS_CERT_FILE` / `AGENT_TLS_KEY_FILE` | *(empty)* | Set **both** to serve HTTPS on `AGENT_PORT` |
| `AGENT_FAIL2BAN_CONFIG_DIR` | `/etc/fail2ban` | Fail2ban configuration root, passed to every `fail2ban-client` call as `-c` |
| `AGENT_LOG_ROOT` | `/var/log` | Where `/var/log` paths are found during logpath tests (for example a container mount) |
| `AGENT_HEALTH_INTERVAL` | `30s` | Supervisor check interval (minimum `5s`) |
| `AGENT_HEALTH_AUTO_RELOAD` | `true` | Reload Fail2ban after repeated failed pings |
| `AGENT_HEALTH_AUTO_RESTART` | `true` | Restart Fail2ban when a reload is not enough |
| `AGENT_HEALTH_MAX_RETRIES` | `3` | Failed pings in a row before remediation starts |

Booleans accept `true`/`false`, `yes`/`no`, `on`/`off` and `1`/`0`.

**NOTE:** `AGENT_FAIL2BAN_RUN_DIR` was removed. The agent ignores it and logs a warning; `fail2ban-client` finds its socket through `AGENT_FAIL2BAN_CONFIG_DIR`.

**Callback poller**

| Variable | Default | Description |
|----------|---------|---------------|
| `AGENT_CALLBACK_URL` | — | Fallback callback URL, used only while no store from Fail2ban-UI exists |
| `AGENT_CALLBACK_SECRET` | — | Fallback callback secret |
| `AGENT_CALLBACK_SERVER_ID` | — | Fallback server ID |
| `AGENT_CALLBACK_HOSTNAME` | host name | Hostname reported with each event; also used with UI-pushed callbacks when the server entry has no hostname |
| `AGENT_CALLBACK_POLL_INTERVAL` | `4s` | Poll interval: `0` disables the poller, otherwise at least `1s` |

Set `AGENT_CALLBACK_URL`, `AGENT_CALLBACK_SECRET` and `AGENT_CALLBACK_SERVER_ID` together; the agent ignores an incomplete set and logs a warning. The store at **`${AGENT_FAIL2BAN_CONFIG_DIR}/fail2ban-ui-agent.id`** wins over these variables.


## 5. Build and run (host binary)

**Procedure**

1. Build a **static** Linux binary:

   ```bash
   cd /path/to/fail2ban-ui-agent
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fail2ban-ui-agent ./cmd/agent
   ```

2. Run with a random secret:

   ```bash
   sudo AGENT_SECRET="$(openssl rand -hex 32)" ./fail2ban-ui-agent
   ```

   Enter the same secret in the agent server settings of Fail2ban-UI.


## 6. Command-line interface

Global help:

```bash
./fail2ban-ui-agent --help
```

Subcommands:

| Subcommand | Purpose |
|------------|---------|
| `health-check` | `GET /healthz` of the local agent |
| `health-check --ready` | `GET /readyz`; exits `0` only when the agent can manage Fail2ban |
| `health-check --detail` | `GET /v1/health` with `X-F2B-Token` (from `--secret` or `AGENT_SECRET`) |
| `test connection` | Check **agent → Fail2ban-UI**: `GET <base>/auth/status`; with a callback secret, also `GET <base>/api/healthcheck/callback` |

`health-check` flags: `--url <url>` (default: `127.0.0.1` for a wildcard `AGENT_BIND_ADDRESS`, `AGENT_PORT`, `https` when `AGENT_TLS_CERT_FILE` is set; certificate verification is skipped only for that derived loopback URL), `--secret <token>`, `--json`.

`test connection` flags: `--callback-url <url>`, `--callback-secret <token>`, `--json`. Without `--callback-url`, it tests the callback the agent itself would use: the store pushed by Fail2ban-UI, then `AGENT_CALLBACK_*`. The output names the source (`flags`, `store` or `env`).

Exit codes: `0` success, `1` check failed, `2` usage error (including an unknown command or flag).

Examples:

```bash
./fail2ban-ui-agent health-check
./fail2ban-ui-agent health-check --ready
./fail2ban-ui-agent health-check --detail --json
./fail2ban-ui-agent test connection
./fail2ban-ui-agent test connection --callback-url https://ui.example.com --callback-secret your-callback-secret
```

## 7. Integrated container image (LinuxServer Fail2ban)

### 7.1. Purpose

The **root `Dockerfile`** in this directory produces an image that:

1. **Builds** this agent as a **static** binary for each target platform (`linux/amd64`, `linux/arm64`).
2. **Uses** the prebuilt image **`lscr.io/linuxserver/fail2ban:latest`** as the **runtime** base (LinuxServer.io **Fail2ban** container: Fail2ban, s6-overlay, and their layout under `/config`, etc.).
3. **Installs** the binary to **`/usr/local/bin/fail2ban-ui-agent`**.
4. **Adds** s6 **custom-init** and **custom-services** files from **`docker/linuxserver/`** so the agent starts with Fail2ban **without** the need of bind-mounting the binary or those scripts from the host.

**Pre-built multi-arch image available here:**

   ```bash
   podman pull swissmakers/fail2ban-ui-agent:latest
   ```

### 7.2. Build

**Procedure**

1. From **this** directory:

   ```bash
   podman build -t localhost/fail2ban-ui-agent:latest .
   ```

   or:

   ```bash
   docker build -t localhost/fail2ban-ui-agent:latest .
   ```

### 7.3. Runtime notes

- Publish **`AGENT_PORT`** (default **9700** in the image `ENV`) or use **host networking** in Compose as your environment requires.
- Set **`AGENT_SECRET`** in the container environment; align the same value in Fail2ban-UI’s agent server settings. `container-compose.yml` reads it from the shell and refuses to start without it:

   ```bash
   AGENT_SECRET="$(openssl rand -hex 32)" podman compose -f container-compose.yml up -d
   ```

- Mount a persistent **`/config`** tree compatible with LinuxServer Fail2ban (see their documentation for layout and permissions).



## 8. Packaging

For **systemd** unit files and an **RPM spec** skeleton (needs to be finished), see here:

- `packaging/README.md`
- `packaging/systemd/fail2ban-ui-agent.service`
- `packaging/rpm/fail2ban-ui-agent.spec`

The agent version is defined in `internal/version/version.go`; CI tags images with it.


## 9. License

- **fail2ban-ui-agent** (sources and the binary you build from them) is licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0-only). Full text: **`LICENSE`** in this directory; summary: [GNU AGPLv3](https://www.gnu.org/licenses/agpl-3.0.en.html).
- **Fail2ban-UI** (main application) is licensed under the same **AGPLv3** where stated in that repository.


## 10. Additional resources

- Fail2ban-UI agent connector implementation: `internal/fail2ban/connector_agent.go` ([Fail2ban-UI project](https://github.com/swissmakers/fail2ban-ui/blob/main/internal/fail2ban/connector_agent.go)).
- LinuxServer.io Fail2ban image: [linuxserver/docker-fail2ban](https://github.com/linuxserver/docker-fail2ban) (upstream documentation and license information).
