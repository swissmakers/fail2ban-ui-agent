# fail2ban-ui-agent

## Abstract

**fail2ban-ui-agent** is a small HTTP service that runs on a host where **Fail2ban** is installed. It exposes a JSON REST API secured by a shared secret so **Fail2ban-UI** can drive the same operations as local or SSH connectors (jails, filters, ban/unban, reload, logpath checks, and callbacks via a poller). This document summarizes behavior, the API surface, runtime configuration, the **integrated container image** built on **LinuxServer.io**’s prebuilt **fail2ban** image.

**Audience:** Operators and integrators using the Fail2ban-UI **agent** connector; developers extending or packaging the agent.

**NOTE:** Treat this component as **development-oriented** until you harden secrets, TLS, and network exposure for your environment.

## Table of contents

1. [Introduction](#1-introduction)
2. [Architecture and Fail2ban-UI integration](#2-architecture-and-fail2ban-ui-integration)
3. [HTTP API](#3-http-api)
   1. [Authentication](#31-authentication)
   2. [Public endpoints](#32-public-endpoints)
   3. [Protected endpoints](#33-protected-endpoints)
4. [Environment variables](#4-environment-variables)
5. [Build and run (host binary)](#5-build-and-run-host-binary)
6. [Command-line interface](#6-command-line-interface)
7. [Integrated container image (LinuxServer Fail2ban)](#7-integrated-container-image-linuxserver-fail2ban)
8. [Packaging](#8-packaging)
9. [License](#9-license)
10. [Additional resources](#10-additional-resources)



## 1. Introduction

Remote control plane for Fail2ban on a single host, consumed by Fail2ban-UI’s `Agent-Connector`.

The agent does **not** replace Fail2ban; it requires a working **fail2ban** daemon and appropriate permissions to manage jails and configuration files.


## 2. Architecture and Fail2ban-UI integration

**Overview**

1. Fail2ban-UI connects to the agent using the server URL and **agent secret** pre-configured per Fail2ban server.
2. All management traffic uses the **v1 API** with header `X-F2B-Token` (see [Section 3](#3-http-api)).
3. For ban/unban **callbacks**, Fail2ban-UI pushes the needed settings for verified agents with **`PUT /v1/callback/config`**. The agent persists them (under `fail2ban-ui-agent.id` in the Fail2ban config tree). A **poller** compares jail state over time and POSTs changes (bans or unbans) to Fail2ban-UI’s **`/api/ban`** and **`/api/unban`** API secured with the **`X-Callback-Secret`**.

**IMPORTANT:** The poller-based callback path is the only supported model for agent connectors; please do not try to copy `ui-custom-action` scripts on agent-managed hosts.


## 3. HTTP API

Base URL is `http(s)://<host>:<AGENT_PORT>` (default port **9700** unless overridden).

### 3.1. Authentication

| Scope | Requirement |
|-------|-------------|
| **`/v1/*`** | Header **`X-F2B-Token: <AGENT_SECRET>`** must match the agent’s configured secret (constant-time compare on the server). |
| **`/healthz`**, **`/readyz`** | No token required by default |

Responses are **JSON**. Errors typically include an `"error"` string and appropriate HTTP status codes.

### 3.2. Public endpoints

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/healthz` | Liveness / health JSON |
| `GET` | `/readyz` | Readiness when the supervisor reports healthy |

### 3.3. Protected endpoints

All of the following require **`X-F2B-Token`**.

**Callback configuration**

| Method | Path | Purpose |
|--------|------|---------|
| `PUT` | `/v1/callback/config` | Body: `serverId`, `callbackUrl`, `callbackSecret`, optional `callbackHostname` -> persisted for the poller |

**Fail2ban service actions**

| Method | Path | Purpose |
|--------|------|---------|
| `POST` | `/v1/actions/reload` | Reload Fail2ban configuration |
| `POST` | `/v1/actions/restart` | Restart Fail2ban (with fallbacks where applicable) |

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
| `POST` | `/v1/jails` | Create jail |
| `DELETE` | `/v1/jails/{name}` | Delete jail |
| `POST` | `/v1/jails/update-enabled` | Map of jail name -> enabled flag |
| `POST` | `/v1/jails/test-logpath` | Test log path pattern |
| `POST` | `/v1/jails/test-logpath-with-resolution` | Resolve `%(var)s` style log paths then test |
| `GET` | `/v1/jails/check-integrity` | `jail.local` presence / managed / legacy UI-action markers |
| `POST` | `/v1/jails/ensure-structure` | Ensure managed `jail.local`; optional JSON `content` |

**Filters**

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/v1/filters` | List filter names |
| `GET` | `/v1/filters/{name}` | Read filter config |
| `PUT` | `/v1/filters/{name}` | Write filter `.local` |
| `POST` | `/v1/filters` | Create filter |
| `DELETE` | `/v1/filters/{name}` | Delete filter `.local` |
| `POST` | `/v1/filters/test` | Run `fail2ban-regex`-style test |

**NOTE:** Filter names that contain slashes must be URL-encoded in the path (as implemented in Fail2ban-UI’s connector).


## 4. Environment variables

| Variable | Default | Description |
|----------|-------------------|-------------|
| `AGENT_BIND_ADDRESS` | `0.0.0.0` | Listen address |
| `AGENT_PORT` | `9700` | Listen port |
| `AGENT_SECRET` | *(empty)* | **Required** to start the API server |
| `AGENT_TLS_CERT_FILE` / `AGENT_TLS_KEY_FILE` | *(empty)* | Set **both** to serve HTTPS on `AGENT_PORT` |
| `AGENT_FAIL2BAN_CONFIG_DIR` | `/etc/fail2ban` | Fail2ban configuration root |
| `AGENT_FAIL2BAN_RUN_DIR` | `/var/run/fail2ban` | Runtime directory (socket path context) |
| `AGENT_LOG_ROOT` | `/var/log` | Used for logpath tests / resolution |
| `AGENT_HEALTH_INTERVAL` | `30s` | Supervisor check interval |
| `AGENT_HEALTH_AUTO_RELOAD` | `true` | Auto-reload Fail2ban on repeated failures |
| `AGENT_HEALTH_AUTO_RESTART` | `true` | Auto-restart Fail2ban when reload is not enough |
| `AGENT_HEALTH_MAX_RETRIES` | `3` | Supervisor retry budget |

**Callback poller**

| Variable | Default | Description |
|----------|---------|---------------|
| *(persisted file)* | — | Primary source after **`PUT /v1/callback/config`** |
| `AGENT_CALLBACK_URL` | — | Optional override (env wins over file when set) |
| `AGENT_CALLBACK_SECRET` | — | Optional override |
| `AGENT_CALLBACK_SERVER_ID` | — | Optional override |
| `AGENT_CALLBACK_HOSTNAME` | — | Optional override |
| `AGENT_CALLBACK_POLL_INTERVAL` | `4s` | Poll interval; **`0`** disables the poller |

Persisted callback file path: **`${AGENT_FAIL2BAN_CONFIG_DIR}/fail2ban-ui-agent.id`**.


## 5. Build and run (host binary)

**Procedure**

1. Build a **static** Linux binary:

   ```bash
   cd /path/to/fail2ban-ui-agent
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fail2ban-ui-agent ./cmd/agent
   ```

2. Run with a secret:

   ```bash
   sudo AGENT_SECRET='change-me' ./fail2ban-ui-agent
   ```


## 6. Command-line interface

Global help:

```bash
./fail2ban-ui-agent --help
```

Subcommands:

| Subcommand | Purpose |
|------------|---------|
| `health-check` | `GET` the agent’s `/healthz` (optional `X-F2B-Token`) |
| `test connection` | Check **agent → Fail2ban-UI**: `GET <base>/auth/status`; with `--callback-secret`, also `GET <base>/api/healthcheck/callback` |

Examples:

```bash
./fail2ban-ui-agent health-check
./fail2ban-ui-agent health-check --json --url http://127.0.0.1:9700
./fail2ban-ui-agent test connection --callback-url https://ui.example.com
./fail2ban-ui-agent test connection --callback-url https://ui.example.com --callback-secret your-callback-secret
```

## 7. Integrated container image (LinuxServer Fail2ban)

### 7.1. Purpose

The **root `Dockerfile`** in this directory produces an image that:

1. **Builds** this agent as a **static** `linux/amd64` binary.
2. **Uses** the prebuilt image **`lscr.io/linuxserver/fail2ban:latest`** as the **runtime** base (LinuxServer.io **Fail2ban** container: Fail2ban, s6-overlay, and their layout under `/config`, etc.).
3. **Installs** the binary to **`/usr/local/bin/fail2ban-ui-agent`**.
4. **Adds** s6 **custom-init** and **custom-services** files from **`docker/linuxserver/`** so the agent starts with Fail2ban **without** the need of bind-mounting the binary or those scripts from the host.

**Pre-build imge available here:**

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
- Set **`AGENT_SECRET`** in the container environment; align the same value in Fail2ban-UI’s agent server settings.
- Mount a persistent **`/config`** tree compatible with LinuxServer Fail2ban (see their documentation for layout and permissions).



## 8. Packaging

For **systemd** unit files and an **RPM spec** skeleton (needs to be finished), see here:

- `packaging/README.md`
- `packaging/systemd/fail2ban-ui-agent.service`
- `packaging/rpm/fail2ban-ui-agent.spec`


## 9. License

- **fail2ban-ui-agent** (sources and the binary you build from them) is licensed under the **GNU General Public License v3.0**. Full text: **`LICENSE`** in this directory; summary: [GNU GPLv3](https://www.gnu.org/licenses/gpl-3.0.en.html).
- **Fail2ban-UI** (main application) is licensed under the same **GPLv3** where stated in that repository.


## 10. Additional resources

- Fail2ban-UI agent connector implementation: `internal/fail2ban/connector_agent.go` ([Fail2ban-UI project](https://github.com/swissmakers/fail2ban-ui/blob/main/internal/fail2ban/connector_agent.go)).
- LinuxServer.io Fail2ban image: [linuxserver/docker-fail2ban](https://github.com/linuxserver/docker-fail2ban) (upstream documentation and license information).
