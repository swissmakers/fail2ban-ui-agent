# Packaging fail2ban-ui-agent for Linux distributions

## Abstract

This document describes the **packaging skeleton** for **fail2ban-ui-agent**: a `systemd` unit suitable for RHEL-compatible systems, and an **RPM `.spec` file** for building a binary package. The artifacts are templates; you must adapt versioning, sources, signing, and macros to your build system and distribution policy.

**Audience:** System administrators and packagers deploying the agent on bare metal or VMs (not the container image described in the parent `README.md`).

## Table of contents

1. [Introduction](#1-introduction)
2. [Prerequisites](#2-prerequisites)
3. [systemd unit deployment](#3-systemd-unit-deployment)
   1. [Install the unit file and binary](#31-install-the-unit-file-and-binary)
   2. [Configure environment variables](#32-configure-environment-variables)
   3. [Enable and start the service](#33-enable-and-start-the-service)
   4. [Verify the deployment](#34-verify-the-deployment)
4. [RPM package build](#4-rpm-package-build)
   1. [Overview](#41-overview)
   2. [Build a source tarball](#42-build-a-source-tarball)
   3. [Build the RPM](#43-build-the-rpm)
   4. [Adapt the spec for production](#44-adapt-the-spec-for-production)
5. [Additional resources](#5-additional-resources)


## 1. Introduction

| Component | Path | Purpose |
|-----------|------|---------|
| systemd unit | `packaging/systemd/fail2ban-ui-agent.service` | Runs `fail2ban-ui-agent` as a long-running service after `fail2ban.service` |
| Environment defaults | `/etc/default/fail2ban-ui-agent` (optional) | Overrides and secrets; referenced by the unit via `EnvironmentFile=-` |
| RPM spec | `packaging/rpm/fail2ban-ui-agent.spec` | Builds `%{_bindir}/fail2ban-ui-agent` and installs the systemd unit |

The agent listens on a TCP port (default in the shipped unit: **9443**; override with `AGENT_PORT` in `/etc/default/fail2ban-ui-agent` if you standardize on **9700** for Fail2ban-UI compatibility).


## 2. Prerequisites

* A Linux host with **systemd** and **fail2ban** installed and enabled.
* **Root** (or equivalent) to install unit files under `/etc/systemd/system` or `/usr/lib/systemd/system` and to bind to privileged ports if required.
* For RPM builds: **RPM build tools** (`rpm-build`, `rpmlint` optional) and a **Go toolchain** matching `BuildRequires` in the spec (currently **Go ≥ 1.25** per the spec).
* A strong **`AGENT_SECRET`**; without it the API server refuses to start when using the standard `config.Load()` path.

**IMPORTANT:** Store `AGENT_SECRET` in a root-only file (for example `/etc/default/fail2ban-ui-agent` with mode `0600`). Do not commit secrets to version control.


## 3. systemd unit deployment

### 3.1. Install the unit file and binary

**Procedure**

1. Build a static binary suitable for your architecture (recommended for portable installs):

   ```bash
   cd /path/to/fail2ban-ui-agent
   CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o fail2ban-ui-agent ./cmd/agent
   ```

2. Install the binary:

   ```bash
   sudo install -D -m 0755 fail2ban-ui-agent /usr/bin/fail2ban-ui-agent
   ```

   **NOTE:** The unit file references `ExecStart=/usr/bin/fail2ban-ui-agent`. If you install to `/usr/local/bin`, edit `ExecStart` accordingly or add a symlink.

3. Install the unit:

   ```bash
   sudo install -D -m 0644 packaging/systemd/fail2ban-ui-agent.service \
     /etc/systemd/system/fail2ban-ui-agent.service
   ```

4. Reload systemd:

   ```bash
   sudo systemctl daemon-reload
   ```

### 3.2. Configure environment variables

**Procedure**

1. Create `/etc/default/fail2ban-ui-agent` (optional but **required** for `AGENT_SECRET`):

   ```bash
   sudo install -D -m 0600 /dev/stdin /etc/default/fail2ban-ui-agent <<'EOF'
   AGENT_SECRET=change-me-to-a-long-random-value
   AGENT_BIND_ADDRESS=0.0.0.0
   AGENT_PORT=9700
   AGENT_FAIL2BAN_CONFIG_DIR=/etc/fail2ban
   AGENT_FAIL2BAN_RUN_DIR=/var/run/fail2ban
   AGENT_LOG_ROOT=/var/log
   EOF
   ```

2. Adjust paths if your distribution places Fail2ban config under a different root (for example some container-style layouts use `/config/fail2ban`).

**NOTE:** Variables in `/etc/default/fail2ban-ui-agent` override defaults set in the unit file for the same keys.

### 3.3. Enable and start the service

**Procedure**

1. Enable the service at boot:

   ```bash
   sudo systemctl enable --now fail2ban-ui-agent.service
   ```

2. Ensure **fail2ban** is active:

   ```bash
   sudo systemctl enable --now fail2ban.service
   ```

### 3.4. Verify the deployment

**Procedure**

1. Check service state:

   ```bash
   systemctl status fail2ban-ui-agent.service
   ```

2. Check the health endpoint (replace port if you changed `AGENT_PORT`):

   ```bash
   curl -fsS "http://127.0.0.1:9700/healthz"
   ```

3. Review logs on failure:

   ```bash
   journalctl -u fail2ban-ui-agent.service -e --no-pager
   ```


## 4. RPM package build

### 4.1. Overview

The spec file `packaging/rpm/fail2ban-ui-agent.spec` is a **minimal skeleton**. It:

* Builds the Go binary during `%build`.
* Installs `fail2ban-ui-agent` into `%{_bindir}`.
* Installs `packaging/systemd/fail2ban-ui-agent.service` into `%{_unitdir}`.
* Uses standard `%systemd_*` scriptlets for RHEL/Fedora-style macros.

**IMPORTANT:** You must supply **`Source0`** as a tarball whose top-level directory matches what `%autosetup` expects (typically `fail2ban-ui-agent-%{version}`). The repository layout alone is not sufficient; create a release archive or adjust `%prep` to match your layout.

### 4.2. Build a source tarball

**Procedure**

1. From a clean export of the agent sources at version `0.1.0`, create an archive named so the unpacked directory is `fail2ban-ui-agent-0.1.0` (example naming; align with `Version:` in the spec).

2. Place the tarball where `rpmbuild` expects it, for example `~/rpmbuild/SOURCES/fail2ban-ui-agent-0.1.0.tar.gz`.

### 4.3. Build the RPM

**Procedure**

1. Copy the spec into your build tree:

   ```bash
   cp packaging/rpm/fail2ban-ui-agent.spec ~/rpmbuild/SPECS/
   ```

2. Build:

   ```bash
   rpmbuild -ba ~/rpmbuild/SPECS/fail2ban-ui-agent.spec
   ```

3. Install the resulting RPM on a test host and repeat [Section 3.2](#32-configure-environment-variables) and [3.4](#34-verify-the-deployment).

### 4.4. Adapt the spec for production

Before publishing packages, review and typically change:

| Topic | Action |
|-------|--------|
| **License** | Ensure `License:` matches the actual license of the shipped sources (and `%license` file list). |
| **Version / Release** | Align with your release policy; use `Release:` for rebuilds. |
| **Source0 / URL** | Point to signed tarballs or a Git forge archive; add `Source1` for vendor tarballs if you bundle Go modules offline. |
| **`BuildRequires`** | Match the Go version available in your buildroots (RHEL 9 AppStream, EPEL, module streams, etc.). |
| **`%build`** | Add `CGO_ENABLED=0` and explicit `GOOS`/`GOARCH` if you need a static binary for musl-free glibc targets. |
| **Signing** | Enable GPG signing in `~/.rpmmacros` or your CI pipeline. |
| **`/etc/default` file** | Optionally ship `%config(noreplace)` for `/etc/default/fail2ban-ui-agent` with a documented default **without** a real secret. |


## 5. Additional resources

* Agent runtime and API: parent directory `README.md` in the fail2ban-ui-agent module.
* Container image (linuxserver/fail2ban + baked agent): root `Dockerfile` in the same module.
* Upstream Fail2ban-UI integration: `internal/fail2ban/connector_agent.go` in the main Fail2ban-UI repository.
