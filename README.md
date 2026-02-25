# PingTunnel-Multi by Zagros UI

This directory contains the Zagros multi-user PingTunnel implementation.

It is a Zagros-integrated PingTunnel variant used by the panel runtime, with
multi-user authentication, session control, and usage accounting extensions.

## What Is Different From Upstream

This implementation adds database-backed multi-user operation on the server side:

- `-db` server flag for auth/usage database path.
- User-key validation from DB (enabled users only).
- Quota checks (`used_bytes` vs `quota_bytes`).
- Active-session enforcement per user key.
- Session handoff timeout and stale session cleanup.
- Background user reload and traffic flush loops.
- Usage log persistence (`usage_log`) and session persistence (`active_sessions`).

Key code locations:

- `cmd/main.go`: `-db` flag and `NewServerWithDB(...)`
- `server.go`: auth-aware server runtime path
- `authdb.go`: user cache, session control, traffic accounting

## Verified In This Repository

The current source and binary in this repo contain multi-user code paths:

- Source evidence:
  - `NewServerWithDB` is present and used in server startup.
  - `AuthManager` includes session and usage logic.
  - `PINGTUNNEL_USER_RELOAD`, session timeout/handoff env controls exist.
- Binary evidence:
  - Compiled binary contains strings for:
    - `database path for multi-user auth (server only)`
    - `PINGTUNNEL_USER_RELOAD`
    - `active_sessions`
    - `user already has active session`

## Runtime Notes

The panel uses PostgreSQL as primary control-plane DB.  
This PingTunnel variant uses its own SQLite DB for PingTunnel runtime auth/usage
state (via `-db`), which is synchronized by the panel services.

Do not assume stock upstream behavior for this variant.

## Server Usage (Multi-User Variant)

Example server startup with database-backed auth:

```bash
./pingtunnel -type server -key 123456789 -db /opt/pingtunnel/data.db
```

Useful environment controls:

- `PINGTUNNEL_USER_RELOAD` (default `1s`)
- `PINGTUNNEL_SESSION_TIMEOUT` (default `60s`)
- `PINGTUNNEL_SESSION_HANDOFF` (default `5s`)

## Build

Build locally:

```bash
cd cores/pingtunnel/cmd
go build -v -o ../pingtunnel
```

## Attribution, License, and Redistribution

Upstream project license is MIT and must be preserved.

For this distribution:

- Keep upstream MIT license text intact.
- Retain this notice in README/NOTICE when redistributing this modified build.
- Retain a visible attribution to this repository in redistributed source/binaries.
- Attribution to retain:
  - `Refactored multi-user PingTunnel by Zagros UI`
  - `Source: https://github.com/MeXenon/PingTunnel-Multi`

This keeps upstream license obligations intact while making origin explicit.

Important:

- You cannot remove upstream MIT rights from upstream code.
- You can require preserving attribution for this redistributed modified
  package by keeping this README and NOTICE in distribution artifacts.
