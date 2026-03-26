# Networking Tools

This repo is organized to hold multiple small Go tools for this network model.

Today it contains:
- `netbox_audit`: a NetBox consistency audit

## Quick Start

From the repo root:

```bash
go run ./cmd/netbox_audit \
  -netbox-base-url http://mini.dev.yanch.ar:8000 \
  -netbox-token-file ../.netbox_api_token \
  -format text
```

Minimal run requirements:
- NetBox reachable at the configured base URL
- a NetBox API token via `NETBOX_TOKEN` or `-netbox-token-file`

Optional:
- `netbox_audit.config.json` if you want to override built-in policy defaults

## Pages

- [`cmd/netbox_audit/CHECKS.md`](cmd/netbox_audit/CHECKS.md): what each audit check verifies, what it catches, and its current scope limitations
- [`cmd/netbox_audit/CONFIG.md`](cmd/netbox_audit/CONFIG.md): config schema, policy knobs, and rule meanings
- [`cmd/netbox_audit/OPERATION.md`](cmd/netbox_audit/OPERATION.md): snapshot loading, progress output, CLI flags, environment variables, and report formats

## Repo Layout

- `cmd/netbox_audit/`: the current audit executable and its command-specific logic
- `internal/`: code shared between tools
- `netbox_audit.config.json`: example policy config for `netbox_audit`
- `go.mod`: module metadata

## Typical Workflows

Run the full audit:

```bash
go run ./cmd/netbox_audit -netbox-base-url http://mini.dev.yanch.ar:8000 -netbox-token-file ../.netbox_api_token
```

Emit JSON for machine consumption:

```bash
go run ./cmd/netbox_audit -format json
```

Fail CI or automation if findings exist:

```bash
go run ./cmd/netbox_audit -fail-on-findings
```

## Editing Guidance

- Update `cmd/netbox_audit/CHECKS.md` when a check’s behavior, scope, or rationale changes.
- Update `cmd/netbox_audit/CONFIG.md` when config keys or policy semantics change.
- Update `cmd/netbox_audit/OPERATION.md` when CLI, snapshot behavior, or output behavior changes.
