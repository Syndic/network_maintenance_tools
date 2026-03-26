# Operation

## Snapshot Behavior

The audit tries to evaluate one coherent NetBox snapshot.

Workflow:
1. Read the latest row from NetBox changelog (`/api/core/object-changes/`)
2. Load all required API datasets once
3. Read the latest changelog row again
4. If the changelog changed during loading, wait and retry

Default retry behavior:
- maximum attempts: `5`
- delay between attempts: `3s`

If NetBox keeps changing during load, the audit exits with failure.

## Runtime Behavior

The audit gives progress feedback on `stderr`:
- startup line with target NetBox URL and config path
- selected checks for the run
- snapshot attempts
- per-collection snapshot progress, including request count, item count, and duration
- per-check completion, including finding count and duration

Text reports on `stdout` include timing summaries for:
- total run time
- coherent snapshot load time
- per-collection fetch durations
- per-check durations

## Running It

Run the default text report:

```bash
go run ./cmd/netbox_audit
```

Explicit example:

```bash
go run ./cmd/netbox_audit \
  -netbox-base-url http://mini.dev.yanch.ar:8000 \
  -netbox-token-file ../.netbox_api_token \
  -format text
```

To use the example policy file explicitly:

```bash
go run ./cmd/netbox_audit -config netbox_audit.config.json
```

JSON output:

```bash
go run ./cmd/netbox_audit -format json
```

Non-zero exit when findings exist:

```bash
go run ./cmd/netbox_audit -fail-on-findings
```

Color control:

```bash
go run ./cmd/netbox_audit -color auto
go run ./cmd/netbox_audit -color always
go run ./cmd/netbox_audit -color never
```

## CLI Flags

- `-netbox-base-url`
  - NetBox base URL
  - default: `http://mini.dev.yanch.ar:8000`
- `-netbox-token-file`
  - path to a NetBox API token file
  - default: `.netbox_api_token`
- `-config`
  - path to the audit policy JSON
  - default behavior:
    - if run from the repo root, use `netbox_audit.config.json` if present
    - if run from `cmd/netbox_audit`, use `../../netbox_audit.config.json` if present
    - if no config file is found, built-in defaults are used
    - if `-config` or `NETBOX_AUDIT_CONFIG` explicitly points to a missing file, the audit fails
- `-format`
  - `text` or `json`
- `-color`
  - `auto`, `always`, or `never`
- `-max-snapshot-attempts`
  - coherent-snapshot retry limit
- `-snapshot-retry-delay`
  - wait time between snapshot retries
- `-fail-on-findings`
  - exit `2` if any findings are reported

## Environment Variables

- `NETBOX_BASE_URL`
  - overrides default base URL
- `NETBOX_TOKEN`
  - if set, used directly instead of reading a token file
- `NETBOX_TOKEN_FILE`
  - overrides default token file
- `NETBOX_AUDIT_CONFIG`
  - overrides default config path
  - if set to a missing file, the audit fails
- `NETBOX_AUDIT_COLOR`
  - same values as `-color`
- `NO_COLOR`
  - disables color in `auto` mode

CLI flags take precedence over environment-variable defaults.

## Output

Text mode:
- prints progress on `stderr`
- prints snapshot metadata, timing, and one section per check on `stdout`
- uses colored status labels when enabled:
  - `PASS` = green
  - `WARN` = orange
  - `FAIL` = red

JSON mode:
- emits one JSON document with:
  - `snapshot`
  - `checks`
