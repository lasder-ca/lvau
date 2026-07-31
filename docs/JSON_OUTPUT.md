# CLI JSON output contract

Lvau 0.5.0 defines JSON schema version 1 for automation-facing commands that use the shared output envelope.

Successful output has this top-level shape:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "status": "ok",
  "data": {}
}
```

The generic schema is stored at [`schemas/lvau-cli-output-v1.schema.json`](../schemas/lvau-cli-output-v1.schema.json).

## Commands using the versioned envelope

The following commands currently emit schema version 1:

| Invocation | `command` value |
|---|---|
| `inspect --json` | `inspect` |
| `verify --json` | `verify` |
| `preflight --json` | `preflight` |
| `report --json` | `report` |
| `policy lint --json` | `policy-lint` |
| `bundle diff --json` | `bundle-diff` |

`bundle inspect --json` and `bundle list --json` currently emit command-specific JSON objects without the shared top-level envelope. Their shape must not be treated as schema version 1 until they are migrated explicitly.

## Compatibility rules

Within schema version 1:

- new optional fields may be added to `data`;
- field removal, type changes, or semantic reinterpretation require a new schema version;
- consumers should ignore unknown fields;
- process exit status remains authoritative for success or failure;
- human-readable messages are not stable identifiers.

Fields inside `data` are command-specific. Validate the top-level envelope first, then validate only the fields required by the invoking workflow.

## Errors

The schema contains a reserved error form:

```json
{
  "schema_version": 1,
  "command": "inspect",
  "status": "error",
  "error": {
    "code": "example_code",
    "message": "Human-readable detail"
  }
}
```

Not every command handler emits this form yet. In Lvau 0.5.0, callers must always check the process exit code and retain stderr for diagnostics. Do not assume that a failed `--json` invocation produces a JSON document.

JSON output must never include passwords, private keys, seeds, recovery-share contents, or decrypted payload bytes.
