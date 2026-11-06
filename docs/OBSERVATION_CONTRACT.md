# Observation contract

The JSON and MCP payloads are public interfaces. In the `0.x` series, a breaking field change requires a **minor version bump** and migration notes in `CHANGELOG.md`. A patch release may add fields or values without changing the meaning of existing fields. Do not reinterpret unknown evidence as healthy or treat an empty incident scan as clean.

## Health envelope

The frozen health envelope is emitted by the CLI `qts health` command and MCP `qts_health`. It requires `status`, `healthy_claim`, `findings`, and `unknowns`, plus the existing `storage` observation. `findings` and `unknowns` are arrays of objects with `code` and `message`. `status` is `healthy`, `unhealthy`, or `indeterminate`; `healthy_claim` is `permitted` or `not_permitted`.

Health limitations are currently carried at **`storage.limitations`**, not at the health root. Standalone `qts storage` returns the storage observation directly and carries its `limitations` at that payload's root. In an incident report, the health envelope is nested at `observations.health`; the incident report itself is not a health envelope.

## Command schemas

Schemas use JSON Schema and are kept in `schemas/`:

- `observation-health.schema.json`: `qts health`, MCP `qts_health`, and nested incident `observations.health`.
- `observation-storage.schema.json`: standalone `qts storage` output or the nested health `storage` object.
- `observation-raid.schema.json`: the `qts raid` / MCP `qts_raid` output from `ssh_backend.raid_status`.
- `observation-incident.schema.json`: the report returned by `qts incident scan` / MCP `qts_incident`. Its scan evidence is `ransomware_scan.indicators`; no-hit results remain `indeterminate`, never `clean`.

RAID and incident payloads have their own schemas and do not have to expose the five-field health envelope. Contract tests use a small stdlib-only validator for the schema keywords used here; no JSON Schema package is a runtime or test dependency.
