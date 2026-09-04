# Bench Evidence Index

This directory stores redacted evidence metadata and structure fixtures for
hardware development. It is not a runtime vendor registry.

Store each model's versioned files under:

```text
<vendor>/<model>/<firmware>/
  manifest.yaml
  no-config.structure.json
  known-good.structure.json
```

Store raw `upgrade.har`, `config-apply.har`,
`no-config.device-backup.json`, and `known-good.device-backup.json` files only
under `/var/lib/provisioner/bench-evidence/` on the bench host. The raw files
can contain credentials, tokens, keys, PSKs, serials, and private network data.

Use [`docs/BENCH_EVIDENCE.md`](../docs/BENCH_EVIDENCE.md) for capture, access,
and review rules, [`docs/EVIDENCE_RUNBOOK.md`](../docs/EVIDENCE_RUNBOOK.md)
for the per-vendor capture steps, [`docs/EVIDENCE_CONTRIBUTING.md`](../docs/EVIDENCE_CONTRIBUTING.md)
for the issue and PR flow, and [`INVENTORY.md`](INVENTORY.md) for what is
still missing per record.

Every HAR has a `capture-summary.md` next to it, both here and beside the raw
file on the bench host. The summary is the redacted request sequence (method,
path, form field names, status codes, reported firmware) plus a short list of
what the capture did. Read it before you change an endpoint, a form field, or
an apply sequence. Generate it with:

```bash
python scripts/summarize_har.py <capture.har> --out <record>/capture-summary.md \
  --title "<model>: <what it did> (<date>)" --note "<one fact per note>"
```

The raw HAR files live only on the bench host under
`/var/lib/provisioner/bench-evidence/<vendor>/<model>/<firmware>/` (root-owned,
`700`/`600`). Deploys never touch that directory. Read them there with
`sudo -n`; do not copy them into a checkout.

Structure fixtures at `fixture_version: 2` carry a `values` map. The map holds
only fields that the vendor's field ownership contract classifies as
`fleet_policy`, `role`, or `device_default`. Generate it with
`scripts/redact_bench_fixture.py`. Template values and handler tables must
trace to these fixture paths (`tests/test_cambium_evidence.py`).

Set `fixture_witness: baseline` when the known-good export came from a unit
that received our baseline; it then witnesses fleet policy and template
values. Set `fixture_witness: role` when the unit is a working field radio
with other policy values; it then witnesses only the radio role set and the
device defaults.

A manifest may declare `no_config_backup: missing` while the exact
pre-first-apply backup is outstanding. Record bench transitions under
`transitions:` (`from`/`to` in `fresh`, `sm`, `ap`, `ptp`; `result`). The
qualification matrix offers a post-provision mode only after both directions
of that transition are recorded as `success`.

The Cambium records are under
[`cambium/ePMP_4518/5.11.1/`](cambium/ePMP_4518/5.11.1/),
[`cambium/ePMP_4616/5.11.1/`](cambium/ePMP_4616/5.11.1/), and
[`cambium/Force_300-25/5.11.1/`](cambium/Force_300-25/5.11.1/). Each holds a
known-good SM export fixture. Their values prove the SM role set
(`wirelessInterfaceMode`, `wirelessInterfacePTPMode`,
`wirelessInterfaceProtocolMode`) and show that antenna gain, minimum antenna
gain, GPS USB priority, and the second PTP mode field vary per unit, so those
are device defaults. The 4518 record also carries the factory no-config
fixture. No bench transition is recorded yet.

The current Tachyon records are under
[`tachyon/TNA-303L-65/1.15.1-rev-8541/`](tachyon/TNA-303L-65/1.15.1-rev-8541/)
and [`tachyon/TNA-301/1.15.1-rev-55177/`](tachyon/TNA-301/1.15.1-rev-55177/).
Their redacted indexes are usable in checkout. The secure raw sets are
incomplete until the exact pre-first-apply no-config backups exist.

The TNA-301 record is AP process evidence. It is tower/customer-specific and
is not a reusable template. TNA-302 shares its family but normally uses an SM
upload; do not reuse the TNA-301 capture for it.

The [`ubiquiti/Wave-Nano/unknown/`](ubiquiti/Wave-Nano/unknown/) record is
Wave Nano process evidence. Its capture leaves `network.interfaces.data.mgmtVLAN`
unset. VLAN 12 was applied outside the capture, so the management-VLAN
transition and reconnect path are not validated. Do not use this capture as a
canonical template. VLAN 12 is a required model setting for the standard Wave
Nano deployment. Encode it in the sanitized baseline after the path is
validated so that technicians do not need to remember it.
