# hebrides-agent: device patch-audit agent

A small Go program that reports a device's **OS version, installed software
and pending updates** to HebridesCyber, so the dashboard can show which
devices miss the Cyber Essentials rule that high and critical security updates
are installed within 14 days. (Gap analysis item P1-5.)

What it does **not** do:

- It never scans the network, opens listening ports, or talks to anything but
  the one HebridesCyber origin it's enrolled against (plus the OS's own update
  service, which `softwareupdate` and Windows Update query exactly as the OS
  does on its own schedule).
- It never installs, changes or removes anything. Every command it runs is a
  read-only query (`collect/` lists them; a test fails if a network tool shows
  up in a collector).
- It doesn't run `apt update` or `dnf makecache`: it reads what the package
  lists already know. A machine whose lists are never refreshed reports fewer
  pending updates than it has, and the dashboard can't tell.

`hebrides-agent inventory` prints exactly what would be sent, and sends
nothing.

## Commands

```
hebrides-agent enrol --token hcd_… [--server https://www.hebridescyber.co.uk]
hebrides-agent report        # collect and send once
hebrides-agent inventory     # print the JSON, send nothing
hebrides-agent version
```

`--config <path>` overrides the config file, which defaults to:

| OS | Path |
|---|---|
| Windows | `%ProgramData%\HebridesCyber\agent.json` |
| macOS | `/Library/Application Support/HebridesCyber/agent.json` |
| Linux | `/etc/hebrides-agent/agent.json` |

The file holds the server origin and the device token, written `0600`. Run
`enrol` and `report` as Administrator/root: the uninstall keys under HKLM,
`softwareupdate` and the config path all need it.

Exit codes: `0` sent, `1` failed (network, server error, bad config), `2` usage
error, `3` the server rejected the token (revoked or unknown: issue a new one).

## Where the data comes from

| OS | OS version | Software | Pending updates |
|---|---|---|---|
| Windows | `Win32_OperatingSystem` + `HKLM\…\CurrentVersion` (build + UBR) | the three registry *Uninstall* keys (HKLM, WOW6432Node, HKCU) | Windows Update Agent search (`IsInstalled=0`); `Get-HotFix` for installed updates |
| macOS | `sw_vers` | `system_profiler SPApplicationsDataType`, plus `pkgutil` receipts that aren't Apple's | `softwareupdate --list` |
| Linux | `/etc/os-release`, `uname -r` | `dpkg-query` (with the source package) or `rpm -qa` | `apt-get -s dist-upgrade` (security pocket = security update) or `dnf check-update` + `dnf updateinfo --security` |

A source that fails is reported in `errors` and leaves `software_checked` /
`pending_updates_checked` false, and the server shows the device as "not
enough evidence", never as up to date.

Windows Update searches can be slow: one took 20 minutes on a Windows 11 test
machine while another search was running. Each command has a 30-minute limit;
a timeout is recorded as "pending updates unknown".

## Running it daily

Run `report` once a day from the OS scheduler. Templates are in `packaging/`:

- Linux: `packaging/linux/hebrides-agent.service` + `.timer` (systemd).
- macOS: `packaging/macos/uk.co.hebridescyber.agent.plist` (launchd).
- Windows: `packaging/windows/register-task.ps1` (Task Scheduler, as SYSTEM).

The installers that will lay these down are an owner step (see `SIGNING.md`).

## Protocol

`POST https://www.hebridescyber.co.uk/api/agent/inventory`, `Authorization:
Bearer hcd_…`, JSON body as in `internal/inventory/inventory.go`. The server's
zod schema (`hebridescyber-app/src/lib/deviceAgent/inventorySchema.ts`) uses
the same limits; the agent trims to them before sending (5,000 software items,
1,000 pending updates, 2 MB body) and sets `truncated`. The agent refuses
plain `http` (except `localhost` with `--allow-insecure-localhost`) and never
follows a redirect, so the token can't be carried to another host.

Server answers: `200` with `{device_id, patch_status, summary}`; `401` token
rejected (permanent); `403` the account's plan doesn't include it; `400`/`413`
payload refused (permanent); `429`/`5xx` retried with backoff, honouring
`Retry-After`.

## Developing

```bash
cd agent
go vet ./...
go test ./...
./build.sh 0.1.0          # unsigned binaries for 6 targets into dist/
```

Collectors are pure parsers over command output; their fixtures are in
`internal/collect/testdata/`. `TestGoldenInventories` writes the full payload
for each OS to `testdata/inventory-*.golden.json`, and the server's schema test
validates those same files, so a field changed on one side fails a test on the
other. Regenerate with `UPDATE_GOLDEN=1 go test ./internal/collect/` and check
the schema.

The module has no third-party dependencies.
