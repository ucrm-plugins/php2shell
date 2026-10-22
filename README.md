# php2shell

Patches the PHP inside a **UISP** server against
**CVE-2026-109618 / CVE-2026-109619** — unauthenticated remote code execution
in PHP, CVSSv4 **9.2**, disclosed 21 October 2026.

UISP's **CRM** — the billing and client-management half, including the client
zone — runs on PHP, in the `ucrm` container. The **NMS** side (devices, sites,
topology) is Node.js and is not affected by this CVE.

That still leaves the exposed half exposed: the CRM serves the admin UI and the
client zone, and both are normally internet-reachable. Until Ubiquiti ships an
image built on a fixed PHP, those are exploitable **without credentials**.

```bash
git clone https://github.com/<org>/php2shell.git
cd php2shell
sudo ./php2shell.sh status      # am I affected?
sudo ./php2shell.sh install
```

> Not affiliated with, endorsed by, or supported by Ubiquiti. It modifies how
> your UISP container is built. Read [What it changes](#what-it-changes), and
> take a backup first.

## What it actually does

It rebuilds the **same PHP minor version** UISP already ships, at a patch level
that contains the fix, and runs UISP on that image. Nothing else changes — not
UISP's code, not its extensions, not its configuration.

Afterwards `php -v` inside the container reports a fixed version. **The
vulnerability is gone from the binary**, which is different from the request
filters going around for this CVE: those leave the vulnerable PHP running and
try to keep certain requests away from it. Per the PHP advisories, *the request
is processed before any application code runs* — so filters that let
authenticated traffic through still expose every account, and UISP's client zone
means that is every customer, not just admins.

## Commands

| | |
|---|---|
| `./php2shell.sh status` | What is running and whether it is patched. Changes nothing. |
| `sudo ./php2shell.sh install` | Build the patched image and run UISP on it. Safe to re-run. |
| `sudo ./php2shell.sh remove` | Restore UISP's own image. |

All three need to talk to the Docker daemon, so run them as root **or** as a
user in the `docker` group — `status` changes nothing either way, but it cannot
read the container without that access. On some installs `/home/unms` is also
restricted, in which case even `status` needs `sudo`. The script says which of
the two is missing rather than guessing.

`status` exits **0** patched, **1** stale, **2** vulnerable, so it works as a
cron or monitoring check:

```bash
*/30 * * * * root /opt/php2shell/php2shell.sh status || logger -t php2shell "UISP PHP needs attention"
```

## Re-run `install` after every UISP update

UISP updates replace the container with Ubiquiti's own image, which undoes the
patch. That is intentional — if Ubiquiti's new image is already fixed you want
theirs, not ours — but it reverts on **any** update, not only a fixing one.

`install` re-derives everything from what the box holds at that moment, so
re-running it is always the right move, and `status` will tell you when it is
needed:

```
php2shell block   : present (UISP_VERSION=4.6.13)
STALE: the override pins 4.6.13 but UISP now holds 4.6.16
```

If Ubiquiti's new image already contains a fixed PHP, `install` says so and does
nothing. Use `remove` to tidy up.

## UISP's own tooling bypasses this patch — on purpose

`unms-cli` and the UISP updater invoke Compose as:

```bash
docker compose -p unms -f /home/unms/app/docker-compose.yml ...
```

Passing `-f` explicitly **disables Compose's automatic discovery of
`docker-compose.override.yml`** — the file this tool writes to. Nothing in
`unms-cli` references that file at all.

The practical effect: **`unms-cli restart|start|stop` runs UISP on Ubiquiti's
stock image**, not the patched one, until something invokes bare `docker compose`
again (which `php2shell.sh install` does).

That is the behaviour we want, and the reason this tool writes to the override
file rather than editing `docker-compose.yml`:

- The patch **steps aside automatically** once Ubiquiti ships a fixed image.
  There is no leftover customisation quietly shadowing a newer, better release.
- `docker-compose.yml` is **regenerated from a template on every UISP update**,
  so anything written there is lost anyway — and it is upstream's file.

The catch is that it steps aside on **any** `unms-cli` restart, not only after a
fixing update. So after one, UISP may be back on stock PHP without saying so.
That is exactly what `status` is for, and why it exits non-zero:

```
container running : ubnt/unms-crm:4.6.13
PHP in container  : 8.3.32
VULNERABLE: PHP 8.3.32 < 8.3.36
```

Run `install` again and you are patched; it is safe to re-run at any time.

## PHP 8.1 and older cannot be fixed by this tool

For this CVE the PHP project published a fixed **release** only for 8.2, 8.3,
8.4 and 8.5. Branches 7.4, 8.0 and 8.1 got a minimal **source backport** — there
is no release to build, and this tool does not apply patches.

Older UISP images ship PHP 8.1. On those, `install` refuses and explains why,
rather than rebuilding 8.1.34 (the newest 8.1 there is, and still vulnerable)
and reporting success. **The remedy there is updating UISP to a build on PHP
8.2+.**

## What it changes

Two things on the host, both reversible by `remove`:

1. **`<uisp-app-dir>/php2shell/Dockerfile`** — the build context.
2. **A delimited block in `<uisp-app-dir>/docker-compose.override.yml`:**

```yaml
# >>> php2shell >>>
# Managed by php2shell. Do not edit by hand; re-run 'php2shell.sh install'.
# Removing this block and recreating the container restores UISP's own image.
  ucrm:
    image: php2shell/unms-crm:4.6.13-php8.3.36
    build:
      context: ./php2shell
      args:
        UISP_VERSION: "4.6.13"
        PHP_VERSION: "8.3.36"
        PHP_SHA256: "dd54693aa334c5c4d72e9aee96b082c2473750a18a6c1d105789c93a3b1692fd"
# <<< php2shell <<<
```

Block style rather than flow (`args: { ... }`) deliberately: both are valid YAML,
but block diffs cleanly and avoids quoting edge cases in a generated file.
`args` as a mapping needs Compose-spec parsing, which any UISP host already has —
UISP's own `docker-compose.yml` carries no `version:` key, so it requires the
same.

`docker-compose.yml` is **never touched** — UISP regenerates it on update. If you
already have an override it is backed up and merged, never overwritten, and the
result is validated with `docker compose config` and rolled back if it does not
parse. If something else already defines a `ucrm` service, the install stops.

## How the build is verified

The PHP tarball is downloaded from php.net and checked against the **SHA-256
published by php.net's own release API** — a tampered mirror fails the build.

The build then reads the stock image's exact `./configure` line and reuses it, so
the rebuilt PHP matches Ubiquiti's flags rather than a guess, and refuses to
proceed if it cannot read it. Before the image is committed it asserts:

- the resulting `php -v` is the version requested;
- `extension_dir` has not moved (otherwise shared extensions would not load);
- `php -m` matches the stock image **exactly**.

That last check is the important one: PHP's extension ABI is fixed per minor
version, so UISP's bundled extensions keep working across a patch-level swap —
and the build proves it instead of assuming it.

You can confirm the same thing yourself:

```bash
diff <(docker run --rm --entrypoint php ubnt/unms-crm:4.6.13 -m) \
     <(docker run --rm --entrypoint php php2shell/unms-crm:4.6.13-php8.3.36 -m)
```

## Requirements

A UISP host with Docker and `docker compose`, and outbound HTTPS to php.net.

`install` and `remove` need root. `status` needs root or `docker` group
membership. The build compiles PHP and takes a few minutes; after that, a
re-install on the same version is cached and near-instant.

## License

MIT — see [LICENSE](LICENSE).
