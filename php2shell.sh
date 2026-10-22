#!/usr/bin/env bash
#
# php2shell — rebuild UISP's bundled PHP at a patched patch-level.
#
#   php2shell.sh install    build the patched image and run UISP on it
#   php2shell.sh remove     restore UISP's own image
#   php2shell.sh status     report what is running, and whether it is patched
#
# Addresses CVE-2026-109618 / CVE-2026-109619 ("php2shell"), unauthenticated
# RCE in PHP, CVSSv4 9.2. This is remediation, not mitigation: it replaces the
# vulnerable binary. It is NOT a WAF rule and does not filter requests.
#
# Run it from anywhere on a UISP host. It locates the install itself.

set -euo pipefail

readonly MARK_BEGIN="# >>> php2shell >>>"
readonly MARK_END="# <<< php2shell <<<"
readonly PROJECT="unms"

# The first release of each MINOR that contains the fix. php.net's "latest
# patch of this minor" is NOT sufficient on its own: 8.1 is end-of-life and its
# latest release (8.1.34) does NOT contain the fix -- PHP shipped only a source
# backport for 7.4/8.0/8.1. Resolving latest-of-minor there would rebuild the
# same vulnerable version and report success, which is the one outcome a
# security tool must never produce. Hence an explicit floor.
php_floor() {
    case "$1" in
        8.2) echo "8.2.35" ;;
        8.3) echo "8.3.36" ;;
        8.4) echo "8.4.27" ;;
        8.5) echo "8.5.12" ;;
        *)   echo "" ;;
    esac
}

say()  { printf '  %s\n' "$*"; }
head_() { printf '\n%s\n' "$*"; }
warn() { printf '  \033[33m%s\033[0m\n' "$*" >&2; }
bad()  { printf '  \033[31m%s\033[0m\n' "$*" >&2; }
good() { printf '  \033[32m%s\033[0m\n' "$*"; }
die()  { bad "$*"; exit 1; }

require_root() {
    [ "$(id -u)" -eq 0 ] || die "must run as root (try: sudo $0 $*)"
}

# Every subcommand -- including the read-only one -- needs to talk to Docker.
#
# The socket is root:docker 0660, so a plain user without docker-group
# membership cannot use it. Checked up front and named plainly, because the
# alternative is worse than a failure: without this, the docker calls return
# empty, and `status` concludes "is the ucrm container running?" -- blaming the
# container for what is actually a permissions problem.
require_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed, or not on PATH"

    if docker info >/dev/null 2>&1; then
        return 0
    fi

    if [ "$(id -u)" -eq 0 ]; then
        die "cannot talk to the Docker daemon even as root -- is it running?"
    fi

    bad "cannot talk to the Docker daemon as $(id -un)"
    say ""
    say "  The socket is normally root:docker 0660, so this needs either:"
    say "    sudo $0 ${1:-status}"
    say "  or membership of the docker group:"
    say "    sudo usermod -aG docker $(id -un)   # then log out and back in"
    exit 1
}

# Readable-config check, separate from the Docker one so the message names the
# actual obstacle. A stock UISP install may keep /home/unms tighter than the
# host we developed against.
require_readable() {
    [ -r "$1/docker-compose.yml" ] && [ -r "$1/unms.conf" ] && return 0
    bad "cannot read $1 as $(id -un)"
    say "  UISP keeps its compose files under a restricted directory on some"
    say "  installs. Re-run with sudo."
    exit 1
}

# Locate the UISP install. unms.conf is the marker -- it is what unms-cli reads
# and it sits beside the compose files.
find_app_dir() {
    local d
    for d in "${UISP_APP_DIR:-}" /home/unms/app /opt/unms/app /usr/local/unms/app; do
        [ -n "$d" ] && [ -f "$d/unms.conf" ] && [ -f "$d/docker-compose.yml" ] && { echo "$d"; return 0; }
    done
    d="$(find / -maxdepth 5 -name unms.conf -type f 2>/dev/null | head -1)" || true
    [ -n "$d" ] && [ -f "$(dirname "$d")/docker-compose.yml" ] && { dirname "$d"; return 0; }
    return 1
}

# The image docker-compose.yml names for the ucrm service -- i.e. what UISP's
# own version system holds, independent of anything we have done.
stock_image() {
    sed -n '/^  ucrm:/,/^  [a-z]/p' "$1/docker-compose.yml" \
      | sed -n 's/^[[:space:]]*image:[[:space:]]*//p' | head -1
}

# PHP version inside an image, without needing the container to be running.
php_in_image() {
    docker run --rm --entrypoint php "$1" -r 'echo PHP_VERSION;' 2>/dev/null || true
}

php_in_container() {
    docker exec ucrm php -r 'echo PHP_VERSION;' 2>/dev/null || true
}

# Run a PHP snippet WITHOUT requiring PHP on the host.
#
# A UISP host does not necessarily have php installed -- PHP lives inside the
# container. Since Docker is already a hard requirement, the UISP image's own
# PHP is used as the JSON parser, which adds no dependency at all. Prefers the
# running container (no new process image) and falls back to the stock image.
php_run() {
    local code="$1" image="${2:-}"
    if docker exec -i ucrm php -r "$code" 2>/dev/null; then
        return 0
    fi
    [ -n "$image" ] || return 1
    docker run --rm -i --entrypoint php "$image" -r "$code" 2>/dev/null
}

# Latest patch release of a given minor, from php.net, with its sha256. The
# digest is published by php.net alongside the tarball and is verified inside
# the build -- so a tampered mirror fails the build rather than shipping.
resolve_release() {
    local minor="$1" image="${2:-}"
    local json; json="$(curl -fsS --max-time 20 "https://www.php.net/releases/?json&version=${minor}" 2>/dev/null)" || return 1
    printf '%s' "$json" | php_run '
          $d = json_decode(stream_get_contents(STDIN), true);
          $v = $d["version"] ?? "";
          if ($v === "") { exit(1); }
          $sha = "";
          foreach (($d["source"] ?? []) as $s) {
              if (($s["filename"] ?? "") === "php-$v.tar.xz") { $sha = $s["sha256"] ?? ""; }
          }
          if ($sha === "") { exit(1); }
          echo "$v $sha";
        ' "$image"
}

# Sort-based >= comparison, so 8.3.9 vs 8.3.36 orders correctly.
version_ge() {
    [ "$1" = "$2" ] && return 0
    [ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | head -1)" = "$2" ]
}

is_patched_image() {
    [ "$(docker image inspect "$1" --format '{{index .Config.Labels "tech.archous.php2shell"}}' 2>/dev/null)" = "1" ]
}

# ---------------------------------------------------------------------------
# Override file handling
#
# docker-compose.yml is REGENERATED by UISP on update, so it is never edited.
# docker-compose.override.yml is hand-maintained and survives -- but it may
# already contain the operator's own changes, so our block is delimited by
# markers and merged in, never written over the top.
#
# Every edit is validated with `docker compose config` afterwards and rolled
# back if the result does not parse. A broken compose file on a UISP host is a
# far worse outcome than a failed install.
# ---------------------------------------------------------------------------

override_path() { echo "$1/docker-compose.override.yml"; }

has_our_block() { [ -f "$1" ] && grep -qF "$MARK_BEGIN" "$1"; }

strip_our_block() {
    local f="$1"
    [ -f "$f" ] || return 0
    awk -v b="$MARK_BEGIN" -v e="$MARK_END" '
        index($0, b) { skip = 1 }
        !skip        { print }
        index($0, e) { skip = 0 }
    ' "$f" > "$f.php2shell.tmp"
    mv "$f.php2shell.tmp" "$f"
}

write_our_block() {
    local f="$1" image="$2" uisp="$3" php="$4" sha="$5"
    local block

    block="$(cat <<YAML
${MARK_BEGIN}
# Managed by php2shell. Do not edit by hand; re-run 'php2shell.sh install'.
# Removing this block and recreating the container restores UISP's own image.
  ucrm:
    image: ${image}
    build:
      context: ./php2shell
      args:
        UISP_VERSION: "${uisp}"
        PHP_VERSION: "${php}"
        PHP_SHA256: "${sha}"
${MARK_END}
YAML
)"

    if [ ! -f "$f" ]; then
        printf 'services:\n%s\n' "$block" > "$f"
        return 0
    fi

    if grep -qE '^services:' "$f"; then
        # Insert as a sibling of whatever services are already declared. A
        # second top-level `services:` key would be a duplicate mapping key,
        # which Compose resolves by discarding one of them -- silently.
        awk -v blk="$block" '
            !done && /^services:[[:space:]]*$/ { print; print blk; done = 1; next }
            { print }
        ' "$f" > "$f.php2shell.tmp"
        mv "$f.php2shell.tmp" "$f"
    else
        printf '\nservices:\n%s\n' "$block" >> "$f"
    fi
}

compose_ok() {
    ( cd "$1" && docker compose -p "$PROJECT" config >/dev/null 2>&1 )
}

# ---------------------------------------------------------------------------

cmd_install() {
    require_root install
    require_docker install
    local app; app="$(find_app_dir)" || die "no UISP install found (set UISP_APP_DIR=/path/to/app)"
    require_readable "$app"
    head_ "php2shell install"
    say "UISP install   : $app"

    local stock; stock="$(stock_image "$app")"
    [ -n "$stock" ] || die "could not read the ucrm image from docker-compose.yml"

    # The base is ALWAYS re-derived from what the box holds right now, so a
    # re-run after a UISP update corrects itself rather than pinning the old
    # version. This is why install is safe -- and necessary -- to re-run.
    local uisp_version="${stock##*:}"
    say "UISP image     : $stock"

    local cur_php; cur_php="$(php_in_container)"
    [ -n "$cur_php" ] || cur_php="$(php_in_image "$stock")"
    [ -n "$cur_php" ] || die "could not determine the PHP version UISP ships"
    local minor="${cur_php%.*}"
    say "PHP installed  : $cur_php"

    local floor; floor="$(php_floor "$minor")"
    if [ -z "$floor" ]; then
        # Two very different reasons land here, and telling an operator the
        # wrong one wastes their time during an incident. Anything below 8.2 is
        # end-of-life; anything above the newest minor we know about is simply
        # newer than this tool.
        if version_ge "8.2" "$minor" && [ "$minor" != "8.2" ]; then
            bad "PHP $minor is end-of-life -- no patched release exists."
            say ""
            say "  For CVE-2026-109618/109619 the PHP project published only a minimal"
            say "  SOURCE BACKPORT for 7.4, 8.0 and 8.1. There is no release to build,"
            say "  and this tool does not apply patches."
            say ""
            say "  Building the latest $minor would reproduce the SAME vulnerable version"
            say "  and report success. Refusing instead."
            say ""
            say "  The remedy is a UISP version built on PHP 8.2 or newer."
        else
            bad "PHP $minor is newer than this tool knows about."
            say ""
            say "  No fixed-version floor is recorded for $minor, so this tool cannot"
            say "  tell whether a build would actually contain the fix. Refusing rather"
            say "  than guessing."
            say ""
            say "  Check for a newer php2shell, or confirm by hand that UISP's PHP"
            say "  already includes the CVE-2026-109618/109619 fix."
        fi
        exit 2
    fi

    local rel target sha
    rel="$(resolve_release "$minor" "$stock")" || true
    target="${rel%% *}"; sha="${rel##* }"
    # Checked explicitly: a parser that fails can return EMPTY with status 0,
    # and an empty target would sail past `|| die` into a nonsense build arg.
    case "${target}:${sha}" in
        :*|*:) die "could not resolve the latest $minor release from php.net (network? proxy?)" ;;
    esac
    [ "$target" != "$sha" ] || die "unexpected response from php.net for $minor"

    version_ge "$target" "$floor" \
        || die "php.net's latest $minor is $target, below the fixed $floor -- refusing"

    say "PHP target     : $target (fixed at >= $floor)"

    if version_ge "$cur_php" "$floor"; then
        good "already running $cur_php, which contains the fix -- nothing to do"
        say "if a php2shell block is present, 'remove' will return UISP to stock."
        exit 0
    fi

    local image="php2shell/unms-crm:${uisp_version}-php${target}"
    say "image to build : $image"

    # Ship the build context inside the UISP app dir so `docker compose build`
    # finds it from the override's relative context.
    install -d -m 0755 "$app/php2shell"
    install -m 0644 "$(dirname "$(readlink -f "$0")")/Dockerfile" "$app/php2shell/Dockerfile"

    local ov; ov="$(override_path "$app")"
    local backup=""
    if [ -f "$ov" ]; then
        backup="$ov.php2shell-bak-$(date +%Y%m%d%H%M%S)"
        cp -a "$ov" "$backup"
        say "override backup: $backup"
        if ! has_our_block "$ov" && grep -qE '^[[:space:]]{2}ucrm:' "$ov"; then
            die "docker-compose.override.yml already defines a 'ucrm' service; refusing to touch it"
        fi
    fi

    strip_our_block "$ov"
    write_our_block "$ov" "$image" "$uisp_version" "$target" "$sha"

    if ! compose_ok "$app"; then
        bad "the resulting compose file does not parse -- rolling back"
        if [ -n "$backup" ]; then cp -a "$backup" "$ov"; else rm -f "$ov"; fi
        exit 1
    fi
    good "override written and validated"

    head_ "building $image (compiles PHP; this takes a few minutes)"
    ( cd "$app" && docker compose -p "$PROJECT" build ucrm ) || {
        bad "build failed -- rolling back the override; UISP is untouched"
        if [ -n "$backup" ]; then cp -a "$backup" "$ov"; else rm -f "$ov"; fi
        exit 1
    }

    head_ "recreating the ucrm container"
    ( cd "$app" && docker compose -p "$PROJECT" up -d ucrm --force-recreate )

    head_ "result"
    cmd_status || true
}

cmd_remove() {
    require_root remove
    require_docker remove
    local app; app="$(find_app_dir)" || die "no UISP install found (set UISP_APP_DIR=/path/to/app)"
    require_readable "$app"
    head_ "php2shell remove"
    say "UISP install   : $app"

    local ov; ov="$(override_path "$app")"
    if ! has_our_block "$ov"; then
        say "no php2shell block present"
    else
        cp -a "$ov" "$ov.php2shell-bak-$(date +%Y%m%d%H%M%S)"
        strip_our_block "$ov"
        # An override we created and that now holds nothing but 'services:'
        # is removed entirely rather than left as a confusing stub.
        if [ "$(grep -cvE '^[[:space:]]*(#.*)?$' "$ov")" -le 1 ] && grep -qE '^services:' "$ov"; then
            rm -f "$ov"
            say "override removed (it contained nothing else)"
        else
            say "php2shell block removed; your other overrides are untouched"
        fi
        compose_ok "$app" || warn "compose config does not parse -- check $ov"
    fi

    rm -rf "$app/php2shell"

    head_ "restoring UISP's own image"
    say "image          : $(stock_image "$app")"
    ( cd "$app" && docker compose -p "$PROJECT" up -d ucrm --force-recreate )

    head_ "result"
    cmd_status || true
}

cmd_status() {
    require_docker status
    local app; app="$(find_app_dir)" || die "no UISP install found (set UISP_APP_DIR=/path/to/app)"
    require_readable "$app"
    local stock running running_php ov rc=0
    stock="$(stock_image "$app")"
    running="$(docker inspect ucrm --format '{{.Config.Image}}' 2>/dev/null || echo '(not running)')"
    running_php="$(php_in_container)"
    ov="$(override_path "$app")"

    head_ "php2shell status"
    say "UISP install      : $app"
    say "UISP image (stock): $stock"
    say "container running : $running"
    say "PHP in container  : ${running_php:-(unknown)}"

    local minor="${running_php%.*}" floor=""
    [ -n "$running_php" ] && floor="$(php_floor "$minor")"

    if has_our_block "$ov"; then
        local pinned; pinned="$(sed -n 's/^[[:space:]]*UISP_VERSION:[[:space:]]*"\{0,1\}\([^"]*\)"\{0,1\}[[:space:]]*$/\1/p' "$ov" | head -1)"
        say "php2shell block   : present (UISP_VERSION=$pinned)"
        if [ "${stock##*:}" != "$pinned" ]; then
            bad "STALE: the override pins $pinned but UISP now holds ${stock##*:}"
            say "    re-run 'php2shell.sh install' to rebuild against the current version,"
            say "    or 'php2shell.sh remove' if UISP's own PHP is now patched."
            rc=1
        fi
    else
        say "php2shell block   : absent"
    fi

    if [ -z "$running_php" ]; then
        warn "cannot read PHP; is the ucrm container running?"
        return 1
    fi

    if [ -z "$floor" ]; then
        bad "VULNERABLE: PHP $minor is end-of-life and has no patched release"
        say "    only a source backport exists; update UISP to a PHP 8.2+ build"
        return 2
    fi

    if version_ge "$running_php" "$floor"; then
        good "PATCHED: PHP $running_php >= $floor"
    else
        bad "VULNERABLE: PHP $running_php < $floor (CVE-2026-109618/109619)"
        say "    run 'php2shell.sh install'"
        rc=2
    fi

    return $rc
}

case "${1:-}" in
    install) shift; cmd_install "$@" ;;
    remove|uninstall) shift; cmd_remove "$@" ;;
    status)  shift; cmd_status "$@" ;;
    *)
        cat <<USAGE
php2shell — rebuild UISP's bundled PHP at a patched patch-level
             (CVE-2026-109618 / CVE-2026-109619)

  sudo $0 install   build the patched image and run UISP on it
  sudo $0 remove    restore UISP's own image
       $0 status    report what is running, and whether it is patched

status exits 0 patched, 1 stale, 2 vulnerable — so it works as a cron or
monitoring check.

Re-run 'install' after every UISP update: it re-derives the base image from
what the box holds, so it corrects itself rather than pinning an old version.
USAGE
        exit 1 ;;
esac
