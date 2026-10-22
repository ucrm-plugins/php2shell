# php2shell — rebuild UISP's bundled PHP at a patched patch-level.
#
# WHAT THIS DOES, AND DELIBERATELY DOES NOT DO
# --------------------------------------------------------------------------
# It replaces the PHP *binaries* inside Ubiquiti's `unms-crm` image with the
# same PHP MINOR at a fixed PATCH level, and changes nothing else. UISP's own
# application code, its extensions, its configuration and its entrypoint are
# untouched.
#
# It is NOT a request filter and NOT a WAF rule. After this build, `php -v`
# reports the patched version and CVE-2026-109618 / CVE-2026-109619 are gone
# from the binary. That is remediation, not mitigation.
#
# WHY ONLY THE BINARIES
# --------------------------------------------------------------------------
# PHP's extension ABI is fixed per MINOR version: every 8.3.x shares
# `no-debug-non-zts-20230831`. So the ~17 shared extensions UISP ships
# (apcu, ds, intl, pdo_pgsql, zip, ...) remain loadable against a newer 8.3.x
# without being rebuilt. Rebuilding them would mean re-deriving pecl versions
# and build flags we cannot see, for no benefit.
#
# Extensions built FROM the PHP source tree -- here `sodium`, which the stock
# configure line marks `--with-sodium=shared` -- are rebuilt by `make install`
# as part of this, which is correct: they must match the new binary.
#
# WHY THE CONFIGURE LINE IS EXTRACTED, NOT HARDCODED
# --------------------------------------------------------------------------
# `php -i` reports the exact `./configure` invocation the stock image was built
# with. Reading it at build time means one Dockerfile is correct for every UISP
# release, instead of a hardcoded list that silently drifts the first time
# Ubiquiti changes a flag. If the extraction fails, the build STOPS rather than
# falling back to a guess -- a PHP built with different flags is not the PHP
# UISP expects.

ARG UISP_VERSION
FROM ubnt/unms-crm:${UISP_VERSION}

ARG UISP_VERSION
ARG PHP_VERSION
ARG PHP_SHA256

LABEL tech.archous.php2shell="1" \
      tech.archous.php2shell.php="${PHP_VERSION}" \
      tech.archous.php2shell.base="ubnt/unms-crm:${UISP_VERSION}"

# A single layer: build deps are added, used, and removed before it is
# committed, so the patched image stays close to the stock image in size.
RUN set -eux; \
    \
    test -n "${PHP_VERSION}"; \
    test -n "${PHP_SHA256}"; \
    \
    STOCK_VERSION="$(php -r 'echo PHP_VERSION;')"; \
    STOCK_MODULES="$(php -m | sort | tr '\n' ' ')"; \
    STOCK_EXTDIR="$(php -r 'echo ini_get("extension_dir");')"; \
    echo "stock PHP      : ${STOCK_VERSION}"; \
    echo "target PHP     : ${PHP_VERSION}"; \
    \
    # Refuse to cross a minor boundary. The extension ABI argument above only
    # holds within one minor; across minors every shared .so would need
    # rebuilding and UISP's own code may not even be compatible.
    test "${STOCK_VERSION%.*}" = "${PHP_VERSION%.*}" \
        || { echo "REFUSING: ${STOCK_VERSION} -> ${PHP_VERSION} crosses a minor version"; exit 1; }; \
    \
    CONFIGURE="$(php -i | sed -n 's/^Configure Command => *//p' | sed "s|^'\./configure' *||")"; \
    test -n "${CONFIGURE}" || { echo "REFUSING: could not read the stock configure line"; exit 1; }; \
    echo "configure      : ${CONFIGURE}"; \
    \
    apk add --no-cache --virtual .php2shell-build \
        ${PHPIZE_DEPS} \
        argon2-dev \
        coreutils \
        curl-dev \
        gnu-libiconv-dev \
        libsodium-dev \
        libxml2-dev \
        linux-headers \
        oniguruma-dev \
        openssl-dev \
        readline-dev \
        sqlite-dev \
        zlib-dev \
    ; \
    \
    mkdir -p /tmp/php2shell; \
    cd /tmp/php2shell; \
    wget -q -O php.tar.xz "https://www.php.net/distributions/php-${PHP_VERSION}.tar.xz"; \
    echo "${PHP_SHA256}  php.tar.xz" | sha256sum -c -; \
    tar -xJf php.tar.xz; \
    cd "php-${PHP_VERSION}"; \
    \
    # The stock image's own CFLAGS/LDFLAGS, so the rebuild matches its
    # hardening (stack protector, PIE) rather than defaulting.
    export CFLAGS="${PHP_CFLAGS}" CPPFLAGS="${PHP_CPPFLAGS}" LDFLAGS="${PHP_LDFLAGS}"; \
    eval "./configure ${CONFIGURE}"; \
    make -j"$(nproc)"; \
    make install; \
    \
    cd /; \
    rm -rf /tmp/php2shell; \
    \
    # No strip/prune step here on purpose. It was tried and measured: /usr/local
    # is 249MB in the stock image and 250MB after this build, and the binaries
    # are the same 20MB either way -- there is nothing to reclaim. The patched
    # image is ~60MB larger than stock purely because this RUN layer re-records
    # the files `make install` rewrote, while the originals remain in the base
    # layer. That is layer accounting, not bloat in the running container, and
    # removing it would mean a multi-stage rebuild of the whole UISP image.
    \
    apk del --no-network .php2shell-build; \
    \
    # --- verification, in the build, so a bad image is never produced --------
    NEW_VERSION="$(php -r 'echo PHP_VERSION;')"; \
    test "${NEW_VERSION}" = "${PHP_VERSION}" \
        || { echo "FAILED: php reports ${NEW_VERSION}, expected ${PHP_VERSION}"; exit 1; }; \
    \
    test "$(php -r 'echo ini_get("extension_dir");')" = "${STOCK_EXTDIR}" \
        || { echo "FAILED: extension_dir moved; shared extensions would not load"; exit 1; }; \
    \
    NEW_MODULES="$(php -m | sort | tr '\n' ' ')"; \
    if [ "${NEW_MODULES}" != "${STOCK_MODULES}" ]; then \
        echo "FAILED: module set changed"; \
        echo "  stock: ${STOCK_MODULES}"; \
        echo "  built: ${NEW_MODULES}"; \
        exit 1; \
    fi; \
    \
    php-fpm -v; \
    echo "php2shell: ${STOCK_VERSION} -> ${NEW_VERSION}, ${STOCK_MODULES}"
