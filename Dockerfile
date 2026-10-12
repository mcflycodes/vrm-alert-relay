# Base images are pinned by multi-arch index digest (ADR 0003). The runtime is assembled from
# Wolfi packages into a scratch image: Chainguard's free python image only publishes tags that
# track the newest CPython minor, so Python 3.13 comes from Wolfi's versioned python-3.13
# package instead. The build stage and the runtime root filesystem install that package in one
# step, so the virtual environment matches the runtime's /usr/bin/python3.13. Wolfi packages
# are not version-pinned, so rebuilds are not byte-identical; the SBOM records exact versions.

FROM ghcr.io/astral-sh/uv:0.13.0@sha256:cdc6093146eb3ff6a40107b38f008b789e050e77ad87865e381d9917da55a168 AS uv

FROM cgr.dev/chainguard/wolfi-base:latest@sha256:256c88bb066424045021090932d50be93c8e3f2ce3586707702a401b146f3e43 AS build
COPY --from=uv /uv /usr/local/bin/uv
# The runtime root filesystem gets no shell and no package manager: apk installs into /rootfs
# without itself, and its keys and repository list are removed afterwards. The relay user is
# UID and GID 65532, as before. The state directory is created empty and owner-only; COPY
# creates its destination with a default mode but keeps the modes of the entries it copies,
# so the directory is copied as a child of /staging.
# hadolint ignore=DL3018
RUN set -eux; \
    apk add --no-cache python-3.13-base; \
    mkdir -p /rootfs/etc/apk; \
    cp -a /etc/apk/keys /etc/apk/repositories /rootfs/etc/apk/; \
    apk add --no-cache --root /rootfs --initdb \
        wolfi-baselayout ca-certificates-bundle tzdata python-3.13-base; \
    rm -rf /rootfs/etc/apk/keys /rootfs/etc/apk/repositories /rootfs/var/cache/apk; \
    grep -q '^nonroot:' /rootfs/etc/passwd \
        || echo 'nonroot:x:65532:65532:nonroot:/home/nonroot:/sbin/nologin' >> /rootfs/etc/passwd; \
    grep -q '^nonroot:' /rootfs/etc/group || echo 'nonroot:x:65532:' >> /rootfs/etc/group; \
    install -d -o 65532 -g 65532 -m 0750 /rootfs/home/nonroot; \
    mkdir -p -m 0700 /staging/vrm-alert-relay
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_NO_CACHE=1 \
    UV_PROJECT_ENVIRONMENT=/opt/venv \
    UV_PYTHON=/usr/bin/python3.13 \
    UV_PYTHON_DOWNLOADS=never
WORKDIR /src
COPY pyproject.toml uv.lock README.md LICENSE ./
COPY src ./src
RUN ["/usr/local/bin/uv", "sync", "--locked", "--no-dev", "--no-editable"]

FROM scratch
LABEL org.opencontainers.image.title="vrm-alert-relay" \
      org.opencontainers.image.description="Unofficial alert relay for Victron VRM measurements. Not affiliated with or endorsed by Victron Energy." \
      org.opencontainers.image.source="https://github.com/mcflycodes/vrm-alert-relay" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /rootfs/ /
COPY --from=build /opt/venv /opt/venv
# The state directory belongs to the relay user and nobody else (ADR 0002). A named
# volume mounted here starts with this ownership and mode.
COPY --from=build --chown=65532:65532 /staging/ /var/lib/
ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["/opt/venv/bin/vrm-alert-relay"]
CMD ["run"]
