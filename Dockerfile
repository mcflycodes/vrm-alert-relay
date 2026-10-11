# Base images are pinned by multi-arch index digest. The build and runtime stages must use the
# same distroless release so the virtual environment matches the runtime's /usr/bin/python3.13.

FROM ghcr.io/astral-sh/uv:0.12.19@sha256:04d046b13e60d6bcec73cbc5e1cad25d680dea90c8573340950a0ac2d1aef424 AS uv

FROM gcr.io/distroless/python3-debian13:debug@sha256:ce19e13f9da2f730632bff686a681e03fd45e851a80aebe3d7a12d0c7fc149d0 AS build
COPY --from=uv /uv /usr/local/bin/uv
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

FROM gcr.io/distroless/python3-debian13:nonroot@sha256:83aa8d4f74a4d7f7cf2d472054139bef71a927b76c680c0f2e1021d6b1d6d732
LABEL org.opencontainers.image.title="vrm-alert-relay" \
      org.opencontainers.image.description="Unofficial alert relay for Victron VRM measurements. Not affiliated with or endorsed by Victron Energy." \
      org.opencontainers.image.source="https://github.com/mcflycodes/vrm-alert-relay" \
      org.opencontainers.image.licenses="MIT"
COPY --from=build /opt/venv /opt/venv
ENV PATH=/opt/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
USER 65532:65532
ENTRYPOINT ["/opt/venv/bin/vrm-alert-relay"]
