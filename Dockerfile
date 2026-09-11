# syntax=docker/dockerfile:1
FROM golang:1.26-bookworm AS network-build

WORKDIR /src
COPY network/go.mod network/go.sum ./
RUN go mod download
COPY network/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/qapp-backend-network .

FROM debian:bookworm-slim AS network-runtime

RUN groupadd --system --gid 10001 qapp \
    && useradd --system --uid 10001 --gid qapp --home-dir /nonexistent --shell /usr/sbin/nologin qapp \
    && mkdir -p /data/network \
    && chown -R qapp:qapp /data/network

COPY --from=network-build /out/qapp-backend-network /usr/local/bin/qapp-backend-network
USER qapp
VOLUME ["/data/network"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["qapp-backend-network"]

FROM golang:1.26-bookworm AS media-build

WORKDIR /src
COPY media/go.mod media/go.sum ./
COPY media/third_party ./third_party
RUN go mod download
COPY media/*.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/qapp-call-media .

FROM debian:bookworm-slim AS media-runtime

RUN groupadd --system --gid 10001 qapp \
    && useradd --system --uid 10001 --gid qapp --home-dir /nonexistent --shell /usr/sbin/nologin qapp \
    && mkdir -p /data/backend/call-media-grants \
    && chown -R qapp:qapp /data

COPY --from=media-build /out/qapp-call-media /usr/local/bin/qapp-call-media
USER qapp
VOLUME ["/data/backend"]
ENTRYPOINT ["qapp-call-media"]

FROM ghcr.io/astral-sh/uv:python3.12-bookworm-slim AS build

ENV UV_COMPILE_BYTECODE=1 UV_LINK_MODE=copy
WORKDIR /app

COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

COPY src ./src
RUN uv sync --locked --no-dev --no-editable

FROM python:3.12-slim-bookworm AS runtime

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    RNS_CONFIG_DIR=/data/reticulum \
    BACKEND_DATA_DIR=/data/backend \
    BACKEND_IDENTITY_PATH=/data/backend/identity \
    BACKEND_DATABASE_PATH=/data/backend/backend.sqlite3

RUN groupadd --system --gid 10001 qapp \
    && useradd --system --uid 10001 --gid qapp --home-dir /nonexistent --shell /usr/sbin/nologin qapp \
    && mkdir -p /data/reticulum /data/backend /data/backups \
    && chown -R qapp:qapp /data

WORKDIR /app
COPY --from=build /app/.venv /app/.venv

USER qapp
VOLUME ["/data/reticulum", "/data/backend", "/data/backups"]
STOPSIGNAL SIGTERM
ENTRYPOINT ["qapp-backend-call"]
