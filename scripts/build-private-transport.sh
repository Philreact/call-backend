#!/usr/bin/env sh
# Build once for source development; Docker builds and bundles this automatically.
set -eu
cd "$(dirname "$0")/../media"
"${QORTAL_GO_BINARY:-go}" build -trimpath -o bin/qapp-private-transport ./cmd/private-transport
