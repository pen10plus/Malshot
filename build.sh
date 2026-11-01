#!/usr/bin/env sh
set -eu
cd "$(dirname "$0")"

command -v go >/dev/null 2>&1 || {
    echo "[ERROR] Go was not found on PATH." >&2
    exit 1
}
command -v gcc >/dev/null 2>&1 || {
    echo "[ERROR] gcc was not found on PATH. Install a CGO-capable toolchain." >&2
    exit 1
}

export CGO_ENABLED=1
echo "[INFO] Building MalShot with CGO_ENABLED=${CGO_ENABLED}..."
go build -trimpath -tags deepinspection -ldflags="-s -w" -o malshot .
echo "[OK] Created $(pwd)/malshot"
