#!/usr/bin/env bash
# Run any command inside the doublethink dev container.
# The repo is mounted at /work; the Go build/module cache lives in named volumes
# so it does not collide with the host and is not re-resolved on every run.
#
#   .claude-dev/run.sh go build ./...
#   .claude-dev/run.sh go test ./...
#   .claude-dev/run.sh bash        # interactive shell
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="doublethink-dev"

# Build the image if it is missing or the Dockerfile changed.
if ! docker image inspect "$IMAGE" >/dev/null 2>&1; then
  docker build -t "$IMAGE" "$REPO_ROOT/.claude-dev"
fi

docker run --rm -i \
  -v "$REPO_ROOT:/work" \
  -v doublethink-go-build:/root/.cache/go-build \
  -v doublethink-go-mod:/go/pkg/mod \
  -w /work \
  -e CI=1 \
  "$IMAGE" "$@"
