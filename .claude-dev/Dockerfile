# Dev container for doublethink. Toolchain lives here, never on the host.
# Go 1.25 matches the go.mod floor (x/crypto v0.53+ requires go >= 1.25).
FROM golang:1.25-bookworm

# git + ca-certificates for module fetches and any repo-touching tests.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# Default to an interactive shell; run.sh mounts the source over /work.
CMD ["bash"]
