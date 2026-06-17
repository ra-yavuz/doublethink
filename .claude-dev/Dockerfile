# Dev container for doublethink. Toolchain lives here, never on the host.
# Go 1.25 matches the go.mod floor (x/crypto v0.53+ requires go >= 1.25).
FROM golang:1.25-bookworm

# git + ca-certificates for module fetches and any repo-touching tests.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /work

# The repo is bind-mounted from the host (a different uid), so git inside the
# container would refuse to read it ("dubious ownership"), which breaks Go's VCS
# build stamping. Mark /work safe so `go build` can stamp the revision normally.
RUN git config --global --add safe.directory /work

# Default to an interactive shell; run.sh mounts the source over /work.
CMD ["bash"]
