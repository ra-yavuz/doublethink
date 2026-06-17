# Production image for doublethink: a multi-stage build that compiles a static
# binary and ships it on a minimal distroless base. Used by docker-compose.build.yml
# and by anyone who wants a self-contained image rather than the mount-from-source
# dev path (docker-compose.yml).
#
# NO WARRANTY: doublethink carries other parties' private traffic and enforces
# access to it. It is provided as is; you alone are responsible for how you deploy
# and secure it. The author is not liable for any harm, however caused.

# --- build stage ---
FROM golang:1.25-bookworm AS build
WORKDIR /src

# Cache modules first, then build.
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags=-s -o /out/doublethink ./cmd/doublethink

# --- runtime stage ---
# distroless static: no shell, no package manager, minimal attack surface, runs as
# a non-root user. The broker needs nothing but the binary and CA certs.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/doublethink /usr/bin/doublethink

# Channels on 8080 (public). The admin/pairing API binds to loopback inside the
# container and is NOT published; reach it via "docker compose exec" or an explicit
# port mapping you add deliberately. It must never be exposed off-host.
EXPOSE 8080

# State (the channel registry: public keys only, no private material) persists in
# /data, which compose mounts as a volume.
VOLUME ["/data"]

ENTRYPOINT ["/usr/bin/doublethink"]
CMD ["serve", "--addr", ":8080", "--admin-addr", "127.0.0.1:8081", "--state", "/data/state.json"]
