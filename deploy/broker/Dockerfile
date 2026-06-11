# OpenScope broker (openscoped) — enterprise VPC deployment.
#
# The broker holds the privileged credentials (SSH keys, HTTP API
# profiles) so agents on devices/CI never do. Agents authenticate with
# osk_agent_* Bearer tokens; mint them inside the container:
#
#   docker exec -it openscoped openscope agent token mint ci-runner-1
#
# Build from the repo root:
#   docker build -f deploy/broker/Dockerfile -t openscope-broker .

FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# The router/ subtree is a separate Go module — not part of this build.
RUN CGO_ENABLED=0 go build -trimpath -o /out/openscoped ./cmd/openscoped && \
    CGO_ENABLED=0 go build -trimpath -o /out/openscope ./cmd/openscope

# alpine, not distroless: the ssh executor shells out to the openssh client.
FROM alpine:3.21
RUN apk add --no-cache openssh-client ca-certificates tzdata \
    && addgroup -S openscope && adduser -S -G openscope openscope
COPY --from=build /out/openscoped /out/openscope /usr/local/bin/

# /etc/openscope        — admin configs (ssh_targets.yaml, http_profiles.yaml, …)
# /var/lib/openscope    — daemon state (tokens, policies, audit log)
RUN mkdir -p /etc/openscope /var/lib/openscope && \
    chown -R openscope:openscope /var/lib/openscope
VOLUME ["/etc/openscope", "/var/lib/openscope"]

ENV OPENSCOPE_CONFIG_DIR=/var/lib/openscope \
    OPENSCOPE_ADMIN_DIR=/etc/openscope \
    OPENSCOPE_HTTP_LISTEN=:8443

USER openscope
EXPOSE 8443
ENTRYPOINT ["/usr/local/bin/openscoped"]
