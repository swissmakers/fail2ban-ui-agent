# Fail2ban container with integrated fail2ban-ui-agent
# Can be build from this directory by: docker build -t localhost/fail2ban-ui-agent:dev .

FROM golang:1.25.12 AS builder
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod ./
RUN go mod download
COPY . .
# TARGETARCH is set by podman/docker for each --platform slice ('amd64', 'arm64', and so on..)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build -trimpath -ldflags="-s -w" -o /out/fail2ban-ui-agent ./cmd/agent

FROM lscr.io/linuxserver/fail2ban:latest

COPY --from=builder /out/fail2ban-ui-agent /usr/local/bin/fail2ban-ui-agent
RUN chmod 755 /usr/local/bin/fail2ban-ui-agent

COPY docker/linuxserver/custom-cont-init.d/ /custom-cont-init.d/
COPY docker/linuxserver/custom-services.d/ /custom-services.d/
RUN chmod 755 /custom-cont-init.d/* /custom-services.d/* 2>/dev/null || true

# Defaults for dev compose
ENV AGENT_BIND_ADDRESS=0.0.0.0 \
    AGENT_PORT=9700

EXPOSE 9700
