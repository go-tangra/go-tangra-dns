##################################
# Stage 0: Build frontend module
##################################

FROM node:20-alpine AS frontend-builder

RUN npm install -g pnpm@9

WORKDIR /frontend
COPY frontend/package.json frontend/pnpm-lock.yaml* ./
RUN pnpm install --frozen-lockfile || pnpm install
COPY frontend/ .
RUN pnpm build

##################################
# Stage 1: Build Go executable
##################################

FROM golang:1.25-alpine AS builder

ARG APP_VERSION=1.0.0

# Enable toolchain auto-download if go.mod requests a newer patch
ENV GOTOOLCHAIN=auto

# Install build dependencies
RUN apk add --no-cache git make curl

# Install buf for proto descriptor generation
RUN curl -sSL "https://github.com/bufbuild/buf/releases/latest/download/buf-$(uname -s)-$(uname -m)" -o /usr/local/bin/buf && \
    chmod +x /usr/local/bin/buf

WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the entire source code
COPY . .

# Regenerate proto descriptor (ensures embedded descriptor.bin is always up to date)
RUN buf build -o cmd/server/assets/descriptor.bin

# Copy frontend dist into assets for go:embed
COPY --from=frontend-builder /frontend/dist cmd/server/assets/frontend-dist/

# Build the server
RUN CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64 \
    go build -ldflags "-X main.version=${APP_VERSION} -s -w" \
    -o /src/bin/dns-server \
    ./cmd/server

##################################
# Stage 2: Create runtime image
##################################

FROM alpine:3.20

ARG APP_VERSION=1.0.0

RUN apk --no-cache add ca-certificates tzdata

ENV TZ=UTC

WORKDIR /app

COPY --from=builder /src/bin/dns-server /app/bin/dns-server
COPY --from=builder /src/configs/ /app/configs/

RUN addgroup -g 1000 dns && \
    adduser -D -u 1000 -G dns dns && \
    mkdir -p /app/certs /app/data && chown -R dns:dns /app

USER dns:dns

# gRPC + HTTP ports
EXPOSE 9800 9801

CMD ["/app/bin/dns-server", "-c", "/app/configs"]

LABEL org.opencontainers.image.title="DNS Service" \
      org.opencontainers.image.description="DNS zone/record management backed by PowerDNS" \
      org.opencontainers.image.version="${APP_VERSION}"
