# Makefile for DNS Service

VERSION ?= 1.0.0
GOFLAGS ?=
LDFLAGS ?= -X main.version=$(VERSION) -s -w

DNS_IMAGE_NAME ?= menta2l/dns-service
DNS_IMAGE_TAG ?= $(VERSION)
DOCKER_REGISTRY ?=

# Generate ent ORM code
.PHONY: ent
ent:
	@echo "Generating ent code..."
	@GOFLAGS=-mod=mod ent generate \
		--feature sql/modifier \
		--feature sql/upsert \
		--feature sql/lock \
		./internal/data/ent/schema

# Generate proto Go code
.PHONY: api
api:
	@echo "Generating proto code..."
	@buf generate

# Generate the OpenAPI spec embedded for registration
.PHONY: openapi
openapi:
	@echo "Generating OpenAPI spec..."
	@buf generate --template buf.openapi.gen.yaml

# Generate proto descriptor for dynamic routing / transcoding
.PHONY: descriptor
descriptor:
	@echo "Generating proto descriptor..."
	@buf build -o cmd/server/assets/descriptor.bin --exclude-source-info
	@echo "Proto descriptor generated: cmd/server/assets/descriptor.bin"

# Generate wire dependencies
.PHONY: wire
wire:
	@cd ./cmd/server && GOFLAGS=-mod=mod wire

# Generate everything
.PHONY: generate
generate: api ent descriptor openapi wire
	@echo "Generation complete!"

# Build the server binary
.PHONY: build-server
build-server:
	@echo "Building DNS server..."
	@go build $(GOFLAGS) -ldflags "$(LDFLAGS)" -o ./bin/dns-server ./cmd/server

# Run the server locally
.PHONY: run-server
run-server:
	@go run ./cmd/server -c ./configs

# Build Docker image
.PHONY: docker
docker:
	@echo "Building Docker image $(DNS_IMAGE_NAME):$(DNS_IMAGE_TAG)..."
	@docker build \
		-t $(DNS_IMAGE_NAME):$(DNS_IMAGE_TAG) \
		-t $(DNS_IMAGE_NAME):latest \
		--build-arg APP_VERSION=$(VERSION) \
		-f ./Dockerfile \
		.

# Run tests
.PHONY: test
test:
	@go test -v ./...

# Run tests with coverage
.PHONY: test-cover
test-cover:
	@go test -v -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
.PHONY: clean
clean:
	@rm -rf ./bin
	@rm -f coverage.out coverage.html
