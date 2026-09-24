GO        ?= go
PKGS      := $(shell $(GO) list ./... | grep -v /ui/)
COVER_OUT := coverage.out

.PHONY: lint vuln test test-integration cover generate ui-build build build-ui image redaction-scan

lint:
	$(GO) vet ./...
	staticcheck ./...
	gosec -quiet -exclude-generated -exclude-dir=ui ./...

vuln:
	../../scripts/vulncheck.sh

test:
	$(GO) test -race -count=1 ./...

test-integration:
	$(GO) test -race -count=1 -tags integration ./internal/repo/repodb/ ./tests/integration/...

# Generated protobuf, SQL bindings (internal/store, */*db), wiring (internal/app,
# cmd) and test packages are exercised by the tagged integration suite and are
# excluded from the unit gate on purpose.
COVERPKG := $(shell $(GO) list ./... | grep -v -E '/api/|/internal/store$$|db$$|/internal/app$$|/valkeykv$$|/cmd/|/tests/|/ui|/internal/stream|/repotest' | paste -sd, -)

cover:
	$(GO) test -count=1 -coverprofile=$(COVER_OUT) -coverpkg=$(COVERPKG) $(PKGS)
	./scripts/coverage-gate.sh $(COVER_OUT)

generate:
	buf generate

# SR-002/SC-007: sentinel API keys never appear in captured output.
redaction-scan:
	./scripts/redaction-scan.sh

# Build the federated UI remote (produces ui/dist consumed by the -tags ui build).
ui-build:
	cd ui && npm ci && npm run build

# Build the service binary without the embedded UI.
build:
	$(GO) build -o bin/dnssvc ./cmd/dnssvc

# Build the service binary with the embedded UI remote (requires ui-build first).
build-ui: ui-build
	$(GO) build -tags "ui" -o bin/dnssvc ./cmd/dnssvc

# Build the container image (context is the repo root so replace directives resolve).
image:
	docker build -f Dockerfile -t dnssvc ../..

