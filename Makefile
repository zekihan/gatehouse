GO ?= go
VERSION := $(shell cat VERSION)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build fmt lint test test/race test/integration audit container-test release-check
build:
	mkdir -p dist
	$(GO) build -trimpath -ldflags '$(LDFLAGS)' -o dist/gatehouse ./cmd/gatehouse
fmt:
	gofmt -w cmd internal tests/integration
lint:
	@test -z "$$(gofmt -l cmd internal tests/integration)" || (gofmt -l cmd internal tests/integration; exit 1)
	golangci-lint run --build-tags=integration
test:
	$(GO) test -count=1 ./...
test/race:
	$(GO) test -race -count=1 ./...
test/integration: build
	GATEHOUSE_BINARY=$(CURDIR)/dist/gatehouse $(GO) test -count=1 -tags=integration -v ./tests/integration
audit: lint test test/race test/integration
	$(GO) mod verify
container-test:
	docker build --build-arg VERSION=$(VERSION) --tag gatehouse:smoke .
	@test "$$(docker image inspect gatehouse:smoke --format '{{.Config.User}}')" = '65532:65532'
	@test "$$(docker run --rm --read-only --network none gatehouse:smoke version)" = '$(VERSION)'
	docker run --rm --read-only --network none -v '$(CURDIR)/examples:/config:ro' gatehouse:smoke validate /config/operator.yaml
release-check:
	goreleaser check
