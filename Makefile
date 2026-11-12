all: test vet fmt build

test:
	go test ./...

vet:
	go vet ./...

fmt:
	go list -f '{{.Dir}}' ./... | grep -v /vendor/ | xargs -L1 gofmt -l
	test -z $$(go list -f '{{.Dir}}' ./... | grep -v /vendor/ | xargs -L1 gofmt -l)

#lint:
#	go list ./... | grep -v /vendor/ | xargs -L1 golint -set_exit_status

build:
	go build -o bin/bamboohr-slack-bot ./cmd/bamboohr-slack-bot

# Builds the Debian package in bin/ inside Docker, so neither Go nor dpkg is needed locally:
#   make deb [VERSION=...] [ARCH=amd64|arm64]
# By default, the version comes from `git describe --tags`, the same as in CI:
# - on a tagged commit it's the tag, e.g. 1.1.0;
# - otherwise it's a development version, e.g. 1.0.0-15-gabc1234 means 15 commits after
#   the tag 1.0.0, at the commit abc1234.
VERSION ?= $(shell git describe --tags)
ARCH ?= amd64
GO_VERSION := $(shell sed -n 's/^go \([0-9]*\.[0-9]*\).*/\1/p' go.mod)

deb:
	docker run --rm -v "$(CURDIR):/src" -w /src \
		-v bamboohr-slack-bot-gomod:/go/pkg/mod -v bamboohr-slack-bot-gocache:/root/.cache/go-build \
		golang:$(GO_VERSION) release/build-deb.sh "$(VERSION)" "$(ARCH)"

.PHONY: all test vet fmt build deb
