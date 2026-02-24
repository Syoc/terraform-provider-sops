BINARY    = terraform-provider-sops
HOSTNAME  = registry.opentofu.org
NAMESPACE = syoc
TYPE      = sops
VERSION   = 0.1.0
OS_ARCH   = $(shell go env GOOS)_$(shell go env GOARCH)

INSTALL_PATH = ~/.terraform.d/plugins/$(HOSTNAME)/$(NAMESPACE)/$(TYPE)/$(VERSION)/$(OS_ARCH)

.PHONY: default build install test testacc fmt vet

default: install

build:
	go build -o $(BINARY) .

install: build
	mkdir -p $(INSTALL_PATH)
	cp $(BINARY) $(INSTALL_PATH)/$(BINARY)

# Unit tests — no Vault required; uses an in-process mock HTTP server.
test:
	go test ./... -v -count=1

# Acceptance tests — require a running Vault instance.
#
#   vault server -dev &
#   vault secrets enable transit
#   vault write -f transit/keys/sops-test
#   make testacc VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=<root-token>
testacc:
	TF_ACC=1 go test ./internal/provider/... -v -count=1

fmt:
	gofmt -l -w .

vet:
	go vet ./...
