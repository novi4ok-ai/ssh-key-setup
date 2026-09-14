.PHONY: build build-desktop build-compatible run test test-terminal check check-desktop integration test-linux screenshot

build:
	mkdir -p dist
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o dist/ssh-key-setup ./cmd/ssh-key-setup
	cd dist && { sha256sum ssh-key-setup; if [ -f ssh-key-setup-gui ]; then sha256sum ssh-key-setup-gui; fi; } > SHA256SUMS

build-desktop: build
	go build -tags gui -trimpath -ldflags="-s -w" -o dist/ssh-key-setup-gui ./cmd/ssh-key-setup-gui
	cd dist && sha256sum ssh-key-setup ssh-key-setup-gui > SHA256SUMS

build-compatible:
	docker build --output type=local,dest=dist -f Dockerfile.desktop .

run:
	CGO_ENABLED=0 go run ./cmd/ssh-key-setup -cli

test:
	go test -race -timeout 90s ./internal/... ./cmd/ssh-key-setup

test-terminal: build
	python3 scripts/test-terminal.py

check:
	go vet ./...
	go mod verify

check-desktop: check
	go vet -tags gui ./cmd/ssh-key-setup-gui

integration:
	python3 scripts/test-openssh.py

test-linux: build
	python3 scripts/test-linux.py

screenshot:
	mkdir -p artifacts
	SSH_SETUP_SCREENSHOT=$(CURDIR)/artifacts/window.png go test -count=1 -run '^TestFormValidationAndScreenshot$$' ./internal/ui
