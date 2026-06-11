DOCKER ?= $(or $(shell command -v docker 2>/dev/null),$(DOCKER_APP_CANDIDATE),/Applications/Docker.app/Contents/Resources/bin/docker)
DOCKER_BIN_DIR ?= $(dir $(DOCKER))
WEB_IMAGE ?= openscope-web
WEB_PORT ?= 3000

.PHONY: web-docker-build web-docker-run

web-docker-build:
	PATH="$(DOCKER_BIN_DIR):$$PATH" $(DOCKER) build -t $(WEB_IMAGE) ./web

web-docker-run:
	PATH="$(DOCKER_BIN_DIR):$$PATH" $(DOCKER) run --rm -p $(WEB_PORT):3000 $(WEB_IMAGE)

# --- Enterprise broker (Linux VPC deployment) --------------------------------
BROKER_IMAGE ?= openscope-broker
DIST_DIR ?= dist

.PHONY: broker-build-linux broker-docker-build

broker-build-linux:
	mkdir -p $(DIST_DIR)/broker-linux-amd64 $(DIST_DIR)/broker-linux-arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o $(DIST_DIR)/broker-linux-amd64/ ./cmd/openscoped ./cmd/openscope
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -o $(DIST_DIR)/broker-linux-arm64/ ./cmd/openscoped ./cmd/openscope
	for arch in amd64 arm64; do \
		cp deploy/broker/install.sh deploy/broker/openscoped.service deploy/broker/openscoped.env.example deploy/broker/logrotate.openscope $(DIST_DIR)/broker-linux-$$arch/; \
		tar -C $(DIST_DIR) -czf $(DIST_DIR)/openscope-broker_linux_$$arch.tar.gz broker-linux-$$arch; \
	done

broker-docker-build:
	PATH="$(DOCKER_BIN_DIR):$$PATH" $(DOCKER) build -f deploy/broker/Dockerfile -t $(BROKER_IMAGE) .
