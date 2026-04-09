DOCKER ?= $(or $(shell command -v docker 2>/dev/null),$(DOCKER_APP_CANDIDATE),/Applications/Docker.app/Contents/Resources/bin/docker)
DOCKER_BIN_DIR ?= $(dir $(DOCKER))
WEB_IMAGE ?= openscope-web
WEB_PORT ?= 3000

.PHONY: web-docker-build web-docker-run

web-docker-build:
	PATH="$(DOCKER_BIN_DIR):$$PATH" $(DOCKER) build -t $(WEB_IMAGE) ./web

web-docker-run:
	PATH="$(DOCKER_BIN_DIR):$$PATH" $(DOCKER) run --rm -p $(WEB_PORT):3000 $(WEB_IMAGE)
