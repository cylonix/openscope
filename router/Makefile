# OpenScope router stack — convenience targets.

VERSION ?= dev
DIST_DIR ?= dist
COMPOSE  := docker compose -f deploy/docker-compose.yml

.PHONY: db-up db-down db-reset migrate verify-privacy build test \
        full-up full-down full-logs secrets release-linux smoke

db-up:
	$(COMPOSE) up -d postgres

db-down:
	$(COMPOSE) down

# Wipes the local Postgres volume. Destructive — only for local dev.
db-reset:
	$(COMPOSE) down -v
	$(MAKE) db-up
	@echo "waiting for postgres to come up..."
	@until docker exec openscope-postgres pg_isready -U openscope_admin -d openscope >/dev/null 2>&1; do sleep 1; done
	$(MAKE) migrate

# Embedded-SQL migration runner (no psql needed). Dev passwords for local use.
migrate:
	OPENSCOPE_ADMIN_DSN=postgres://openscope_admin:dev_admin_password@127.0.0.1:5432/openscope?sslmode=disable \
		go run ./cmd/openscope-migrate --set-dev-passwords

# The 6-proof privacy boundary verification — see scripts/verify_privacy.sh.
verify-privacy:
	./scripts/verify_privacy.sh

build:
	go build ./...

test:
	go test ./...

# --- Full Docker stack (postgres + migrate + router + console + dashboard) ---

full-up:
	@if [ ! -f deploy/.env ]; then \
		echo "==> generating deploy/.env"; \
		./scripts/generate_secrets.sh > deploy/.env; \
	fi
	cd deploy && docker compose --env-file .env up --build -d

full-down:
	cd deploy && docker compose --env-file .env down

full-logs:
	cd deploy && docker compose --env-file .env logs -f

# Offline smoke test: full stack with the mock provider, no AWS required.
smoke:
	./scripts/smoke.sh

# Production secret generation — redirect into your secrets store or .env.
secrets:
	./scripts/generate_secrets.sh

# Linux release tarballs: router, console, mint, migrate + systemd units.
release-linux:
	@for arch in amd64 arm64; do \
		out=$(DIST_DIR)/router-linux-$$arch; \
		mkdir -p $$out; \
		CGO_ENABLED=0 GOOS=linux GOARCH=$$arch go build -trimpath \
			-ldflags "-s -w -X main.version=$(VERSION)" -o $$out/ \
			./cmd/openscope-router ./cmd/openscope-console ./cmd/openscope-mint ./cmd/openscope-migrate; \
		cp deploy/systemd/*.service deploy/systemd/install.sh deploy/systemd/router.env.example $$out/; \
		cp configs/dlp.example.yaml $$out/; \
		tar -C $(DIST_DIR) -czf $(DIST_DIR)/openscope-router_$(VERSION)_linux_$$arch.tar.gz router-linux-$$arch; \
	done
	@ls -lh $(DIST_DIR)/*.tar.gz
