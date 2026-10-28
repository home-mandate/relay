# Tool versions are pinned; `go run` fetches them on first use.
STATICCHECK := honnef.co/go/tools/cmd/staticcheck@v0.8.1
GOVULNCHECK := golang.org/x/vuln/cmd/govulncheck@v1.8.0
ACTIONLINT  := github.com/rhysd/actionlint/cmd/actionlint@v1.7.12
GITLEAKS    := github.com/zricethezav/gitleaks/v8@v8.28.0

COVER_MIN := 80
FUZZTIME  ?= 15s
FUZZ_TARGETS := FuzzDecodeFrame FuzzReadFrame FuzzDecodeControl FuzzDecodeDataBind FuzzParseProxyV2 FuzzParseGatewaySPIFFEID FuzzHomeIDFromServerName
export GOWORK := off

.PHONY: check test cover vet staticcheck vulncheck actionlint secrets modverify hooks fuzz fuzz-targets

check: modverify vet staticcheck cover vulncheck actionlint secrets

test:
	go test -race -shuffle=on -count=1 ./...

cover:
	go test -race -shuffle=on -count=1 -coverprofile=cover.out ./...
	@total=$$(go tool cover -func=cover.out | awk '/^total:/ {sub("%","",$$3); print $$3}'); \
	echo "coverage $$total% (minimum $(COVER_MIN)%)"; \
	awk -v t="$$total" -v m="$(COVER_MIN)" 'BEGIN { exit (t+0 < m+0) }' || { echo "coverage below $(COVER_MIN)%"; exit 1; }

vet:
	@test -z "$$(gofmt -l .)" || { gofmt -l .; echo "gofmt needed"; exit 1; }
	go vet ./...

# staticcheck v0.8.1 cannot read Go 1.27 export data (dominikh/go-tools#1832); same workaround
# as home-mandate-cloud: a run whose only output is that error counts as a warning, anything else
# fails. REMOVAL CONDITION: delete this workaround as soon as STATICCHECK is pinned to a release
# that reads Go 1.27 export data (go-tools#1832 fixed); then a staticcheck error must fail again.
STATICCHECK_EXPORT_DATA := export data version 5 is greater than maximum supported version 4
staticcheck:
	@out=$$(go run $(STATICCHECK) ./... 2>&1); status=$$?; \
	if [ $$status -ne 0 ] && echo "$$out" | grep -qF "$(STATICCHECK_EXPORT_DATA)" && \
	   ! echo "$$out" | grep -vF -e "$(STATICCHECK_EXPORT_DATA)" -e "exit status" -e "go: downloading " | grep -q .; then \
		msg="staticcheck skipped: $(STATICCHECK) cannot read this Go version's export data (dominikh/go-tools#1832)"; \
		if [ -n "$$GITHUB_ACTIONS" ]; then echo "::warning::$$msg"; else echo "WARNING: $$msg"; fi; \
		exit 0; \
	fi; \
	[ -z "$$out" ] || echo "$$out"; exit $$status

vulncheck:
	go run $(GOVULNCHECK) ./...

actionlint:
	go run $(ACTIONLINT)

modverify:
	go mod verify
	go mod tidy -diff

# Runs every fuzz target for FUZZTIME (default 15s). Corpus seeds live in the tests.
fuzz:
	@for t in $(FUZZ_TARGETS); do \
		echo "fuzz $$t"; \
		go test ./tunnel -run '^$$' -fuzz "^$$t$$" -fuzztime $(FUZZTIME) || exit 1; \
	done

# Prints FUZZ_TARGETS as a JSON array; the scheduled workflow runs one job per target.
fuzz-targets:
	@printf '%s\n' $(FUZZ_TARGETS) | jq -R . | jq -sc .

# Installs the repository's git hooks (gitleaks on staged changes before every commit).
hooks:
	git config core.hooksPath .githooks

secrets:
	go run $(GITLEAKS) git --redact --no-banner .
