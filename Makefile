.PHONY: help test lint secrets ci bootstrap inventory validate-profiles validate-fpm \
        build-nginx build-php build-all profile-draft calibrate-remote remote matrix \
        labs-up labs-down labs-status labs-test \
        labs-fpm-up labs-fpm-down labs-fpm-status labs-fpm-smoke labs-fpm-ports labs-fpm-test \
        clean

help:                          ## Show this help
	@grep -E '^[a-zA-Z0-9_.-]+:.*##' $(MAKEFILE_LIST) | \
	  awk 'BEGIN {FS = ":.*## "}; {printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2}'

test:                          ## Run the unit test suite
	PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -v

lint:                          ## Run ruff on the Python tools and tests
	ruff check tools tests

secrets:                       ## Run gitleaks to detect leaked secrets
	gitleaks detect --source . --no-git --redact -v

ci: lint test validate-profiles validate-fpm  ## Run the fast CI checks locally

bootstrap:                     ## Fetch and pin the upstream exploit
	python3 tools/bootstrap_upstream.py

inventory:                     ## Print the profile and offset inventory
	python3 tools/php2shell_inventory.py

validate-profiles:             ## Validate every build profile against the generic schema
	python3 -c "import json, jsonschema; \
	  schema = json.load(open('profiles/schema.json')); \
	  from pathlib import Path; \
	  [jsonschema.validate(json.loads(p.read_text()), schema) or print(f'  ok  {p.name}') \
	   for p in sorted(Path('profiles').glob('*.json')) \
	   if p.name not in ('schema.json', 'fpm-schema.json')]"

validate-fpm:                  ## Validate the PHP-FPM profiles against the FPM schema
	python3 -c "import glob, json, jsonschema; \
	  s = json.load(open('profiles/fpm-schema.json')); \
	  [jsonschema.validate(json.load(open(p)), s) or print(f'  ok  {p}') \
	   for p in sorted(glob.glob('profiles/*-fpm.json'))]"

# --------------------------------------------------------------------------- #
# PHP-FPM laboratory (nginx + PHP-FPM, user prefix, no Docker)
# --------------------------------------------------------------------------- #

build-nginx:                   ## Build nginx into lab/fpm/runtime
	lab/fpm/build_nginx.sh

build-php:                     ## Build a PHP version into lab/fpm/runtime (VERSION=8.4.26)
	@test -n "$(VERSION)" || \
	  (echo "usage: make build-php VERSION=8.4.26"; exit 2)
	lab/fpm/build_php.sh "$(VERSION)"

build-all:                     ## Build several PHP versions (VERSIONS="8.4.25 8.4.26")
	@test -n "$(VERSIONS)" || \
	  (echo "usage: make build-all VERSIONS=\"8.4.25 8.4.26\""; exit 2)
	lab/fpm/build_all.sh $(VERSIONS)

profile-draft:                 ## Generate a draft FPM profile (PHP_FPM=... VERSION=...)
	@test -n "$(PHP_FPM)" -a -n "$(VERSION)" || \
	  (echo "usage: make profile-draft PHP_FPM=/path/to/php-fpm VERSION=8.4.25"; exit 2)
	python3 tools/php2shell_fpm_profile.py --php-fpm "$(PHP_FPM)" --version "$(VERSION)"

calibrate-remote:              ## Discover a profile over HTTP only (VERSION=... BASE=... BUILDER=...)
	@test -n "$(VERSION)" || \
	  (echo "usage: make calibrate-remote VERSION=8.2.34 BASE=http://127.0.0.1:8406 BUILDER=http://127.0.0.1:8407"; exit 2)
	python3 tools/php2shell_fpm.py --version "$(VERSION)" \
	  --base "$(BASE)" --builder "$(BUILDER)" calibrate

remote:                        ## Run the 100%-remote chain (VERSION=... BASE=... BUILDER=...)
	@test -n "$(VERSION)" || \
	  (echo "usage: make remote VERSION=8.2.34 BASE=http://127.0.0.1:8406 BUILDER=http://127.0.0.1:8407"; exit 2)
	python3 tools/php2shell_fpm.py --version "$(VERSION)" \
	  --base "$(BASE)" --builder "$(BUILDER)" \
	  --command "id>out/remote-$(VERSION)" --proof-file "out/remote-$(VERSION)" \
	  no-oracle

matrix:                        ## Verify the remote chain on every unpatched build
	python3 tools/php2shell_fpm_matrix.py

# --------------------------------------------------------------------------- #
# Laboratories
# --------------------------------------------------------------------------- #

labs-up:                       ## Start all local Docker laboratories (ports 8100-8106)
	python3 tools/php2shell_labs.py up

labs-down:                     ## Stop all local Docker laboratories
	python3 tools/php2shell_labs.py down

labs-status:                   ## Show Docker laboratory container status
	python3 tools/php2shell_labs.py status

labs-test:                     ## Run the dispatcher against each Docker lab
	python3 tools/php2shell_labs.py test

labs-fpm-up:                   ## Start the nginx + PHP-FPM laboratories (no Docker)
	python3 tools/php2shell_fpm_labs.py up

labs-fpm-down:                 ## Stop the nginx + PHP-FPM laboratories
	python3 tools/php2shell_fpm_labs.py down

labs-fpm-status:               ## Show FPM laboratory status
	python3 tools/php2shell_fpm_labs.py status

labs-fpm-smoke:                ## Check the FPM lab endpoints
	python3 tools/php2shell_fpm_labs.py smoke

labs-fpm-ports:                ## Print the FPM lab port map
	python3 tools/php2shell_fpm_labs.py ports

labs-fpm-test:                 ## Run primitive + endgame against the FPM lab
	python3 tools/php2shell_fpm_labs.py test

clean:                         ## Remove generated files and vendor checkout
	rm -rf vendor/php2shell-upstream
	rm -rf lab/rce/out/
	rm -rf lab/fpm/webroot/out/
