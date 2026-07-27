# Developer entrypoints that mirror CI 1:1. Run `make checks` before opening a PR.
#
# Gates here run identically locally and in .github/workflows/ — if `make checks`
# is green, the corresponding CI jobs are green.

.PHONY: checks py39 templates test install-dev help

# Override with `make PYTHON=python checks` if your interpreter is named `python`.
PYTHON ?= python3

help:
	@echo "make install-dev - install test deps (do this first on a fresh box)"
	@echo "make checks     - run all pre-PR gates (py39, templates, test)"
	@echo "make py39       - fail on Python 3.10+ syntax/APIs (host runs 3.9)"
	@echo "make templates  - validate config templates (JSON + placeholder rules)"
	@echo "make test       - run the pytest suite"

py39:
	$(PYTHON) scripts/check_py39.py

templates:
	$(PYTHON) scripts/check_templates.py

test:
	$(PYTHON) -m pytest

# Same extras CI installs (.github/workflows/test.yml). Without [dev],
# test_setup_api.py and test_web_pages.py fail at *collection* (missing httpx),
# which reads as a broken repo rather than a missing install step.
install-dev:
	$(PYTHON) -m pip install -e ".[dev,web,snmp]"

checks: py39 templates test
	@echo "All checks passed."
