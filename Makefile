# Developer entrypoints that mirror CI 1:1. Run `make checks` before opening a PR.
#
# Gates here run identically locally and in .github/workflows/ — if `make checks`
# is green, the corresponding CI jobs are green.

.PHONY: checks docs templates test help

# Override with `make PYTHON=python checks` if your interpreter is named `python`.
PYTHON ?= python3

help:
	@echo "make checks     - run all pre-PR gates (docs, templates, test)"
	@echo "make docs       - validate documentation links, safety examples, and facts"
	@echo "make templates  - validate config templates (JSON + placeholder rules)"
	@echo "make test       - run the pytest suite"

docs:
	$(PYTHON) scripts/check_docs.py


templates:
	$(PYTHON) scripts/check_templates.py

test:
	$(PYTHON) -m pytest

checks: docs templates test
	@echo "All checks passed."
