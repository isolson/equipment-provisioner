# Epic: Contribution Readiness (governance + hard-blocking conformance gates)

> Status: Proposed · Owner: TBD · Sibling epic: `docs/epic-vendor-isolation-refactor.md` · Standards: `AGENTS.md`

## Goal

Let outside humans **and coding agents** open conformant PRs against this public repo without a maintainer holding their hand. Two halves:

1. **Make the rules discoverable** — one contribution entry point that routes to the standards we already wrote (`AGENTS.md`, `CLAUDE.md`, `docs/HANDLER_DEVELOPMENT.md`, `STANDARDS.md`).
2. **Make the rules mechanical** — turn every architecture rule and "common mistake" into a **required, hard-blocking CI gate**, so a contributor (especially an agent) gets fast, deterministic feedback instead of relying on a reviewer's memory.

The bar: a contributor goes from zero to a conformant PR using only `CONTRIBUTING.md` + its links, and **every** bullet in `CLAUDE.md` → "Common Mistakes to Avoid" is covered by either a recipe or a CI gate.

## Problem (recap)

The repo has unusually strong *architecture* docs but **no contribution process** and **no enforcement**:

- **Process gap.** No `CONTRIBUTING.md`, no PR template, no issue templates, no `CODEOWNERS`, no `SECURITY.md` / `CODE_OF_CONDUCT.md` / `LICENSE` file — despite being public and declaring MIT in `pyproject.toml` (which still ships placeholder `authors = "Your Name" / "you@example.com"`).
- **Enforcement gap.** `ruff`/`black`/`mypy` are configured in `pyproject.toml` but **never run** — CI (`.github/workflows/test.yml`) runs only `pytest`. None of the load-bearing rules are checked: no guard against vendor brand strings in `base.py`, no guard against `{{placeholder}}` templates, no AST-level Python-3.9 guard (running the suite on 3.9 only catches *executed* code). The rules live in prose; nothing blocks a PR that breaks them.
- **Agent-hostile by omission.** Agents thrive on fast machine feedback. Today a wrong assumption surfaces only in human review, which is slow and inconsistent.

This epic closes the *process* and *enforcement* gaps. The *pluggability* gap (collapsing the ~10 vendor registries) is a separate, already-scoped effort — see below.

## Relationship to the vendor-isolation epic (who owns what)

This epic is a **sibling**, not an overlap, of `docs/epic-vendor-isolation-refactor.md`. Clear ownership so we don't build the same thing twice:

| Concern | Owned by | This epic's role |
|---|---|---|
| Collapse ~10 vendor registries → one `VendorSpec` | isolation epic (S2–S6) | none |
| Remove the `base.py` MikroTik brand string | isolation epic (S1) | add the **gate** that prevents reintroduction (C3) |
| **Registry-consistency test** (`tests/test_vendor_registry.py`) | isolation epic (**S0**) | **consume** it — promote it to a required check (C5); do **not** rebuild it |
| Architecture standards prose | `AGENTS.md` (exists) | link it from `CONTRIBUTING.md`; do **not** restate it |
| Public-OSS governance files | **this epic** (A1–A2) | — |
| Contribution workflow + templates | **this epic** (B1–B2) | — |
| Wire & hard-block CI (lint/type/py39/isolation/templates) | **this epic** (C1–C5) | — |

## Success criteria

1. A first-time contributor produces a conformant PR using only `CONTRIBUTING.md` + links.
2. Every `CLAUDE.md` "Common Mistake" maps to a recipe section **or** a CI gate (traceability table in `CONTRIBUTING.md`).
3. All conformance gates are **required status checks** on `main` — a PR failing any one cannot merge.
4. Public-OSS governance complete: `LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, accurate `pyproject` metadata.
5. CI runs `ruff` + `black --check` + `mypy` + the py3.9 guard + the isolation guard + the template guard, all green on the 3.9 target.

## Non-goals (scope guards)

- **Not** building the registry-consistency test or `VendorSpec` registry — those are the isolation epic's. This epic *depends on* and *promotes* them.
- **Not** restating architecture standards — `AGENTS.md` is canonical; `CONTRIBUTING.md` links, never duplicates.
- **Not** automating hardware behavior — there is no simulator. Vendor/model PRs carry a **manual hardware-verification report** (a template section); CI enforces structure/conformance, humans attest hardware.
- **Not** reformatting the existing tree to satisfy new linters in one mega-PR — C1 lands the gate; any pre-existing violations are fixed in the same PR or a tracked, narrowly-scoped cleanup, not smuggled into feature PRs.

---

## Cross-cutting considerations

1. **Hardware can't be CI-tested.** Pure-logic areas (fingerprint, firmware parsing, config deep-merge, port state, provision flow) *must* ship tests using the existing `SpyHandler` (`tests/conftest.py`) and the hand-rolled HTTP-stub pattern (`tests/test_mikrotik_contract.py` `_StubSession`/`_StubResponse`); `provisioner/handlers/mock.py` is the reference handler shape. Hardware behavior is covered by the PR's verification report.
2. **Python 3.9 target.** New gate scripts must themselves be 3.9 (`Optional[...]`/`Dict[...]`, no `match`, no `X | Y`). The py3.9 gate (C2) is *additive* to "CI runs on 3.9": it AST-scans **all** modules incl. tests and unimported code, which a runtime suite misses.
3. **CI is the only safety net.** Gates should be small, fast, dependency-light Python scripts under `scripts/` that are runnable **locally and identically in CI**, so the `CONTRIBUTING.md` "run before you PR" block reproduces CI exactly.
4. **Don't fight the isolation epic mid-flight.** The isolation refactor will move registries around. The isolation **gate** (C3) targets `base.py`/shared *flow* (vendor brand strings), which is stable; the **consistency** check stays owned by isolation-epic S0. Sequence C5 (make-required) after S0 lands so we promote the real test, not a stub.
5. **Two-path deploy.** No gate should assume `/opt` vs `/var/lib/provisioner/repo/` layout; template validation (C4) runs against the in-repo `configs/templates/` tree only. (See `AGENTS.md` §6 / `CLAUDE.md`.)
6. **Public repo hygiene.** `SECURITY.md` must state: no credentials in code/fixtures/templates (use `/var/lib/provisioner/secrets/`), no firmware binaries in PRs, private disclosure path.

---

## Stories

Each story is independently shippable as its own PR. Effort: S ≈ <½ day, M ≈ 1–2 days, L ≈ 3–5 days.

### Phase A — Public-OSS governance (no dependencies)

**A1 — LICENSE + package metadata cleanup · S · risk: none**
**Scope:** add top-level `LICENSE` (MIT, matching `pyproject`/README); replace `pyproject.toml` placeholder `authors`; verify project URLs.
**Acceptance:** `LICENSE` present; no `you@example.com`/`Your Name` strings remain; GitHub "Community Standards" shows License satisfied.

**A2 — SECURITY.md + CODE_OF_CONDUCT.md · S · risk: none**
**Scope:** `SECURITY.md` (private disclosure path; no creds/firmware/secrets in PRs — point to `/var/lib/provisioner/secrets/` per `STANDARDS.md`); `CODE_OF_CONDUCT.md` (Contributor Covenant).
**Acceptance:** both at repo root; linked from `CONTRIBUTING.md` (B1); Community Standards satisfied.

### Phase B — Contribution entry point (depends on `AGENTS.md`, which exists)

**B1 — CONTRIBUTING.md (keystone) · M · risk: none**
**Scope:** the single entry point. Contains:
- PR workflow (branch from `main`, one logical change/PR, link the issue, commit/PR style matching history).
- **"Run before you open a PR"** block, identical to CI: `ruff check .` · `black --check .` · `mypy provisioner` · `python scripts/check_py39.py` · `python scripts/check_templates.py` · `pytest`.
- **Four contribution recipes**, each a thin checklist that **links** the authoritative "Adding New Vendors or Hardware" checklist in `CLAUDE.md` (**15 sites today** — `docs/HANDLER_DEVELOPMENT.md` has the conceptual walkthrough) and never restates it. The count shrinks to a single `VendorSpec` edit once the isolation epic lands:
  1. **Add functionality** — handler-property pattern; no vendor branching in shared code; tests required.
  2. **Add a vendor** — all 15 checklist sites, calling out the **S1 boot-crash** sites (`handler_manager.py`, `handlers/__init__.py`, the `config.py`↔`main.py` credentials pair, `firmware_sources/__init__.py`, `firmware_checker.py` `SOURCE_MAP`) and the **S2 silent-break** sites (fingerprint signature, boot-ping IP, firmware pattern, `setup_tools.py` `SUPPORTED_DEVICE_TYPES` + its readiness/hint/mode dicts, CLI/API/UI lists) + `grep -rin <vendor> provisioner/ configs/` + hardware-verification report.
  3. **Add a model to an existing vendor** — model-conditional properties, firmware patterns, template, alias.
  4. **Pin a config to a specific model** — `configs/templates/{vendor}/{model}.json` + `CONFIG_MODEL_ALIASES`, deep-merge semantics, **no `{{placeholders}}`**, and the repo-dir deploy note.
- **Test bar policy** (pure-logic ⇒ tests via `SpyHandler`/HTTP-stub; hardware ⇒ verification report).
- **Traceability table:** each `CLAUDE.md` "Common Mistake" → the recipe section or CI gate (C1–C4 / isolation-S0) that covers it.
- Links `AGENTS.md` (standards), `SECURITY.md`, `CODE_OF_CONDUCT.md`.
**Acceptance:** all links resolve; the pre-PR block matches the CI job list 1:1; the traceability table has no uncovered mistake.

**B2 — PR template + issue forms + CODEOWNERS · S · risk: none**
**Scope:** `.github/pull_request_template.md` (change-type checkboxes, pre-PR checklist, **Hardware Verification** section for vendor/model PRs); `.github/ISSUE_TEMPLATE/*.yml` issue **forms** for the four scenarios (New Vendor, New Model, Pin Config, Feature/Bug) — structured so agent submissions are parseable; `CODEOWNERS` routing `provisioner/handlers/*` and shared modules (`base.py`, `fingerprint.py`, `port_manager.py`, `config_store.py`) to the maintainer.
**Acceptance:** opening a PR/issue shows the templates; CODEOWNERS auto-requests review.

### Phase C — Wired, hard-blocking CI enforcement

Implement each as a separate required check; each is a `scripts/` entrypoint runnable locally.

**C1 — Lint / format / type job · S · risk: low**
**Scope:** CI job running `ruff check .`, `black --check .`, `mypy provisioner` (already declared in `[project.optional-dependencies].dev`, never executed). Fix any pre-existing violations in the same PR (see non-goal #4).
**Acceptance:** job runs on push + PR; fails on any violation; tree is clean.

**C2 — Python 3.9 compatibility gate · M · risk: low**
**Scope:** `scripts/check_py39.py` AST-walks `provisioner/` + `tests/` and fails on `match`/`case`, PEP 604 unions in annotations (`X | Y`), `datetime.UTC`, `str.removeprefix`/`removesuffix`; backed by `compileall`. Set `[tool.ruff] target-version = "py39"` and `[tool.black] target-version = ["py39"]`; align the contradictory `pyproject` classifiers (currently advertise py310–312 against a hard-3.9 runtime).
**Acceptance:** a deliberate `match` in any module (incl. an unimported one) fails the gate locally and in CI.

**C3 — Vendor-isolation gate · M · risk: low**
**Scope:** `scripts/check_vendor_isolation.py` (or pytest) fails if shared modules — `base.py`, `port_manager.py`, `fingerprint.py`'s flow, `config_store.py` — contain vendor brand strings / concrete-handler references in flow logic, beyond the sanctioned surface. **Complements** isolation-epic S1: until S1 removes the known `base.py:395-403` MikroTik stray, the gate carries a single, commented allowlist entry that S1's PR deletes.
**Acceptance:** adding `if device_type == "cambium"` to `base.py` fails the gate; the allowlist shrinks to empty once S1 lands.

**C4 — Config-template validation gate (incl. remediating existing placeholders) · M · risk: low-med**
**Prereq finding — the current tree is NOT clean.** 6 templates already carry dead `{{placeholder}}` values — `configs/templates/{cambium,tachyon}/{ap,ptp-a,ptp-b}.json` (`{{ssid}}`, `{{hostname}}`) — and the two `ap.json` files even claim in a `_comment` that "Values with {{placeholders}} are auto-replaced." There is **no** substitution engine (`CLAUDE.md` / `AGENTS.md` §4), so deep-merge would write the literal `{{ssid}}`/`{{hostname}}` strings onto devices. These are stale and contradict the architecture. The gate therefore **cannot go green without remediating them first** — this is in scope, not a follow-up.
**Scope:**
1. **Remediate the 6 templates.** Per-device values (hostname/ssid) don't belong in a shared template under deep-merge — drop those keys (they come from `configs/overrides/{MAC}.json`) or replace with real static values from a device export; fix the misleading `_comment` text.
2. Add `scripts/check_templates.py`: parse every file under `configs/templates/` by extension (`.json`/`.yaml`/`.rsc`), failing on parse errors and on any `{{ }}` syntax (including inside `_comment`).
3. If any template genuinely can't be resolved without hardware/maintainer input, park it in a **temporary, commented allowlist** with a linked tracking issue — the gate still blocks **new** placeholders, and the allowlist must reach **empty before C5**.
**Acceptance:** gate is **green against the current tree** (allowlist empty, or every entry linked to a tracking issue); a newly-introduced `{{ssid}}` fails the gate.

**C5 — Make all checks required on `main` (capstone) · S · risk: low**
**Scope:** after C1–C4 **and** the isolation epic's S0 registry-consistency test are green on `main`, configure branch protection / required status checks so none can merge without every gate passing. This is what turns "configured" into "hard block."
**Dependency:** isolation-epic **S0** must exist (we promote the real consistency test, not a placeholder); C4's template-placeholder allowlist must be **empty**.
**Acceptance:** a PR failing any single gate cannot be merged.

---

## Recommended sequence

```
Phase A:  A1   A2                         (parallel, land first)
Phase B:  B1 ──► B2                        (B1 keystone; references C-gate commands)
Phase C:  C1   C2   C3   C4                (parallel; C3 coordinates with isolation S1)
              └────────────┴──► C5 (capstone, requires C1–C4 + isolation S0 green)
```

- **Phase A** is pure governance — zero risk, immediate public-repo hygiene win.
- **Phase B** makes the rules discoverable; B1 is the keystone everything links to.
- **Phase C** makes them mechanical; C1/C2/C4 are independent, C3 coordinates with isolation-S1, C5 is the capstone that requires the isolation epic's S0 to have landed.

## Risks & mitigations

| Risk | Mitigation |
|---|---|
| C1 surfaces a wave of pre-existing lint/type debt | Fix in C1's own PR or a tracked narrow cleanup; never bundle into feature PRs (non-goal #4) |
| C4 can't go green — 6 existing templates carry dead `{{placeholders}}` | C4 explicitly includes remediating them; residual cases use a tracked allowlist that must empty before C5 |
| Isolation refactor moves registries, breaking C3's assumptions | C3 targets stable `base.py`/shared *flow*, not the registries; consistency stays owned by isolation-S0 |
| Promoting required checks before isolation-S0 exists | C5 explicitly depends on S0; sequence it last |
| Hard-block gates frustrate contributors | `CONTRIBUTING.md` pre-PR block reproduces CI exactly, so failures are caught locally first |
| Python 3.10+ syntax slips into unimported code | C2 AST-scans the whole tree, not just executed paths |
| Duplicating the isolation epic's work | Ownership table above; this epic consumes, never rebuilds, S0/S1/`AGENTS.md`/`VendorSpec` |

## Definition of done (epic)

- A1, A2, B1, B2, C1–C4 merged; CI green on the 3.9 target.
- `CONTRIBUTING.md` routes a contributor to a conformant PR; its traceability table leaves no "Common Mistake" uncovered.
- All gates (C1–C4 + isolation-S0 consistency test) are **required status checks** on `main` (C5).
- Public-OSS governance complete (`LICENSE`, `SECURITY.md`, `CODE_OF_CONDUCT.md`, `CODEOWNERS`, clean `pyproject` metadata); GitHub Community Standards fully satisfied.
- A coding agent can follow `CONTRIBUTING.md` + `AGENTS.md` to add a trivial model or pin a config and pass every gate **without human correction** — the real test that the conventions are now machine-enforced.

---

## Filing this as a GitHub epic

GitHub has no native "epic" object; the convention is one **parent tracking issue** owning this narrative, with each story (A1–C5) as its **own independently-shippable issue** linked via **native sub-issues** (not `- [ ] #123` task lists), tagged with an `epic` label. Keep this doc in-repo as the detail; the issue tracks state. Order the sub-issues by the sequence above so the board reads as a plan. Cross-link the sibling epic (`docs/epic-vendor-isolation-refactor.md`) from the parent issue, and note the C5 ⇢ isolation-S0 dependency across the two epics.
