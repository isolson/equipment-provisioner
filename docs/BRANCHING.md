# Branching & Deployment Contract

`main` is the integration branch — all PRs (including the vendor-isolation refactor stories) merge there. The **`production` branch is the deploy pin**: it marks the commit running on the production host, and it is the only branch `scripts/deploy.sh` will deploy without a flag.

The host records what's deployed in `/opt/provisioner/.deployed-rev` (`<sha>[-dirty] <branch> <utc-timestamp>`, written by deploy.sh):

```bash
ssh serveradmin@192.168.10.50 cat /opt/provisioner/.deployed-rev
```

## The production contract

- Production deploys run from a checkout of `production` (keep a dedicated worktree: `git worktree add ../network-provisioner-production production`).
- `production` moves **only by fast-forward** from `main`, and only after the smoke checklist below passes on the host. Promotion:

  ```bash
  git push origin main:production   # rejected automatically if not a fast-forward
  ```

- Hardware-testing a feature branch is fine — deploy it with `./scripts/deploy.sh --allow-branch` (the flag leaves a record in shell history, and `.deployed-rev` records the branch). Re-deploy from `production` when testing is done.
- Never merge `main` into `production` or commit directly to it.

## Phase-gate promotion (refactor epics)

After a refactor phase merges to `main` (see `docs/epic-vendor-isolation-refactor.md`):

1. In the production worktree: `git pull --ff-only` after promoting, then `./scripts/deploy.sh`.
2. Run the smoke checklist. If it fails, fix forward on `main` (or revert the story PR) and redeploy — don't leave production on a failed promotion (roll back, below).

### Smoke checklist (baseline, every gate — ~15 min)

1. `systemctl is-active provisioner-web` is `active`; `journalctl -u provisioner-web --since -5min` has no tracebacks (catches the boot-crash class from missed registry sites).
2. Kiosk touchscreen renders the port grid; `curl -s localhost:8080/ports` returns the port array.
3. `curl -s localhost:8080/setup/readiness` returns OK; setup UI loads.
4. Plug in one on-hand device → detection badge appears with the correct vendor.
5. Run one full provisioning cycle to COMPLETE.

Phase-specific additions:

- **UI phase (Story 5):** vendor names/colors/icons identical to before; vendor-metadata endpoint returns all vendors.
- **Registry capstone (Story 6):** detect + provision **two different vendors**; CLI vendor list intact; firmware checker enumerates all sources without import errors.
- **Fingerprint modularization (Story 7):** detection for every vendor type on hand, MikroTik first (`:8728` short-circuit ordering is the fragile part); simple-mode detection if a no-switch unit is available.

## Deploy guardrails

`scripts/deploy.sh` enforces four guardrails so a bad tree can't quietly land on the host:

1. **Pre-deploy test gate.** The full `pytest` suite runs before anything is pushed; a failure aborts the deploy. Bypass only with `--skip-tests` (prints a warning). This is the gate that would have caught PR #98 shipping with two failing `test_setup_api.py` cases.
2. **Branch guard + loud warning.** Off-`production` deploys still require `--allow-branch`, and now print a prominent banner so a stray feature-branch deploy is never silent.
3. **Rollback snapshot.** Every deploy first copies the current on-host tree to `/opt/provisioner.prev` (excludes `venv`/`.git`). Roll back the last deploy in one command:

   ```bash
   ./scripts/deploy.sh --rollback      # restores /opt/provisioner.prev + restarts + health-checks
   ```

   (The git-based rollback below is still the way to reach an *older* revision than the immediately-previous one.)
4. **Post-deploy health check.** After the restart the script verifies the service is `active`, has no traceback/import error in the last 60s of logs, and serves `/ports`. A failure exits non-zero and prints the `--rollback` command — the deploy is not reported as successful.

## Rollback

Immediately-previous deploy: `./scripts/deploy.sh --rollback` (see guardrail 3). To reach an older revision:

```bash
cd ../network-provisioner-production
git checkout <previous-good-sha>      # see .deployed-rev history / git log production
./scripts/deploy.sh --allow-branch    # detached HEAD reports branch 'HEAD', hence the flag
```

## Hotfix flow (while refactor work is in flight on main)

1. `git checkout -b hotfix/<thing> production`
2. Fix, test. If urgent, deploy from this branch with `--allow-branch`.
3. `git checkout production && git merge --ff-only hotfix/<thing> && git push origin production`, then deploy from `production`.
4. Open a PR of the same branch into `main`; resolve any refactor-moved-the-code conflicts in the PR (production already has the fix).

## Bootstrap note (2026-06-11) — one-time exception

`production` was pinned at `cfddf15` (`isolson/tachyon-fake-upload-bug`, PR #82), which was the tree actually deployed on the host at pin time. Because PRs squash-merge, `cfddf15` will never be an ancestor of `main`, so the **first** promotion after #82 merges must be a one-time non-fast-forward reset:

```bash
git push --force-with-lease=refs/heads/production origin main:production
```

After that, the fast-forward-only rule applies, and a branch-protection rule blocking force pushes should be added to `production` (deferred until then for exactly this reason).
