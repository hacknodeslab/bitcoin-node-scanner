## Why

Since production moved to the `pesquisa` LXC on frodo (2026-09-18), merging to `main` deploys nothing: someone has to SSH in and run `scripts/deploy.sh`. The reason recorded in `docs/deploy-frodo.md` is that *"GitHub Actions cannot reach a container on a home LAN"*. That gap already bit us: on 2026-10-05 production was serving a frontend two PRs behind `main`, and a hand edit on the host (`docs/deploy-frodo.md`) blocked the first manual deploy attempt.

Our sibling project **alt-bitnodes** solved exactly this in September: its `deploy.yml` reaches a VM on the same home LAN over SSH **through Cloudflare Access** (`cloudflared access ssh` as the ProxyCommand, authenticated with an Access service token), gated by a GitHub environment `PRO`. `pesquisa` already runs a Cloudflare Tunnel connector (`frodo-pesquisa`), so the same pattern applies with no inbound ports opened.

The `frontend-deployment` spec is also stale: it still describes building the Next.js artifact in CI and rsyncing it to the EC2 as `ubuntu`, while today `deploy.sh` builds on the host.

## What Changes

- **New workflow `.github/workflows/deploy.yml`** ("Deploy to production"), environment **`PRO`**:
  - Triggered by `workflow_run` when the existing **CI Pipeline** completes **successfully on `main`** (so only green commits deploy), plus `workflow_dispatch` for manual redeploys.
  - Skips the deploy when every file changed since the commit currently live on the host is docs-only (`docs/**`, `openspec/**`, `*.md`); a manual dispatch always deploys.
  - Installs `cloudflared`, SSHes to `ssh-audit.hacknodes.xyz` with `ProxyCommand cloudflared access ssh --hostname %h` and the service token, and runs `scripts/deploy.sh` on the host (pull → deps → `alembic upgrade head` → restart → frontend build → restart → smoke tests). The job fails if `deploy.sh` fails.
  - `concurrency: deploy-prod` (never two deploys at once, never cancel one mid-way).
  - Writes the deployed commit and smoke-test result to the job summary.
- **Least-privilege CI key**: a dedicated SSH key for CI, installed in `deploy`'s `authorized_keys` with a **forced command** that can only run the deploy (no shell, no forwarding). The `deploy` user has `NOPASSWD: ALL` sudo, so a general-purpose key would be equivalent to root on the CT.
- **`scripts/deploy.sh`**: refuses to deploy over uncommitted changes with a clear message (instead of failing inside `git pull`), and its header no longer claims there is no CI path. No `git reset --hard`: host edits are never silently discarded.
- **Operator setup (one-off, Cloudflare + host)**, documented step by step in `docs/deploy-frodo.md`: public hostname `ssh-audit.hacknodes.xyz → ssh://localhost:22` on the existing tunnel; Zero Trust Access self-hosted app with a *Service Auth* policy and a service token; CI key + forced command; host key captured from the LAN; GitHub environment `PRO` (branch `main` only) with the secrets.
- **Spec**: `frontend-deployment` updated to the on-host build and the CI deploy path; the EC2/rsync requirements are removed.

## Capabilities

### New Capabilities
<!-- none -->

### Modified Capabilities
- `frontend-deployment`: deploys are triggered automatically from green `main` through Cloudflare Access and run `scripts/deploy.sh` on the host; the frontend is built on the host, not in CI; adds the restricted-key and docs-only-skip requirements.

## Impact

- **New**: `.github/workflows/deploy.yml`; `scripts/ci-deploy-command.sh` (the forced-command wrapper).
- **Modified**: `scripts/deploy.sh` (dirty-tree guard, header), `docs/deploy-frodo.md` (new section + "current state"), `CLAUDE.md`, `openspec/specs/frontend-deployment` (via delta).
- **External / manual**: Cloudflare dashboard (tunnel public hostname, Access app + service token), host (`authorized_keys`), GitHub (environment `PRO`, secrets). These can only be done by the owner; the workflow is inert until the secrets exist.
- **Unchanged**: application code, database, the manual `deploy.sh` path (still works for hot fixes and `--no-pull`).
- **Out of scope**: rollbacks from CI (still manual, per the runbook), deploying branches other than `main`, notifications beyond the job summary, scheduling the daily enrichment/alt-bitnodes jobs (operator crontab).
