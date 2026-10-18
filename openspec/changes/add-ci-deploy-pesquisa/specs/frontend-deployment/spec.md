## REMOVED Requirements

### Requirement: CI builds a deployable frontend artifact on every push to main
**Reason**: Since the move to the `pesquisa` LXC on frodo (2026-09-18) the frontend is built on the host by `scripts/deploy.sh`; CI only validates it (lint, typecheck, tests, build check).
**Migration**: None for operators — `deploy.sh` runs `pnpm install` and `next build` on the host and assembles the standalone artifact there.

### Requirement: Deploy publishes the frontend artifact to the production host
**Reason**: Replaced by "Green main deploys automatically through Cloudflare Access", which runs the on-host `scripts/deploy.sh` instead of rsyncing a CI-built artifact to the decommissioned EC2.
**Migration**: Deploys happen on merge to `main` via `.github/workflows/deploy.yml`, or manually with `bash scripts/deploy.sh` on the host.

## ADDED Requirements

### Requirement: Green main deploys automatically through Cloudflare Access
A workflow `.github/workflows/deploy.yml` using the GitHub environment `PRO` SHALL deploy production when the "CI Pipeline" workflow completes successfully for a push to `main`, and on manual `workflow_dispatch`. It SHALL reach the host over SSH through Cloudflare Access (`cloudflared access ssh` with a service token) at a dedicated hostname, run `scripts/deploy.sh` on the host, and fail when `deploy.sh` fails. At most one deploy SHALL run at a time and a running deploy SHALL NOT be cancelled.

#### Scenario: Merge with green CI
- **WHEN** a commit is pushed to `main` and "CI Pipeline" concludes `success`
- **THEN** the deploy workflow SHALL run `scripts/deploy.sh` on the host for that commit and report the deployed commit in the job summary

#### Scenario: Red CI
- **WHEN** "CI Pipeline" concludes `failure` for a push to `main`
- **THEN** no deploy SHALL run

#### Scenario: Pull request
- **WHEN** "CI Pipeline" runs for a pull request
- **THEN** no deploy SHALL run

#### Scenario: Secrets not configured
- **WHEN** any of the `PRO` environment secrets is missing
- **THEN** the job SHALL stop before contacting the host with a message naming the missing secret

### Requirement: Docs-only changes skip the automatic deploy
Before deploying, the workflow SHALL ask the host for its live commit and SHALL skip the automatic deploy when every file changed between the live commit and the target matches `docs/**`, `openspec/**` or `*.md`. A manual dispatch SHALL always deploy. If the live commit cannot be determined, the workflow SHALL deploy.

#### Scenario: Documentation merge
- **WHEN** the only changes since the live commit are under `docs/` and `openspec/`
- **THEN** the workflow SHALL skip the deploy and say so in the job summary

### Requirement: CI credential restricted to deploying
The SSH key used by CI SHALL be installed on the host with a forced command (`scripts/ci-deploy-command.sh`) and with port, agent and X11 forwarding and PTY disabled. The forced command SHALL accept only `deploy` (optionally followed by a 40-hex commit id) and `status`, and SHALL reject anything else with a non-zero exit, never opening a shell.

#### Scenario: Arbitrary command refused
- **WHEN** a client using the CI key requests `bash -c id`
- **THEN** the command SHALL exit non-zero without running it

#### Scenario: Status
- **WHEN** a client using the CI key requests `status`
- **THEN** it SHALL print the commit currently checked out on the host

### Requirement: Deploy never discards host changes
`scripts/deploy.sh` SHALL refuse to deploy when the repository on the host has uncommitted changes to tracked files, listing them and exiting non-zero before pulling. It SHALL NOT reset or stash them.

#### Scenario: Hand-edited file on the host
- **WHEN** `docs/deploy-frodo.md` was modified on the host and a deploy starts (manual or CI)
- **THEN** the deploy SHALL stop with a message naming the file and leave it untouched
