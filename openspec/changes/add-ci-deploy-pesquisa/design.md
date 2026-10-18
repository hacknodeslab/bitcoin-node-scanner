## Context

- Production: unprivileged LXC CT 113 `pesquisa` on frodo, LAN `192.168.1.164`, user `deploy` (SSH keys, `NOPASSWD: ALL` sudo), repo `~/bitcoin-node-scanner`. `scripts/deploy.sh` does pull → venv deps → `alembic upgrade head` → restart backend → `pnpm install` + `next build` → assemble standalone → restart frontend → smoke tests (`:8000`, `:3000`, nginx `:80`). Public web via Cloudflare Tunnel `frodo-pesquisa` (connector in the CT, remotely managed with a token).
- CI: `.github/workflows/ci.yml` ("CI Pipeline") runs on push/PR to `main`/`develop`: quality & security (Bandit, ShellCheck, SonarCloud), database integration tests, frontend checks.
- Reference implementation: alt-bitnodes `deploy.yml` — `environment: PRO`, `cloudflared access ssh` ProxyCommand with `TUNNEL_SERVICE_TOKEN_ID/SECRET`, host key from a secret (the runner can't keyscan through the proxy), `git reset --hard` + installer, smoke test. Its SSH hostname is `ssh.hacknodes.xyz`, so `pesquisa` needs a different one.

## Goals / Non-Goals

**Goals:** green `main` → production without a human; no inbound ports; least privilege for the CI credential; never destroy host state silently; manual `deploy.sh` keeps working.

**Non-Goals:** CI-side rollbacks, multi-environment promotion, deploying non-`main` refs, building the frontend in CI again.

## Decisions

**1. Trigger on `workflow_run` of "CI Pipeline" (success, branch `main`, event `push`).** The deploy reuses the existing checks instead of re-running tests (alt-bitnodes runs `pytest` inside its deploy workflow). The job checks `github.event.workflow_run.conclusion == 'success'` and `head_branch == 'main'`; it deploys `workflow_run.head_sha`. `workflow_dispatch` (no inputs) deploys current `main`. *Alternative:* `push` + `needs: tests` in a single workflow — rejected: duplicates CI or forces merging the two workflow files. *Trade-off:* a red SonarCloud gate blocks deploys; that is intended (it is a required check).

**2. Deploy exactly the tested commit when possible.** The SSH command passes `EXPECTED_SHA=<head_sha>`; `deploy.sh` (unchanged logic otherwise) pulls `main` and logs a note if `HEAD` moved past `EXPECTED_SHA` (a newer commit has its own CI run and will deploy itself). It never checks out an older commit than `origin/main`.

**3. Forced-command key, not a shell.** A new ed25519 key used only by CI is installed as:

```
command="/home/deploy/bitcoin-node-scanner/scripts/ci-deploy-command.sh",no-port-forwarding,no-agent-forwarding,no-X11-forwarding,no-pty ssh-ed25519 AAAA… github-actions-deploy
```

`ci-deploy-command.sh` ignores the client's command except for a strict allow-list read from `SSH_ORIGINAL_COMMAND`: `deploy [<40-hex sha>]` and `status`. It `cd`s to the repo and execs `scripts/deploy.sh` with `EXPECTED_SHA`, or prints the contents of the deployed-commit marker (decision 5) for `status`. Anything else exits 2. *Alternative:* plain key like alt-bitnodes — rejected: `deploy` has passwordless root sudo, so a leaked CI secret would mean root on the CT.

**4. Hostname `ssh-audit.hacknodes.xyz`** on the existing `frodo-pesquisa` tunnel (`ssh://localhost:22`), protected by a Zero Trust Access *self-hosted* application with a **Service Auth** policy bound to a dedicated service token. Without the token the hostname is unusable; sshd itself stays LAN-only. *Alternative:* reuse `ssh.hacknodes.xyz` — rejected: that routes to the alt-bitnodes VM.

**5. Docs-only skip, based on the last *successful* deploy.** `deploy.sh` pulls before it builds, so the checked-out `HEAD` is not proof that a commit is live: after a failed build or migration the host sits on the new commit while production still serves the old one. Therefore `deploy.sh` writes the full commit id to a marker file `.deployed-sha` in the repo directory (git-ignored) only after all smoke tests pass, and `status` prints that marker, not `HEAD`. The runner, with full history (`fetch-depth: 0`), diffs `live..target`; if every path matches `docs/**`, `openspec/**`, `**/*.md`, it skips with a summary note. It deploys instead (fail open on the skip, never on the deploy) when: the dispatch is manual; `status` fails or the marker is missing; or `live` is not an ancestor of `target` (`git merge-base --is-ancestor`), e.g. after a `BRANCH=…` or `--no-pull` deploy. *Alternative:* `git rev-parse HEAD` — rejected: a failed deploy followed by a docs-only merge would leave production broken with a green job.

**6. Dirty tree = fail, never reset (only when pulling).** `deploy.sh` gains a guard inside the pull step, before `git fetch`: if `git status --porcelain --untracked-files=no` is non-empty, it prints the files and exits non-zero. `--no-pull` skips the guard on purpose: its job is to deploy the working tree as-is, hot fixes included, and that manual path must keep working. CI always pulls, so it always gets the guard. alt-bitnodes uses `git reset --hard`; we don't, because the host is also where hot fixes and notes get made (the 2026-10-05 `deploy-frodo.md` case) and losing them silently is worse than a failed, explained deploy.

**7. Secrets live in the `PRO` environment**, deployment branches restricted to `main`: `DEPLOY_SSH_KEY`, `DEPLOY_HOST` (`ssh-audit.hacknodes.xyz`), `DEPLOY_USER` (`deploy`), `DEPLOY_HOST_KEY` (`ssh-keyscan 192.168.1.164` from the LAN, rewritten to the public hostname), `CF_ACCESS_CLIENT_ID`, `CF_ACCESS_CLIENT_SECRET`. The workflow exits early with a clear message if any is missing, so merging this change before the operator setup is harmless.

## Risks / Trade-offs

- [Service token or key leak] → forced command limits the key to "deploy main"; the token only grants reaching sshd; rotate both from the dashboard/host.
- [Long frontend build on the CT stalls the job] → `timeout-minutes: 20`; `deploy.sh` already fails fast on errors.
- [Deploy fails half-way (e.g. migration)] → same as a manual deploy: the job is red with the log; rollback stays manual per the runbook.
- [Cloudflare outage] → CI deploy fails; manual `deploy.sh` over the LAN still works.
- [Host key changes (CT rebuilt)] → SSH fails closed; update `DEPLOY_HOST_KEY`.
- [A `--no-pull` deploy of host edits writes `.deployed-sha` for a commit plus local changes] → the next automatic run sees the dirty tree and fails with the file list, so the hot fix is not silently overwritten either way.

## Migration Plan

1. Merge (workflow inert without secrets). 2. Operator setup per the new runbook section. 3. Trigger `workflow_dispatch` once and watch it. 4. From then on, merges deploy. Rollback of the change: delete the workflow and the `authorized_keys` line, remove the Access app/hostname.

## Open Questions

- Add a required reviewer on `PRO` (manual approval per deploy)? Off by default to match alt-bitnodes; one click away in GitHub settings.
