## 1. Host-side scripts

- [ ] 1.1 `scripts/ci-deploy-command.sh`: forced-command wrapper reading `SSH_ORIGINAL_COMMAND`; allow only `deploy [<40-hex sha>]` and `status`; exec `scripts/deploy.sh` with `EXPECTED_SHA`; exit 2 otherwise
- [ ] 1.2 `scripts/deploy.sh`: dirty-tree guard (tracked files only) before pulling; log when `HEAD` moved past `EXPECTED_SHA`; update the header (CI path exists; `.env.example`)
- [ ] 1.3 Tests for both scripts (bats-free: pytest + subprocess on a temp git repo): wrapper allow-list and rejection, dirty-tree refusal, `EXPECTED_SHA` note; ShellCheck clean

## 2. Workflow

- [ ] 2.1 `.github/workflows/deploy.yml`: `workflow_run` on "CI Pipeline" (completed, `main`, push, success) + `workflow_dispatch`; `environment: PRO`; `concurrency: deploy-prod`, no cancel; `timeout-minutes: 20`
- [ ] 2.2 Secret presence check with a named error; install `cloudflared` from pkg.cloudflare.com; SSH config with `ProxyCommand cloudflared access ssh --hostname %h`, key and `known_hosts` from secrets
- [ ] 2.3 `status` call + docs-only diff (`fetch-depth: 0`) → skip with summary on automatic runs; deploy otherwise via `deploy <sha>`; job summary with deployed commit and outcome
- [ ] 2.4 Validate the workflow syntax (actionlint if available) and the docs-only path matcher with a small test

## 3. Docs

- [ ] 3.1 `docs/deploy-frodo.md`: new "CI deploys through Cloudflare Access" section — tunnel public hostname `ssh-audit.hacknodes.xyz → ssh://localhost:22`, Zero Trust Access app (Service Auth + service token), CI key generation and the `authorized_keys` forced-command line, `DEPLOY_HOST_KEY` capture from the LAN, GitHub environment `PRO` (branch `main`) and its secrets, first `workflow_dispatch`; update "Current state" and the "no CI deploy" wording
- [ ] 3.2 `CLAUDE.md` (deploy line) and README deploy mention

## 4. Operator setup (owner — not automatable from the repo)

- [ ] 4.1 Cloudflare: public hostname on tunnel `frodo-pesquisa`; Access application + Service Auth policy + service token
- [ ] 4.2 Host: generate CI key, add the forced-command `authorized_keys` line for `deploy`; capture host key
- [ ] 4.3 GitHub: environment `PRO` restricted to `main`, add the six secrets
- [ ] 4.4 Run `workflow_dispatch` once and confirm a green deploy; then merge something trivial and watch the automatic run
