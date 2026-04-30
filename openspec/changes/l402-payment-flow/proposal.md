## Why

The dashboard redesign (`redesign-dashboard-design-system`) shipped a placeholder L402 surface: `GET /api/v1/l402/example` returns a `402 Payment Required` with a hard-coded `WWW-Authenticate: L402 macaroon="<placeholder>", invoice="<placeholder>"` header, and the drawer's L402 button surfaces the challenge inline as `· l402 not yet available`. The shape of the protocol is wired end-to-end (typed `ProtectedResult<T>` discriminator on the client, header parser, button affordance) — what's missing is real macaroon issuance, real Lightning invoice generation, payment-status polling, and content unlock.

This change replaces the placeholder with a working L402 implementation so the demo endpoint actually gates real content behind a paid Lightning invoice.

## What Changes

- **Macaroon issuance**: server-side mint of macaroons with caveats matching the protected resource (path, optional expiry, optional rate-limit). Use a stable HMAC key from env (`L402_SIGNING_KEY`).
- **Invoice generation**: integrate with a Lightning node or LSP (LND, CLN, LDK, or a service like Strike / Voltage / Alby). Choice deferred to design.md.
- **Endpoint upgrade**: `GET /api/v1/l402/example` returns 402 with a real macaroon + invoice on first hit; 200 with content when the request carries a valid `Authorization: L402 <macaroon>:<preimage>` header.
- **Status polling**: a new endpoint (`GET /api/v1/l402/status/{macaroon}`) the frontend polls after presenting the invoice to detect payment without waiting for the user to retry the protected GET.
- **Frontend integration**: drawer button shows a modal/inline view with the BOLT11 invoice (QR), copy-to-clipboard, status indicator. On payment confirmation, retry the protected fetch and unlock the content.
- **Demo content**: a small piece of real content behind `/l402/example` (e.g. a curated CVE feed or a higher-resolution geo map snippet) so the unlocked state has visible value.

## Capabilities

### Modified Capabilities

- `l402-protocol`: replaces the placeholder challenge issuer with a working macaroon + invoice pipeline. `ProtectedResult<T>` continues to hold the discriminator contract; the resolved `data` is now real content.

### New Capabilities

- `lightning-payments`: integration with a Lightning node/LSP to generate invoices and observe their settled state.
- `l402-macaroons`: macaroon mint, verify, and caveat enforcement.

## Impact

- New deps on the backend: a Lightning client library + a macaroon library (e.g. `pymacaroons`).
- New env vars: `L402_SIGNING_KEY`, `LIGHTNING_BACKEND_URL`, `LIGHTNING_BACKEND_TOKEN` (or equivalent for the chosen LSP/node).
- New endpoint `GET /api/v1/l402/status/{macaroon}`.
- Updates to `src/web/l402.py` (helper) — issuer/verifier moves into a small module hierarchy.
- Frontend: `Drawer` button gains a modal for the invoice + status poll. The `fetchProtected` flow gains a retry-with-token path.
- Tests covering issuance, verification, payment-status, replay protection, and clock-skew tolerance.

## Out of Scope

- CLI parity for L402 commands — track in `align-cli-api-palette-grammar`.
- Multi-tier pricing or subscription macaroons — start with single-shot per-resource invoices.
- Custodial Lightning UX (managed wallets) — assume the operator runs their own node or uses an LSP.
