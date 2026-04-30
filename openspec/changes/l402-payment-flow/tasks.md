## 1. Decisions before code

- [ ] 1.1 Pick the Lightning backend: LND, Core Lightning, LDK Node, or an LSP (Voltage / Strike / Alby). Capture the trade-off in design.md (custody, latency, ops cost, deps).
- [ ] 1.2 Pick the macaroon library and signing-key rotation policy.
- [ ] 1.3 Design the `Authorization: L402` header format expected by the verifier (RFC alignment).
- [ ] 1.4 Define the demo content for `/l402/example` (what unlocked content do we ship?).

## 2. Backend — macaroons + invoices

- [ ] 2.1 `src/web/l402/issuer.py` — mint a macaroon with caveats (path, expiry, rate-limit). Sign with `L402_SIGNING_KEY`.
- [ ] 2.2 `src/web/l402/verifier.py` — accept `Authorization: L402 <macaroon>:<preimage>`, verify signature, caveats, and that the preimage hashes to the invoice's payment hash.
- [ ] 2.3 `src/web/l402/lightning.py` — adapter for the chosen Lightning backend (`create_invoice`, `get_status`).
- [ ] 2.4 Replace the placeholder helper in the existing `src/web/l402.py` with calls into the new module hierarchy. Keep the existing `GET /api/v1/l402/example` route — its 402 response now carries a real macaroon + invoice.
- [ ] 2.5 New endpoint `GET /api/v1/l402/status/{macaroon_id}` — returns `pending`/`paid`/`expired`.

## 3. Frontend — invoice modal + retry

- [ ] 3.1 Drawer L402 button switches from inline note to modal: shows BOLT11 invoice text, QR (use `qrcode` lib), copy-to-clipboard, status indicator.
- [ ] 3.2 Status poll: `useSWR` on `/api/v1/l402/status/{id}` while modal open, 3s interval, stops on terminal state.
- [ ] 3.3 On `paid`, retry `fetchProtected` with the `Authorization: L402 <mac>:<preimage>` header and render the unlocked content in place of the modal.
- [ ] 3.4 Handle expired macaroon and clock-skew tolerance.

## 4. Tests

- [ ] 4.1 Backend issuer/verifier unit tests (round-trip, tampered macaroon, bad preimage, expired).
- [ ] 4.2 Lightning adapter integration test (mocked client; no real LN traffic in CI).
- [ ] 4.3 Frontend: modal flow with mocked SWR for status; success path renders content, expired path surfaces a re-issue affordance.

## 5. Verification

- [ ] 5.1 End-to-end manual run against testnet/regtest (documented in this change's design.md).
- [ ] 5.2 `openspec validate l402-payment-flow` passes.
