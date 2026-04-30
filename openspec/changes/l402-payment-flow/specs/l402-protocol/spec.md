## MODIFIED Requirements

### Requirement: L402 challenge issuance

The protected endpoint `GET /api/v1/l402/example` SHALL issue a real macaroon and a real BOLT11 Lightning invoice on the 402 challenge, replacing the placeholder values shipped in `redesign-dashboard-design-system`.

#### Scenario: First hit, no Authorization header

- **WHEN** a client requests `GET /api/v1/l402/example` without an `Authorization: L402 …` header
- **THEN** the server returns 402 with `WWW-Authenticate: L402 macaroon="<base64>", invoice="<bolt11>"`
- **AND** the macaroon is signed with `L402_SIGNING_KEY` and carries caveats binding it to the path and an expiry
- **AND** the invoice is created via the configured Lightning backend

### Requirement: L402 verification

The protected endpoint SHALL verify a presented macaroon and preimage and return the resource's content when both are valid.

#### Scenario: Valid macaroon and matching preimage

- **WHEN** a client retries `GET /api/v1/l402/example` with `Authorization: L402 <macaroon>:<preimage>`
- **AND** the macaroon signature, caveats, and expiry are valid
- **AND** the preimage hashes to the invoice's payment hash
- **THEN** the server returns 200 with the unlocked content

#### Scenario: Tampered macaroon

- **WHEN** the macaroon's signature is invalid
- **THEN** the server returns 402 with a fresh challenge

#### Scenario: Wrong preimage

- **WHEN** the preimage does not hash to the invoice's payment hash
- **THEN** the server returns 402 with a fresh challenge

## ADDED Requirements

### Requirement: L402 payment status polling

The web API SHALL expose a status endpoint so the dashboard can detect payment without retrying the protected GET on a timer.

#### Scenario: Pending payment

- **WHEN** a client requests `GET /api/v1/l402/status/{macaroon_id}` for an unpaid invoice
- **THEN** the server returns 200 with `{"status":"pending"}`

#### Scenario: Paid payment

- **WHEN** the underlying Lightning backend reports the invoice as settled
- **THEN** the next request returns 200 with `{"status":"paid","preimage":"<hex>"}`

#### Scenario: Expired invoice

- **WHEN** the invoice has expired without payment
- **THEN** the server returns 200 with `{"status":"expired"}`
