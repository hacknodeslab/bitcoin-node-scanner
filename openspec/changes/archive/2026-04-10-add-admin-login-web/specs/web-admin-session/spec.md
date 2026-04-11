## ADDED Requirements

### Requirement: Admin login form
The dashboard SHALL provide a login form in the header with username and password fields. On submit, the entered password SHALL be stored in `sessionStorage` as the API key and used for all subsequent write requests.

#### Scenario: Successful login shows admin controls
- **WHEN** user submits the login form with the correct admin password
- **THEN** the form is hidden, the "Start Scan" button becomes visible, and a logout button appears in the header

#### Scenario: Failed login shows error
- **WHEN** user submits the login form and the first authenticated request returns 401
- **THEN** an error message "Invalid credentials" is shown and sessionStorage is cleared

#### Scenario: Logout clears session
- **WHEN** user clicks the logout button
- **THEN** `sessionStorage` is cleared, the "Start Scan" button is hidden, and the login form is shown again

### Requirement: Session persists within tab
The admin session SHALL be stored in `sessionStorage` so it survives page refresh within the same tab but is cleared when the tab is closed.

#### Scenario: Session restored on page refresh
- **WHEN** the page is refreshed while an admin session is active
- **THEN** the dashboard loads in admin mode without requiring re-login

#### Scenario: Session cleared on tab close
- **WHEN** the browser tab is closed and reopened
- **THEN** the dashboard loads in public (non-admin) mode and shows the login form
