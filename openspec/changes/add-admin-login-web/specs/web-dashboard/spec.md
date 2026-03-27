## MODIFIED Requirements

### Requirement: Dashboard loads without authentication
The dashboard SHALL load and display all read-only content (stats, node table, filters, sorting) without requiring any credentials. The `prompt("Enter API key:")` call SHALL be removed.

#### Scenario: Unauthenticated user sees full data
- **WHEN** a user opens the dashboard without logging in
- **THEN** stats cards, node table, filters, and sorting all work normally

#### Scenario: No credential prompt on load
- **WHEN** the page loads
- **THEN** no popup or prompt asking for an API key appears

### Requirement: Start Scan button gated on admin session
The "Start Scan" button SHALL only be visible and functional when an admin session is active. Unauthenticated users SHALL NOT see the button.

#### Scenario: Button hidden for unauthenticated users
- **WHEN** no admin session is active
- **THEN** the "Start Scan" button is not present in the DOM or is hidden

#### Scenario: Button visible for admin
- **WHEN** an admin session is active
- **THEN** the "Start Scan" button is visible and functional

### Requirement: Login/logout control in header
The header SHALL show a login form when unauthenticated and a logout button when an admin session is active.

#### Scenario: Header shows login form by default
- **WHEN** no admin session exists
- **THEN** username and password fields with a "Login" button are shown in the header

#### Scenario: Header shows logout after login
- **WHEN** admin is logged in
- **THEN** the header shows "Admin" label and a "Logout" button instead of the login form
