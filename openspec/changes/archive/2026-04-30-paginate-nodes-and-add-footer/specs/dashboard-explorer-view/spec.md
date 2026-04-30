## ADDED Requirements

### Requirement: Viewport-bounded explorer layout
The explorer page SHALL fit within the browser viewport on desktop. The top nav, query bar, stats strip, and footer SHALL remain visible without page-level scrolling. Only the node-table region SHALL scroll internally when its rows overflow the available height.

#### Scenario: Footer is visible without page scroll on a 768px-tall viewport
- **WHEN** the explorer renders in a 1280×768 viewport with enough nodes to exceed the table's visible height
- **THEN** the `<footer data-testid="explorer-footer">` element SHALL be within the visible viewport without any scrolling on `document.scrollingElement`

#### Scenario: Table region scrolls internally when rows overflow
- **WHEN** the table region contains more rows than fit in its allotted height
- **THEN** scrolling SHALL occur inside the table container, not on the page; `document.scrollingElement.scrollTop` SHALL remain 0

### Requirement: Paginated node table
The node table SHALL be paginated with offset-based controls. The default page size SHALL be 25 rows, selectable from {25, 50, 100}. Pagination controls SHALL render directly below the table and SHALL include: previous-page, next-page, current page indicator, total page count, total result count, and a page-size selector. The table SHALL drive the existing `limit` and `offset` query parameters on `GET /api/v1/nodes`. Total page and total result counts SHALL be derived from the `X-Total-Count` response header.

#### Scenario: First load shows page 1 with default size
- **WHEN** the explorer loads with no prior pagination state
- **THEN** the table SHALL fetch `GET /api/v1/nodes?limit=25&offset=0&...` and render up to 25 rows; the pagination strip SHALL show "Page 1 of N · M results" where M is the value of the `X-Total-Count` header and N is `ceil(M / 25)`

#### Scenario: Next-page advances the offset
- **WHEN** the user activates the next-page control on page 1 with page size 25
- **THEN** the table SHALL refetch `GET /api/v1/nodes?limit=25&offset=25&...` and render rows for page 2

#### Scenario: Previous-page is disabled on page 1
- **WHEN** the table is on page 1
- **THEN** the previous-page control SHALL be disabled and SHALL render with `dim` colour

#### Scenario: Next-page is disabled on the last page
- **WHEN** the table is on the last page (offset + items_returned ≥ X-Total-Count)
- **THEN** the next-page control SHALL be disabled

#### Scenario: Changing page size resets to page 1
- **WHEN** the user changes the page-size selector from 25 to 100
- **THEN** the table SHALL refetch with `limit=100&offset=0` and the page indicator SHALL show "Page 1 of N"

#### Scenario: Filter or sort changes reset to page 1
- **WHEN** the user changes a filter (`risk`, `country`, `exposed`, `tor`) or activates a sort header while on a page > 1
- **THEN** the table SHALL refetch with `offset=0` and the page indicator SHALL return to "Page 1 of N"

### Requirement: Page footer with disclaimer, sources, and kbd hints
The explorer SHALL render a single bottom footer (`<footer data-testid="explorer-footer">`) containing three semantic sections: a research-only disclaimer, data-source attribution, and keyboard hints. The footer SHALL use `meta` typography in `dim` colour by default. Each kbd token SHALL render with a `surface-2` background. Source labels SHALL include "Shodan", "NVD", and "MaxMind GeoIP". The disclaimer SHALL communicate that the data is provided for security research and educational purposes only.

#### Scenario: Footer renders the three sections
- **WHEN** the explorer is rendered
- **THEN** the footer SHALL contain a kbd-hints region (including a `⌘K` token followed by the label `command palette`), a sources region listing "Shodan", "NVD", and "MaxMind GeoIP" as labels or links, and a disclaimer region whose text includes the phrase "research" (case-insensitive)

#### Scenario: Disclaimer is exposed to assistive tech
- **WHEN** a screen reader traverses the footer
- **THEN** the disclaimer text SHALL be reachable as part of the `<footer>` landmark and SHALL NOT be marked `aria-hidden`

## REMOVED Requirements

### Requirement: Footer keyboard hints
**Reason:** Superseded by the broader "Page footer with disclaimer, sources, and kbd hints" requirement. Keyboard-hint behavior is preserved as the kbd-hints section of the new requirement (including the `⌘K command palette` scenario), so no behavior is lost.

**Migration:** Implementations satisfying the old requirement automatically satisfy the kbd-hints clause of the new one; teams MUST additionally add the disclaimer and sources sections to remain compliant.
