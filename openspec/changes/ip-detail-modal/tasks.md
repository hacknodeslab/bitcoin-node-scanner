## 1. Modal HTML & CSS

- [x] 1.1 Add modal backdrop `<div id="node-modal-backdrop">` and modal container `<div id="node-modal">` with close button to `index.html` (hidden by default)
- [x] 1.2 Add CSS for backdrop (full-screen semi-transparent overlay), modal box (dark card, scrollable), close button, field labels, and two-section layout (Shodan / GeoIP)

## 2. IP Cells — Clickable

- [x] 2.1 In the `fetchNodes` table render, wrap each IP address in a `<button>` (or styled `<span>`) with `data-node-id` and `data-node-json` attributes; add pointer cursor style
- [x] 2.2 Attach a click event listener (delegated on `tbody`) that reads `data-node-id` and `data-node-json` and calls `openNodeModal(nodeId, nodeData)`

## 3. Modal JS — Open / Close

- [x] 3.1 Implement `openNodeModal(nodeId, nodeData)`: populate Shodan section from `nodeData`, show modal, then fetch `/api/v1/nodes/{nodeId}/geo` and populate GeoIP section
- [x] 3.2 Implement `closeNodeModal()`: hide modal and clear content
- [x] 3.3 Bind close button click, Escape keydown, and backdrop click to `closeNodeModal()`

## 4. Modal Content — Field Rendering

- [x] 4.1 Render Shodan fields in a labelled grid: IP, Port, Version, Protocol, Risk Level (with badge), Country (Shodan), ISP, Org, OS, Tags, Open Ports, First Seen, Last Seen
- [x] 4.2 Render GeoIP section with "Loading…" while fetching, then show Country Code and Country Name (MaxMind); show "Unavailable" on error
