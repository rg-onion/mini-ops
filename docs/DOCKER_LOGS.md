# Docker Logs Viewing (SSE)

Functionality is implemented using Server-Sent Events (SSE) to ensure real-time updates and minimal latency.

## Backend Architecture

### Docker Service (`src/docker.rs`)
The `logs_stream` function uses the `bollard` library to connect to the Docker Socket.
- **Parameters**:
  - `since`: Unix timestamp for filtering old logs.
  - `tail`: Number of lines to load on initialization (default **1000** lines). Maximum restricted to **10,000** lines.
- **Implementation**: Uses `futures_util::Stream` for asynchronous log transmission as they appear.

### API Handler (`src/main.rs`)
The endpoint `/api/docker/containers/{id}/logs` accepts query string parameters:
- `since`: (Optional) Time filter.
- `tail`: (Optional) Limit line count. Validated on server (max 10,000).

Authorization is passed via HTTP header:
- `Authorization: Bearer <AUTH_TOKEN>`

## Frontend Architecture

### LogViewer Component (`frontend/src/components/LogViewer.tsx`)
The component manages the SSE connection lifecycle and provides search/filtering interface.

#### Key Features:
- **Search & Filter**:
  - **Instant Search**: Input field filters loaded logs "on the fly" (case-insensitive).
  - **Quick Filters**: `ERROR`, `WARN`, `INFO` buttons for rapid issue diagnosis.
  - **Optimization**: Filtering happens client-side (JavaScript memory) avoiding repeated API requests.
- **History Management**:
  - **Selection Buttons**: `100`, `1k`, `All` (Max 10000), `15m`, `1h`, `24h`.
  - **Memory Protection**: Browser stores no more than **10,000** latest lines to prevent tab freezing.
- **Search Interface**:
  - Search field focuses on text, magnifying glass icon removed to save space and avoid overlap.
  - Clear button (X) moved outside the input field.
- **Download**:
  - `Download` button saves current visible content (respecting active filter).
  - If text is selected, only the selection is saved.
- **Pause/Resume**: Stops auto-scroll but continues accumulating logs in buffer.

#### Internationalization:
- Full support (EN/RU) via `frontend/src/locales/*.json`.
- Keys: `containers.logs_control.*`.

## Security & Performance
- **Auth**: Access restricted via `AUTH_TOKEN`, checked in `auth_middleware`.
- **DoS Protection**:
  - Backend enforces `tail` limit up to 10,000 lines.
  - Frontend trims log array on overflow (FIFO).
