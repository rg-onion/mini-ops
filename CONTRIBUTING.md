# Contributing to Mini-Ops

Thank you for your interest in contributing to Mini-Ops! We welcome contributions from everyone.

## Getting Started

1.  **Fork the repository** on GitHub.
2.  **Clone your fork** locally:
    ```bash
    git clone https://github.com/rg-onion/mini-ops.git
    cd mini-ops
    ```
3.  **Install dependencies**:
    - Rust (`1.93.0`)
    - Node.js (`24.17.x`) and npm (`12.0.x`)

## Development Workflow

### Backend (Rust)
The backend is a monolithic Axum service.
```bash
cargo run
```

### Frontend (React)
The frontend is a Vite + React app located in `frontend/`.
```bash
cd frontend
npm ci --strict-allow-scripts
npm run dev
```

## Pull Request Process

1.  Create a new branch for your feature or bugfix:
    ```bash
    git checkout -b feature/cool-new-thing
    ```
2.  Make your changes and commit them with descriptive messages.
3.  Push your branch to your fork.
4.  Submit a Pull Request to the `master` branch of the original repository.

## Coding Standards

- **Rust**: Use `cargo fmt` and `cargo clippy` before submitting.
- **Frontend**: Run `npm run lint` (ESLint) before submitting.
- **Commits**: Use conventional commits (e.g., `feat: add new widget`, `fix: resolve crash on startup`).

For dependency changes, install `cargo-audit` and run:

```bash
node scripts/tests/check_cargo_audit.mjs
bash scripts/check_cargo_audit.sh
```

The policy wrapper keeps RustSec fail-closed while allowing only the reviewed
`spin` 0.9.8 yank with its exact checksum and dependency path. Raw
`cargo audit` remains strict and exits non-zero until that transitive package
can be removed. Any vulnerability, additional warning/yank, changed checksum,
or new direct dependent fails the wrapper and CI.

Three further RustSec advisories are ignored in `.cargo/audit.toml` by exact ID,
reviewed on 2026-11-21 with a re-review due by 2027-02-21. The wrapper pins each
affected package to its exact `Cargo.lock` name, version and checksum, so any
version change fails CI until the exception is re-reviewed or removed:

- `RUSTSEC-2026-0459` (`libsqlite3-sys` 0.30.1): the attack is local and needs a
  crafted database file plus a sibling `-wal` file; Mini-Ops only opens its own
  database. Remove after upgrading SQLx to 0.9 (requires Rust 1.94 or newer).
- `RUSTSEC-2026-0543` (`chrono` 0.4.43, unmaintained): no fixed release; direct
  dependency, a candidate for replacement with `jiff` or `time`.
- `RUSTSEC-2026-0441` (`pin-utils` 0.1.0, unmaintained): no fixed release;
  transitive dependency through `futures-util` 0.3.31.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
