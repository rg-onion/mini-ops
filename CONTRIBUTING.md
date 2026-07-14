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
    - Rust (latest stable)
    - Node.js (v20+)

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
npm install
npm run dev
```

## Pull Request Process

1.  Create a new branch for your feature or bugfix:
    ```bash
    git checkout -b feature/cool-new-thing
    ```
2.  Make your changes and commit them with descriptive messages.
3.  Push your branch to your fork.
4.  Submit a Pull Request to the `main` branch of the original repository.

## Coding Standards

- **Rust**: Use `cargo fmt` and `cargo clippy` before submitting.
- **Frontend**: Use `eslint` and `prettier`.
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

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
