# Contributing to CredCloak

Thank you for your interest in contributing to **CredCloak**! As a tool protecting credentials from accidental transmission to remote AI APIs, we hold ourselves to rigorous standards of code simplicity, security invariants, and test coverage.

---

## Guiding Principles

1. **Zero Runtime Dependencies**: The core package (`credcloak`) uses **100% Python standard library**. Do not add external runtime dependencies to `project.dependencies` in `pyproject.toml`.
2. **Fail-Closed Security**: Any malformed payload, unrecognized route, or uninspected byte stream must fail closed (reject with HTTP 400/403/500 rather than forwarding uncloaked bytes).
3. **Deterministic Reproducibility**: All releases must build byte-for-byte deterministically using `SOURCE_DATE_EPOCH`.
4. **Comprehensive Test Gates**: Every bug fix or feature must include automated tests asserting that zero plaintext credentials cross loopback boundaries.

---

## Local Development Setup

### 1. Clone & Set Up Virtual Environment

```bash
git clone https://github.com/ayushdixit1-av/credcloak.git
cd credcloak

python3 -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate
```

### 2. Install Development Dependencies

```bash
pip install -e ".[dev]"
```

### 3. Run the Test Suite

CredCloak includes 56+ comprehensive automated tests (including unit, fuzz, adversarial, and real-client simulation tests):

```bash
pytest -v -rs tests/
```

### 4. Verify Package Reproducibility

```bash
export SOURCE_DATE_EPOCH=$(git log -1 --pretty=%ct)
python -m build --outdir dist
python -m build --outdir dist_rebuild
python scripts/verify_reproducibility.py dist dist_rebuild
```

---

## Pull Request Guidelines

1. **Branch Naming**: Use descriptive branch names: `fix/stream-holdback-escape`, `feat/cursor-integration`, `test/adversarial-boundaries`.
2. **Commit Style**: We follow Conventional Commits:
   - `fix(...)`: Bug fixes
   - `feat(...)`: New capabilities or CLI commands
   - `test(...)`: Additional tests or benchmark cases
   - `docs(...)`: Documentation updates
3. **Security Invariant Check**: Ensure new tests use the `InstrumentedRecordingUpstream` or `UpstreamMockServer` pattern to prove that registered secrets never appear in raw recorded upstream traffic.
4. **CI Passing**: All 9 CI jobs (Ubuntu & Windows across Python 3.10–3.13 + Package Build Verification) must be green.

---

## Reporting Vulnerabilities

Please do **NOT** submit public issues for security vulnerabilities or credential bypasses. Follow the confidential disclosure instructions in [`SECURITY.md`](SECURITY.md).
