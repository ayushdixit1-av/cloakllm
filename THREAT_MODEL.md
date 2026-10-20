# CredCloak Threat Model & Security Contract

**Target Version**: v0.1.x / v1.0.0-rc  
**Last Updated**: October 2026  
**License**: MIT  

---

## 1. System Overview & Core Purpose

CredCloak is a zero-dependency, local-first credential firewall for AI coding agents (specifically Claude Code, with compatibility for OpenAI API schemas). It intercepts outbound HTTP requests between the agent CLI and upstream LLM providers on the local loopback interface, detects sensitive credentials, replaces them with session-scoped opaque cryptographic placeholders, and reverses the placeholders in streaming tool calls and responses.

---

## 2. Trust Boundaries & Assumptions

### 2.1 What Is Trusted
* **The Local User**: Single-user ownership of the workstation, filesystem, and project workspace.
* **The Python Standard Library Runtime**: Reliance on standard Python `hashlib`, `hmac`, `http.server`, `socket`, and `urllib`.
* **The Project `.env*` Files**: Source of ground truth for registered credentials.

### 2.2 What Is Untrusted
* **The Remote LLM APIs**: Anthropic, OpenAI, or proxy intermediaries. They must never observe raw plaintext registered credentials.
* **Agent Context Windows**: Tool execution outputs, command logs, bash outputs, and prompt histories forwarded by Claude Code.
* **Adversarial / Malformed Payloads**: Payloads containing malformed JSON, prototype pollution, path traversal attempts, or unsupported structures are rejected fail-closed.

---

## 3. Explicit Threat Analysis (10 Core Dimensions)

### 1. Loopback Network Isolation & Capability Tokens
* **Binding**: CredCloak binds strictly to `127.0.0.1` on a dynamically assigned ephemeral port.
* **Capability Token**: The proxy generates a high-entropy 128-bit random token on startup and requires it in the URL path (`http://127.0.0.1:{port}/{token}/v1/...`).
* **Multi-User Warning**: On shared multi-tenant machines (e.g. shared HPC or university servers where untrusted users can inspect `ps` tables or loopback traffic), standard OS user namespace isolation or Docker containers must be enforced.

### 2. Dynamic Secret Invalidation & Workspace Races
* When `.env` files change or new secrets are registered in the vault, the internal `vault_version` increments atomically under a re-entrant lock.
* In-flight requests verify that the vault version has not changed during serialization; any concurrent registration invalidates the memoization cache and forces an immediate re-scan before upstream dispatch.

### 3. Credential Discovery & Precision Contract
* **Registered Credentials (Protected)**: High-confidence vendor prefixes (`sk-ant-`, `sk-proj-`, `ghp_`, `AKIA`, `xoxb-`, PEM blocks) and `.env*` values passing 5 heuristic validation gates (length $\ge 8$, Shannon entropy $\ge 2.8$ bits/char, token-boundary matching).
* **Explicit Non-Goal**: Unindexed, unstructured strings that lack vendor prefixes and are not defined in project `.env` files cannot be heuristically inferred without causing unacceptably high false-positive rates on normal code tokens.

### 4. Transformed & Obfuscated Secrets
* If a model or prompt transforms a placeholder into Base64, Hex, or ROT13, CredCloak **does not** perform fuzzy or heuristic reconstruction.
* Transformed tokens remain in their opaque placeholder state to prevent accidental leakage or corrupted code generation.

### 5. Inspected Request & Response Fields
* **Outbound**: Every string inside user messages, assistant turns, system prompts, tool results, tool inputs, metadata, and operational dictionaries is recursively traversed and cloaked.
* **Inbound**: Server-Sent Events (`text_delta` and `input_json_delta`) are processed through a grammar-driven hold-back buffer to rehydrate tokens split across TCP chunk boundaries and JSON escape sequences (`\u005f`, `\\_`).

### 6. Immutable & Cryptographically Signed Content Blocks
* Blocks bearing a `signature` or typed as `thinking` / `redacted_thinking` are strictly immutable.
* **Fail-Closed Policy**: If an immutable block contains a plaintext registered secret, CredCloak **strictly refuses to forward the payload** (HTTP 500 `ERR_PAYLOAD_PROCESSING_FAILED`), guaranteeing zero plaintext secret transmission without invalidating cryptographic signatures.

### 7. Upstream Dispatches on Rejected Requests
* For all rejected inputs (HTTP 400, 403, 404, 408, 413, 500), CredCloak drains up to 64KB in non-blocking mode and closes the connection.
* **Zero Dispatches**: Exactly zero HTTP bytes are dispatched to upstream provider servers on any rejected request.

### 8. Diagnostic Sanitization & Error Hygiene
* Error responses returned to clients and entries written to `~/.credcloak/events.jsonl` use generic error codes (`ERR_PAYLOAD_PROCESSING_FAILED`, `ERR_ENDPOINT_NOT_ALLOWED`).
* Raw secret values, capability tokens, and internal stack traces are strictly stripped from all log outputs.

### 9. Filesystem Operations & Scrub Recovery
* Transcript scrubbing and `.claude/settings.json` hardening perform atomic replacement (`0600` permissions) using temporary files on the same filesystem.
* Symlinks in target files, parent folders, or any ancestor directories up to root are rejected unconditionally to prevent symlink traversal attacks.

### 10. Memory Lifecycle
* Secret strings reside in process heap memory for the duration of the proxy session. While garbage collected on exit, Python does not guarantee hardware-level zeroization of freed memory blocks.
