# CloakLLM (`cloakllm`)

**Audit what Claude Code already leaked in `~/.claude` — and cloak your project secrets in real time before they ever leave your machine.**

[![Zero Dependencies](https://img.shields.io/badge/dependencies-zero%20(100%25%20Python%20stdlib)-success)](#install)
[![Tests](https://img.shields.io/badge/tests-16%2F16%20passing-brightgreen)](#reproducible-benchmarks)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Every time Claude Code reads a config file, inspects test output, or runs a shell command that prints environment variables, those plaintext credentials are sent to the upstream API and persisted in `~/.claude/projects/**/*.jsonl` on disk.

**CloakLLM** is a zero-dependency, local-first credential firewall for Claude Code with three layers of defense:

1. **`cloakllm audit` & `cloakllm scrub` (100% Offline, Stdlib-Only)**: Scan your local `~/.claude` transcripts against your project `.env*` files and high-precision credential prefixes (`sk-ant-`, `sk-proj-`, `ghp_`, `AKIA`, `xoxb-`, PEM blocks). Atomically redact historical leaks in-place (`0600` permissions, zero `.bak` files left behind).
2. **`cloakllm harden`**: Inject `Read(./.env)` / `Read(**/*.pem)` deny rules into `.claude/settings.json` while keeping `.env.example` readable.
3. **`cloakllm run -- claude` (Fail-Closed Bidirectional Cloaking Proxy)**: Replaces every secret in outbound `/v1/messages` and `/v1/messages/count_tokens` requests with deterministic, 128-bit session-scoped placeholders (`CLOAKv1_<CATEGORY>_<32HEX>`) and seamlessly rehydrates them in inbound SSE `text_delta` and `input_json_delta` tool-call streams before they reach Claude Code.

---

## Quickstart (30 Seconds, Zero Dependencies)

```bash
pip install .
```

### 1. Audit your local `~/.claude` transcripts (100% offline)

```bash
cloakllm audit
```

```text
CloakLLM v0.1.0 -- Offline Claude Code Transcript Audit
================================================================
  Transcripts scanned : 14 files (8,412 lines)
  .env secrets indexed: 9 high-confidence credentials
----------------------------------------------------------------
  STATUS: LEAKS DETECTED (4 plaintext secret occurrences)

  Breakdown by Category:
    - DB          : 2 leak(s)
    - ANTHROPIC   : 1 leak(s)
    - STRIPE      : 1 leak(s)

  Sample Findings (masked for terminal safety):
    [DB] session-8a2f.jsonl:114 (.env:DATABASE_URL) -> MyProd...99!@
    [ANTHROPIC] session-8a2f.jsonl:209 (prefix:ANTHROPIC) -> sk-ant...4jK6
    [STRIPE] session-1c9d.jsonl:42 (.env:STRIPE_SECRET_KEY) -> sk_liv...3tY5
```

### 2. Scrub leaked transcripts & harden `.claude/settings.json`

```bash
cloakllm scrub
cloakllm harden
```

### 3. Run Claude Code behind the live bidirectional cloaking proxy

```bash
cloakllm run -- claude
```

In another terminal, inspect real-time redaction and rehydration counters without disturbing the interactive TUI:

```bash
cloakllm status
```

---

## How It Works

```text
┌──────────────────┐   1. Outbound POST /v1/messages (+ /count_tokens)   ┌───────────────────────────────┐
│                  │ ──────────────────────────────────────────────────► │  CloakLLM Local Proxy         │
│   Claude Code    │      Contains real .env password / API key          │  http://127.0.0.1:PORT/<tok>  │
│  (Child Process) │                                                     │                               │
│                  │ ◄────────────────────────────────────────────────── │  • Strict Route Allowlist     │
└──────────────────┘   4. Rehydrated SSE Stream (text + tool JSON)       │  • 128-bit HMAC Token Vault   │
                          Real secret restored locally for tool execution└──────────────┬────────────────┘
                                                                                        │
                                              2. Cloaked Request                        │ 3. Upstream SSE Stream
                                                 `CLOAKv1_DB_9F2A1C04...`               │    Emits `CLOAKv1_DB_...`
                                                 (Prompt-cache stable 128-bit HMAC)     ▼
                                                                         ┌───────────────────────────────┐
                                                                         │    api.anthropic.com          │
                                                                         │    Never sees raw secret      │
                                                                         └───────────────────────────────┘
```

### Key Engineering Highlights

- **5-Gate `.env` Loader (`cloakllm/secrets.py`)**:
  - **Gate 1 (Public Denylist)**: Ignores `NEXT_PUBLIC_*`, `VITE_*`, `*PUBLIC*`, `*PUBLISHABLE*`, `_KEY_ID`, `_KEY_PATH`, and `pk_live_` / `pk_test_` values. Skips `.env.example`, `.env.sample`, `.env.template`.
  - **Gate 2 (Token-Boundary Key Matching)**: Matches `KEY`, `SECRET`, `TOKEN`, `PASSWORD`, `PRIVATE`, `WEBHOOK`, `DSN` on `_` token boundaries (never false-positives on `AUTHOR`, `MONKEY`, or `BYPASS`).
  - **Gate 3 (Surgical URL Credential Extraction)**: Plain URLs (`API_URL=https://api.stripe.com/v1`) are ignored even when their Shannon entropy exceeds `2.8 bits/char`. For connection strings (`DATABASE_URL=postgresql://user:pass@host:5432/db`), CloakLLM extracts and cloaks **only the password/token component**, leaving the host, port, and database name visible to the model.
  - **Gate 4 (Entropy & Value Quality)**: Requires length $\ge 12$ ($\ge 8$ with $\ge 2$ character classes for passwords) and Shannon entropy $\ge 2.8\text{ bits/char}$.
  - **Gate 5 (Longest-First Alternation)**: Sorts exact-match secrets longest-first with alphanumeric lookarounds so overlapping secrets never half-clobber each other.
- **128-bit Cryptographic Identifier & Exact-Only Integrity (`cloakllm/secrets.py`, `cloakllm/stream.py`)**:
  - Uses 128-bit tags (`32 hex characters`) derived via `HMAC_SHA256(session_key, secret)[:32]`, pushing the birthday collision bound to $2^{64}$ (18 quintillion tags) with explicit runtime collision detection.
  - **Exact-Only Resolution (Zero Fuzzy Substitution)**: Eliminates fuzzy substitution from the security-critical path. Corrupted, truncated, or unknown tokens are never substituted with real credentials and remain unresolved placeholders.
- **Grammar-Driven SSE Hold-Back & Tool-Call JSON Escape Tolerance (`cloakllm/stream.py`)**:
  - Uses `codecs.getincrementaldecoder("utf-8")()` so multi-byte UTF-8 characters split across TCP packets never raise `UnicodeDecodeError`.
  - Maintains independent hold-back slots per `(choice_idx, block_idx, tool_idx)` using a formal prefix-viability regex over the token grammar.
  - Tolerates Markdown backslash escaping (`\_`, `\\_`) and literal JSON Unicode escapes (`\u005f`) inside `input_json_delta.partial_json`, re-escaping restored secrets via `json.dumps(secret)[1:-1]` (RFC 8259 control characters `< 0x20`, quotes, and backslashes).
- **Prompt-Cache Determinism & Extended-Thinking Signature Immunity (`cloakllm/proxy.py`)**:
  - Memoizes cloaked messages by `(session_key, vault_version, blake2b(canonical_json))`, keeping Anthropic prompt prefixes byte-identical across turns (`~1.1 ms` overhead on 50-turn / 100k-token payloads).
  - Never modifies `thinking`, `redacted_thinking`, or cryptographically signed content blocks (`"signature" in block`) in either direction so multi-turn extended thinking never fails signature verification.
- **Fail-Closed Local Security & Explicit Route Allowlist (`cloakllm/proxy.py`)**:
  - Enforces an explicit route-and-method allowlist (`POST /v1/messages`, `POST /v1/messages/count_tokens`, `POST /v1/chat/completions`, `GET /v1/models`). Blocks all unrecognized routes with `403 Forbidden` and blocks path traversal attempts (`..`) with `400 Bad Request`.
  - Authenticates the local child process via a per-run capability token in `ANTHROPIC_BASE_URL=http://127.0.0.1:{port}/{url_token}`.
  - Fails closed with `500` on malformed request JSON (never forwards raw uncloaked bytes).

---

## Reproducible Benchmarks

Run the bundled benchmark suite locally:

```bash
python benchmarks/rehydration_bench.py
```

| Benchmark Suite | Metric | Result |
| :--- | :--- | :--- |
| **5-Gate `.env` Precision/Recall** (50 realistic entries) | Benign False-Positive Rate | **0.0%** (`0 / 25` false positives) |
| **5-Gate `.env` Precision/Recall** (50 realistic entries) | True Credential Recall | **100.0%** (`25 / 25` captured) |
| **200-Case Streaming & Non-Substitution Integrity** | Exact prose, `\_`, `\\_`, `\u005f`, 1–5B SSE splits, corrupted token non-substitution | **100.0%** (`200 / 200` verified) |
| **51-Turn Conversation Latency** (`~243 KB` payload) | Memoized Next-Turn Proxy Overhead | **1.10 ms** (cold scan: `17.9 ms`) |

---

## Threat Model & Honest Boundaries

CloakLLM is designed as a local developer firewall and transcript hygiene utility. To prevent false security assumptions, keep these technical boundaries in mind:

1. **Heuristic Detection Boundary**: `cloakllm` relies on 5-gate heuristics for `.env*` files and high-precision prefixes for known vendors. Custom, unstructured secrets embedded in non-standard formats, arbitrary command stdout, or rotated credentials no longer present in `.env` cannot be detected without a matching prefix pattern.
2. **Logical Redaction vs. Hardware Erasure**: `cloakllm scrub` performs atomic in-place logical file redaction with `0600` permissions. It rejects symlinks to prevent traversal attacks. However, it does not guarantee forensic erasure of storage blocks on copy-on-write filesystems (APFS, ZFS, Btrfs), SSD wear-leveling pools, filesystem journals, or remote cloud backups.
3. **Pre-Wrap Resumed Sessions**: In sessions started with `cloakllm run -- claude`, thinking blocks only ever see cloaked tokens. If you resume an older uncloaked session that already contains plaintext secrets in a signed `thinking` block, that block cannot be rewritten without invalidating Anthropic's signature.
4. **Non-Goals (String Transformations)**: If a prompt explicitly asks the LLM to output credentials in Base64, hex, rot13, or character-sliced form, the transformed token will not match the token grammar and will remain in its placeholder state.
5. **Local Multi-User Environment**: CloakLLM binds to loopback (`127.0.0.1`) and uses a per-run random path capability token. On shared multi-user Unix machines where untrusted users can inspect process environment tables (`ps e`) or loopback traffic, use standard OS-level user namespace isolation.

## Supported Provider API Schemas & Variant Contracts

CloakLLM strictly validates and parses supported payload structures for the following provider routes:

### 1. Anthropic Messages API (`/v1/messages`, `/v1/messages/count_tokens`)
- **Roles**: `user`, `assistant`.
- **System Prompts**: Top-level `system` string or list of text blocks (`{"type": "text", "text": "..."}`).
- **Content Blocks**:
  - `text`: Plain text blocks (`text: str`).
  - `image`: Visual inputs supporting both `source.type == "base64"` (`media_type`, `data`) and `source.type == "url"` (`url: str`).
  - `tool_use`: Model-invoked tool calls (`id: str`, `name: str`, `input: dict`).
  - `tool_result`: Local execution results (`tool_use_id: str`, optional `content` as string or list of text/image blocks, optional `is_error: bool`).
  - `thinking` & `redacted_thinking`: Extended reasoning blocks (`thinking`, `signature`, `data`), immune to cloaking/rehydration modification to preserve cryptographic signatures.
- **Streaming**: Server-Sent Events (`text_delta`, `input_json_delta`) with grammar-driven hold-back buffer across multi-byte UTF-8, JSON escape (`\u005f`), and markdown escape (`\_`) sequences.

### 2. OpenAI Chat Completions API (`/v1/chat/completions`)
- **Roles**: `system`, `developer`, `user`, `assistant`, `tool`, `function`.
- **Content Variants**:
  - String content across all message roles.
  - Structured parts: `text` (`text: str`), `image_url` (string URL or `{"url": str, "detail": ...}`), and `input_audio` (`data: str`, `format: str`).
  - Null `content`: Permitted for assistant messages specifying `tool_calls` or `function_call`.
- **Tool Calling**:
  - `tool_calls`: List of objects with `id: str`, `type: "function"`, and `function: {"name": str, "arguments": str}`.
  - `function_call`: Legacy function calling (`name: str`, `arguments: str`).
  - `tool`: Tool response messages requiring string `tool_call_id`.
  - `function`: Legacy response messages requiring string `name`.
- **Fail-Closed Contract**: Any role or content block outside this supported matrix is rejected fail-closed with generic JSON error envelopes (`ERR_PAYLOAD_PROCESSING_FAILED`), preventing malformed payload bypass.

---

## License

MIT
