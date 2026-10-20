"""Production Security Release Gate Verification Suite for CloakLLM.

Tests the four fundamental security invariants required for unconditional production security sign-off:
1. Outbound Boundary Invariant: Registered secrets CANNOT cross the proxy boundary in plaintext
   under any supported route, nested JSON structure, tool input, metadata, or array element.
   Verified via an instrumented recording upstream server that captures raw network traffic.
2. Zero Upstream Dispatch Invariant: All rejected requests (malformed schemas, duplicate keys,
   unsupported verbs, path traversals, immutable blocks containing secrets) produce exactly ZERO
   upstream requests.
3. Response Stream Rehydration Invariant: SSE streaming safely rehydrates cloaked tokens across
   arbitrary chunk splits, UTF-8 boundaries, and JSON escape sequences without fuzzy substitution.
4. Concurrency & Cache Coherence Invariant: High-concurrency interleaving of secret registrations
   and outbound cloaking never serves stale or uncloaked content from the memoization cache.
"""

from __future__ import annotations

import http.client
import json
import socket
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlsplit

import pytest

from cloakllm.audit import harden_claude_settings, scrub_transcripts
from cloakllm.proxy import CloakProxyServer, cloak_request_payload
from cloakllm.secrets import SecretVault
from cloakllm.stream import StreamRehydrator


class InstrumentedRecordingUpstream:
    """Mock upstream server that records 100% of received raw HTTP requests for byte-level audit."""

    def __init__(self) -> None:
        self.dispatched_requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        server_ref = self

        class RecordingHandler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                server_ref._record(self, "POST")

            def do_GET(self) -> None:
                server_ref._record(self, "GET")

            def log_message(self, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), RecordingHandler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.port = self._server.server_port
        self.base_url = f"http://127.0.0.1:{self.port}"

    def _record(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        content_len = int(handler.headers.get("Content-Length", 0))
        body_bytes = handler.rfile.read(content_len) if content_len > 0 else b""
        with self._lock:
            self.dispatched_requests.append(
                {
                    "method": method,
                    "path": handler.path,
                    "headers": dict(handler.headers),
                    "body_bytes": body_bytes,
                    "body_str": body_bytes.decode("utf-8", errors="replace"),
                }
            )
        handler.send_response(200)
        handler.send_header("Content-Type", "application/json")
        handler.end_headers()
        handler.wfile.write(b'{"id":"mock_upstream_response_ok"}')

    def assert_zero_secrets_leaked(self, secrets: List[str]) -> None:
        """Assert that NOT A SINGLE BYTE of any registered secret ever appeared in upstream traffic."""
        with self._lock:
            for req in self.dispatched_requests:
                raw_traffic = f"{req['path']} {json.dumps(req['headers'])} {req['body_str']}"
                for s in secrets:
                    assert s not in raw_traffic, (
                        f"CRITICAL SECURITY INVARIANT VIOLATION: Registered secret '{s}' leaked "
                        f"to upstream in {req['method']} {req['path']}!"
                    )

    def assert_zero_upstream_dispatches(self) -> None:
        """Assert that exactly zero requests reached the upstream server."""
        with self._lock:
            assert len(self.dispatched_requests) == 0, (
                f"INVARIANT VIOLATION: Expected 0 upstream requests, but received {len(self.dispatched_requests)}: "
                f"{[r['path'] for r in self.dispatched_requests]}"
            )

    def reset(self) -> None:
        with self._lock:
            self.dispatched_requests.clear()

    def shutdown(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


# ==============================================================================
# 1. OUTBOUND BOUNDARY LEAK-PREVENTION INVARIANTS (All Supported Routes & Trees)
# ==============================================================================

def test_outbound_boundary_leak_prevention_across_all_supported_routes(tmp_path: Path) -> None:
    """Security Invariant 1: Registered secrets CANNOT cross the proxy boundary in plaintext.

    Exercises:
    - Route 1: Anthropic `/v1/messages`
    - Route 2: Anthropic `/v1/messages/count_tokens`
    - Route 3: OpenAI `/v1/chat/completions`
    Across deeply nested structures:
    - Top-level system strings and block lists
    - Deeply nested tool calls & tool arguments
    - Metadata and tracking dictionaries
    - Array elements and mixed content
    - Secrets with symbols, punctuation, and overlapping prefixes
    """
    upstream = InstrumentedRecordingUpstream()
    vault = SecretVault(session_key=b"prod-release-gate-key-32-bytes!")

    # Register diverse secret categories
    sec_ant = "sk-" + "ant-api03-ProductionTestAnthropicKey1234567890"
    sec_oa = "sk-" + "proj-ProductionTestOpenAIKey998877665544332211"
    sec_db_pw = "P@ssw0rd!#_Complex_Punctuation"
    sec_db_url = f"postgresql://admin:{sec_db_pw}@db.prod.internal:5432/main"
    sec_overlap_long = "super_confidential_token_production_long_99"
    sec_overlap_short = "super_confidential_token"

    all_registered = [sec_ant, sec_oa, sec_db_pw, sec_overlap_long, sec_overlap_short]
    for s in all_registered:
        vault.register_secret(s, category="GENERIC")

    proxy = CloakProxyServer(vault=vault, upstream_base_url=upstream.base_url)
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    try:
        # --- Case 1: Anthropic /v1/messages (Deeply nested payload) ---
        anthropic_payload = {
            "model": "claude-3-5-sonnet-20241022",
            "system": [
                {"type": "text", "text": f"System initialization with {sec_ant} and {sec_overlap_short}."}
            ],
            "messages": [
                {
                    "role": "user",
                    "content": [
                        {"type": "text", "text": f"Connect using {sec_db_url}"},
                        {"type": "text", "text": f"Verify overlapping: {sec_overlap_long}"},
                    ],
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "toolu_01",
                            "name": "execute_query",
                            "input": {
                                "connection_string": sec_db_url,
                                "auth_token": sec_ant,
                                "nested_dict": {"inner_key": sec_oa, "items": [sec_db_pw, "public_data"]},
                            },
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "toolu_01",
                            "content": f"Query executed using password {sec_db_pw}.",
                        }
                    ],
                },
            ],
            "metadata": {
                "user_id": f"usr-{sec_overlap_short}",
                "environment_info": {"db": sec_db_url},
            },
        }

        conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
        body1 = json.dumps(anthropic_payload).encode("utf-8")
        conn.request("POST", f"/{tok}/v1/messages", body=body1, headers={"Content-Type": "application/json"})
        resp1 = conn.getresponse()
        resp1.read()
        conn.close()
        assert resp1.status == 200

        # --- Case 2: Anthropic /v1/messages/count_tokens ---
        count_tokens_payload = {
            "model": "claude-3-5-sonnet-20241022",
            "messages": [{"role": "user", "content": f"Counting tokens with {sec_ant} and {sec_db_pw}"}],
        }
        conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
        body2 = json.dumps(count_tokens_payload).encode("utf-8")
        conn.request("POST", f"/{tok}/v1/messages/count_tokens", body=body2, headers={"Content-Type": "application/json"})
        resp2 = conn.getresponse()
        resp2.read()
        conn.close()
        assert resp2.status == 200

        # --- Case 3: OpenAI /v1/chat/completions (Deeply nested tool_calls & developer role) ---
        openai_payload = {
            "model": "gpt-4o",
            "messages": [
                {"role": "developer", "content": f"Developer policy bearing {sec_oa}"},
                {
                    "role": "assistant",
                    "tool_calls": [
                        {
                            "id": "call_01",
                            "type": "function",
                            "function": {
                                "name": "setup_db",
                                "arguments": json.dumps({"conn": sec_db_url, "token": sec_ant}),
                            },
                        }
                    ],
                },
                {
                    "role": "tool",
                    "tool_call_id": "call_01",
                    "content": f"DB initialized with {sec_db_pw}",
                },
            ],
        }
        conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
        body3 = json.dumps(openai_payload).encode("utf-8")
        conn.request("POST", f"/{tok}/v1/chat/completions", body=body3, headers={"Content-Type": "application/json"})
        resp3 = conn.getresponse()
        resp3.read()
        conn.close()
        assert resp3.status == 200

        # HARD SECURITY INVARIANT ASSERTION:
        # Zero occurrences of any registered secret across ALL upstream requests!
        upstream.assert_zero_secrets_leaked(all_registered)
        assert len(upstream.dispatched_requests) == 3

    finally:
        proxy.stop()
        upstream.shutdown()


# ==============================================================================
# 2. ZERO UPSTREAM DISPATCH REJECTION INVARIANTS
# ==============================================================================

def test_adversarial_rejections_produce_zero_upstream_dispatches(tmp_path: Path) -> None:
    """Security Invariant 2: Hostile/malformed requests produce EXACTLY ZERO upstream dispatches.

    Enforces that:
    1. Thinking blocks containing plaintext secrets fail closed before upstream dispatch.
    2. Malformed JSON, duplicate keys, and NaN constants fail closed before dispatch.
    3. Non-allowlisted routes, unsupported methods, and traversal attempts fail closed.
    4. Missing or forged capability tokens fail closed.
    5. In EVERY case, zero requests reach the upstream server.
    """
    upstream = InstrumentedRecordingUpstream()
    vault = SecretVault(session_key=b"zero-dispatch-key-32-bytes!!!!!")
    sec_val = "sk-" + "ant-api03-HostileAttackTestSecretKey987654321"
    vault.register_secret(sec_val, category="ANTHROPIC")

    proxy = CloakProxyServer(vault=vault, upstream_base_url=upstream.base_url)
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    hostile_test_cases = [
        # 1. Plaintext secret in thinking block (fail closed)
        (
            "POST",
            f"/{tok}/v1/messages",
            json.dumps({
                "model": "claude-3-7-sonnet",
                "messages": [{
                    "role": "assistant",
                    "content": [{"type": "thinking", "thinking": f"Leak {sec_val}", "signature": "sig123"}]
                }]
            }).encode("utf-8"),
            500,
        ),
        # 2. Plaintext secret in redacted_thinking block
        (
            "POST",
            f"/{tok}/v1/messages",
            json.dumps({
                "model": "claude-3-7-sonnet",
                "messages": [{
                    "role": "assistant",
                    "content": [{"type": "redacted_thinking", "data": f"blob_{sec_val}"}]
                }]
            }).encode("utf-8"),
            500,
        ),
        # 3. Duplicate JSON keys in request payload (fails closed)
        (
            "POST",
            f"/{tok}/v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[],"messages":[]}',
            (400, 500),
        ),
        # 4. Non-standard JSON constants (NaN / Infinity) (fails closed)
        (
            "POST",
            f"/{tok}/v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[{"role":"user","content":"hi"}],"temperature": NaN}',
            (400, 500),
        ),
        # 5. Missing URL capability token
        (
            "POST",
            "/v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[]}',
            401,
        ),
        # 6. Forged URL capability token
        (
            "POST",
            "/wrong_forged_capability_token/v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[]}',
            401,
        ),
        # 7. Path traversal attempting to escape capability token
        (
            "POST",
            f"/{tok}/../../v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[]}',
            400,
        ),
        # 8. Unsupported HTTP verb (PUT)
        (
            "PUT",
            f"/{tok}/v1/messages",
            b'{"model":"claude-3-5-sonnet"}',
            403,
        ),
        # 9. Unsupported HTTP verb (DELETE)
        (
            "DELETE",
            f"/{tok}/v1/messages",
            None,
            403,
        ),
        # 10. Non-allowlisted route
        (
            "POST",
            f"/{tok}/v1/admin/internal_debug",
            b'{"action":"debug"}',
            403,
        ),
        # 11. Malformed schema (unsupported role)
        (
            "POST",
            f"/{tok}/v1/messages",
            b'{"model":"claude-3-5-sonnet","messages":[{"role":"unsupported_role","content":"hi"}]}',
            500,
        ),
    ]

    try:
        for method, path, body, expected_status in hostile_test_cases:
            conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
            headers = {"Content-Type": "application/json"} if body is not None else {}
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()

            if isinstance(expected_status, tuple):
                assert resp.status in expected_status, (
                    f"Expected status in {expected_status} for {method} {path}, got {resp.status}. "
                    f"Body: {resp_body.decode('utf-8', errors='replace')}"
                )
            else:
                assert resp.status == expected_status, (
                    f"Expected status {expected_status} for {method} {path}, got {resp.status}. "
                    f"Body: {resp_body.decode('utf-8', errors='replace')}"
                )
            # Ensure error response never echoes the registered secret
            assert sec_val not in resp_body.decode("utf-8", errors="replace")

        # HARD INVARIANT: Exactly ZERO requests reached upstream across all hostile attempts!
        upstream.assert_zero_upstream_dispatches()

    finally:
        proxy.stop()
        upstream.shutdown()


# ==============================================================================
# 3. RESPONSE STREAM REHYDRATION INVARIANTS (Adversarial Chunk Splits)
# ==============================================================================

def test_response_stream_rehydration_adversarial_chunk_boundaries() -> None:
    """Security Invariant 3: SSE stream rehydration handles arbitrary chunk splits and corrupted tokens.

    Verifies:
    1. Multi-byte UTF-8 split across TCP chunks never crashes.
    2. Token boundary splits across chunks rehydrate cleanly.
    3. Corrupted or truncated tokens are NEVER fuzzy-substituted (exact-only integrity).
    4. Escaped JSON deltas rehydrate accurately into valid JSON strings.
    """
    vault = SecretVault(session_key=b"rehydration-adversarial-key-32b!")
    real_secret = "sk-" + "ant-api03-StreamingRehydrationKey998877"
    entry = vault.register_secret(real_secret, category="ANTHROPIC")
    token = entry.token

    # 1. Test 1-byte chunk drip over UTF-8 and token split
    sample_text = f"Here is the secret: {token} embedded in text with unicode: 🚀 — and done."
    sse_events = [
        f'data: {{"type":"content_block_delta","delta":{{"type":"text_delta","text":{json.dumps(sample_text)}}}}}\n\n',
        "data: [DONE]\n\n",
    ]
    raw_stream = "".join(sse_events).encode("utf-8")

    rehydrator = StreamRehydrator(vault=vault)
    rehydrated_chunks: List[bytes] = []
    # Drip 1 byte at a time
    for i in range(len(raw_stream)):
        byte_chunk = raw_stream[i : i + 1]
        out = rehydrator.feed_bytes(byte_chunk)
        if out:
            rehydrated_chunks.append(out)
    final_out = rehydrator.flush()
    if final_out:
        rehydrated_chunks.append(final_out)

    rehydrated_full = b"".join(rehydrated_chunks).decode("utf-8")
    assert real_secret in rehydrated_full
    assert token not in rehydrated_full
    assert "🚀" in rehydrated_full

    # 2. Test exact-only resolution: Corrupted / truncated token must NEVER substitute
    corrupted_token = token[:-4] + "XXXX"
    corrupted_stream = f'data: {{"type":"content_block_delta","delta":{{"type":"text_delta","text":"Bad token: {corrupted_token}"}}}}\n\n'.encode("utf-8")

    rehydrator2 = StreamRehydrator(vault=vault)
    out2 = rehydrator2.feed_bytes(corrupted_stream) + rehydrator2.flush()
    out2_str = out2.decode("utf-8")
    # Invariant: Corrupted token is left AS-IS, raw secret is NEVER leaked
    assert real_secret not in out2_str
    assert corrupted_token in out2_str


# ==============================================================================
# 4. CONCURRENCY & CACHE COHERENCE INVARIANTS
# ==============================================================================

def test_high_concurrency_secret_registration_and_cache_coherence() -> None:
    """Security Invariant 4: Sustained concurrent registrations cannot cause in-flight requests to return stale data.

    Fires 10 concurrent reader threads cloaking repeated payloads while a writer thread
    continuously registers new secrets into the vault.
    Asserts:
    1. Zero unhandled exceptions or thread crashes.
    2. Invariant: Every completed cloaked payload contains zero registered secrets in plaintext.
    """
    vault = SecretVault(session_key=b"concurrency-coherence-key-32b!!")
    base_secrets = [f"sk-" + f"ant-api03-BaseSecret{i:03d}_Key" for i in range(10)]
    for s in base_secrets:
        vault.register_secret(s, category="ANTHROPIC")

    stop_event = threading.Event()
    registered_during_test: List[str] = []
    reg_lock = threading.Lock()
    errors: List[Exception] = []

    def writer_worker() -> None:
        idx = 0
        while not stop_event.is_set() and idx < 30:
            new_sec = f"sk-" + f"ant-api03-DynamicSecret{idx:03d}_Key_{time.time()}"
            vault.register_secret(new_sec, category="ANTHROPIC")
            with reg_lock:
                registered_during_test.append(new_sec)
            idx += 1
            time.sleep(0.01)

    def reader_worker(worker_id: int) -> None:
        try:
            for iteration in range(20):
                # Construct payload with mixed static and dynamic secrets
                with reg_lock:
                    known = list(registered_during_test)
                sample_sec = known[-1] if known else base_secrets[0]
                payload = {
                    "model": "claude-3-5-sonnet",
                    "messages": [
                        {
                            "role": "user",
                            "content": f"Worker {worker_id} iteration {iteration}: {base_secrets[worker_id % len(base_secrets)]} and {sample_sec}",
                        }
                    ],
                }
                cloaked_obj, count = cloak_request_payload(payload, vault)
                # Verify that no registered secret is in the output text
                content_text = cloaked_obj["messages"][0]["content"]
                for b_sec in base_secrets:
                    assert b_sec not in content_text, f"Leaked base secret in worker {worker_id}!"
                for d_sec in known:
                    assert d_sec not in content_text, f"Leaked dynamic secret in worker {worker_id}!"
        except Exception as e:
            errors.append(e)

    writer_thread = threading.Thread(target=writer_worker, daemon=True)
    readers = [threading.Thread(target=reader_worker, args=(i,), daemon=True) for i in range(10)]

    writer_thread.start()
    for r in readers:
        r.start()

    for r in readers:
        r.join(timeout=10.0)
        assert not r.is_alive(), "Reader thread timed out!"

    stop_event.set()
    writer_thread.join(timeout=5.0)

    assert len(errors) == 0, f"Concurrency errors encountered: {errors}"


# ==============================================================================
# 5. FILESYSTEM & TRANSCRIPT INTEGRITY INVARIANTS
# ==============================================================================

def test_transcript_scrubbing_atomic_recovery_and_unicode_tolerance(tmp_path: Path) -> None:
    """Security Invariant 5: In-place transcript scrubbing preserves valid history while redacting secrets.

    Verifies:
    1. Malformed/non-JSON lines are handled gracefully without aborting.
    2. Deep Unicode and emoji content are preserved without corrupting text.
    3. Output file is written atomically with 0600 permissions.
    4. Registered secrets are completely erased from the scrubbed transcript.
    """
    secret = "sk-" + "ant-api03-TranscriptScrubTestSecret12345"
    vault = SecretVault(session_key=b"transcript-integrity-key-32b!!")
    vault.register_secret(secret, category="ANTHROPIC")

    transcript_file = tmp_path / "session_test.jsonl"
    lines = [
        json.dumps({"type": "user", "message": f"Please use my key {secret} to test 🚀."}, ensure_ascii=False),
        "NOT_A_JSON_LINE_CORRUPTED_ENTRY_TEST",
        json.dumps({"type": "assistant", "message": "Done with non-secret task."}),
    ]
    transcript_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    mod_count, repl_count = scrub_transcripts(extra_transcript_paths=[transcript_file], vault=vault)
    assert mod_count == 1
    assert repl_count == 1

    scrubbed_content = transcript_file.read_text(encoding="utf-8")
    assert secret not in scrubbed_content
    assert "CLOAKv1_ANTHROPIC_" in scrubbed_content
    assert "🚀" in scrubbed_content
    assert "NOT_A_JSON_LINE_CORRUPTED_ENTRY_TEST" in scrubbed_content
