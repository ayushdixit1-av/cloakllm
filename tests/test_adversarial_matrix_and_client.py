"""Phase 02 Adversarial Security Validation and Real-Client Compatibility Test Suite.

Comprehensive adversarial test suite verifying:
1. Multi-turn Real-Client Simulation (Claude Code tool calling loop with bidirectional cloaking & rehydration).
2. Hostile Probe Rejection (Forged tags, category swapping, truncated tags, non-substitution invariant).
3. Route & Method Isolation (Explicit rejection of /v1/messages/batches, /v1/files, unsupported HTTP verbs).
4. Complex Encoding & Delimiter Boundary Matrix (Punctuation, JSON escapes, Unicode edge cases, control chars).
5. Overlapping & Substring Credential Alternation Invariant.
6. Extreme Nesting & Payload Stress (Deeply nested JSON structures and arrays).
"""

from __future__ import annotations

import http.client
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Dict, List, Optional, Tuple

import pytest

from credcloak.proxy import CloakProxyServer
from credcloak.secrets import SecretVault
from credcloak.stream import StreamRehydrator, rehydrate_text_fragment


class UpstreamMockServer:
    """Mock upstream server that records requests and returns scripted or echo responses."""

    def __init__(self) -> None:
        self.recorded_requests: List[Dict[str, Any]] = []
        self._lock = threading.Lock()
        self.response_queue: List[Tuple[int, Dict[str, str], bytes]] = []
        server_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self) -> None:
                server_ref._handle(self, "POST")

            def do_GET(self) -> None:
                server_ref._handle(self, "GET")

            def do_PUT(self) -> None:
                server_ref._handle(self, "PUT")

            def do_DELETE(self) -> None:
                server_ref._handle(self, "DELETE")

            def log_message(self, *args: Any) -> None:
                return

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.port = self._server.server_port
        self.base_url = f"http://127.0.0.1:{self.port}"

    def _handle(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        content_len = int(handler.headers.get("Content-Length", 0))
        body_bytes = handler.rfile.read(content_len) if content_len > 0 else b""
        with self._lock:
            self.recorded_requests.append(
                {
                    "method": method,
                    "path": handler.path,
                    "headers": dict(handler.headers),
                    "body_bytes": body_bytes,
                    "body_str": body_bytes.decode("utf-8", errors="replace"),
                }
            )
            if self.response_queue:
                status, headers, body = self.response_queue.pop(0)
            else:
                status = 200
                headers = {"Content-Type": "application/json"}
                body = b'{"id":"mock_ok","model":"claude-3-sonnet","content":[{"type":"text","text":"OK"}]}'

        handler.send_response(status)
        for k, v in headers.items():
            handler.send_header(k, v)
        handler.end_headers()
        handler.wfile.write(body)

    def queue_response(self, status: int, headers: Dict[str, str], body: bytes) -> None:
        with self._lock:
            self.response_queue.append((status, headers, body))

    def assert_zero_plaintext_leak(self, secrets: List[str]) -> None:
        with self._lock:
            for req in self.recorded_requests:
                dump = f"{req['path']} {json.dumps(req['headers'])} {req['body_str']}"
                for s in secrets:
                    assert s not in dump, f"Leak detected for secret '{s}' in request: {dump}"

    def assert_zero_upstream_dispatches(self) -> None:
        with self._lock:
            assert len(self.recorded_requests) == 0, f"Expected 0 requests, got {len(self.recorded_requests)}"

    def reset(self) -> None:
        with self._lock:
            self.recorded_requests.clear()
            self.response_queue.clear()

    def close(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._thread.join(timeout=2.0)


@pytest.fixture
def upstream() -> UpstreamMockServer:
    server = UpstreamMockServer()
    yield server
    server.close()


@pytest.fixture
def test_setup(upstream: UpstreamMockServer):
    vault = SecretVault()
    secret_pass = "UltraSecretProdPasswd123!"
    secret_api = "".join(["sk-ant-", "api03-", "MockAnthropicProductionKey998877665544332211"])
    secret_stripe = "".join(["sk_", "live_", "51MockStripeProductionKey998877665544332211"])
    e_pass = vault.register_secret(secret_pass, category="DB")
    e_api = vault.register_secret(secret_api, category="ANTHROPIC")
    e_stripe = vault.register_secret(secret_stripe, category="STRIPE")

    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url=upstream.base_url,
        port=0,
        url_token="adv-test-token-7788",
    )
    proxy.start()
    yield {
        "vault": vault,
        "proxy": proxy,
        "upstream": upstream,
        "secrets": [secret_pass, secret_api, secret_stripe],
        "pass": secret_pass,
        "api": secret_api,
        "stripe": secret_stripe,
        "e_pass": e_pass,
        "e_api": e_api,
        "e_stripe": e_stripe,
    }
    proxy.stop()


def test_real_client_multi_turn_tool_calling_simulation(test_setup):
    """Simulate a complete 2-turn Claude Code conversation with tool calls and execution."""
    proxy = test_setup["proxy"]
    upstream = test_setup["upstream"]
    secret_pass = test_setup["pass"]
    placeholder = test_setup["e_pass"].token
    token = proxy.url_token

    # Script Upstream Response for Turn 1:
    # Model requests bash tool call containing the cloaked placeholder
    sse_response_turn1 = (
        b"event: message_start\n"
        b'data: {"type":"message_start","message":{"id":"msg_1","role":"assistant"}}\n\n'
        b"event: content_block_start\n"
        b'data: {"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tool_call_1","name":"bash","input":{}}}\n\n'
        b"event: content_block_delta\n"
        b'data: {"type":"content_block_delta","index":0,"delta":{"type":"input_json_delta","partial_json":"{\\"command\\": \\"psql '
        + placeholder.encode("utf-8")
        + b'\\"}}"}}\n\n'
        b"event: content_block_stop\n"
        b'data: {"type":"content_block_stop","index":0}\n\n'
        b"event: message_stop\n"
        b'data: {"type":"message_stop"}\n\n'
    )
    upstream.queue_response(200, {"Content-Type": "text/event-stream"}, sse_response_turn1)

    # Turn 1: Claude Code sends user instruction containing the real database password
    conn = http.client.HTTPConnection("127.0.0.1", proxy.port)
    turn1_body = json.dumps(
        {
            "model": "claude-3-5-sonnet-20241022",
            "messages": [
                {
                    "role": "user",
                    "content": f"Connect to postgres and run migration with password {secret_pass}",
                }
            ],
            "stream": True,
        }
    )
    conn.request("POST", f"/{token}/v1/messages", body=turn1_body, headers={"Content-Type": "application/json"})
    resp1 = conn.getresponse()
    assert resp1.status == 200

    # Read and decode client-side stream
    rehydrated_stream = resp1.read().decode("utf-8")
    conn.close()

    # Upstream must NEVER receive the plaintext secret in Turn 1
    upstream.assert_zero_plaintext_leak([secret_pass])

    # But the client must receive the REHYDRATED secret so local tool execution succeeds
    assert secret_pass in rehydrated_stream
    assert placeholder not in rehydrated_stream

    # Turn 2: Claude Code executes tool locally and returns tool_result containing the password
    turn2_body = json.dumps(
        {
            "model": "claude-3-5-sonnet-20241022",
            "messages": [
                {
                    "role": "user",
                    "content": f"Connect to postgres and run migration with password {secret_pass}",
                },
                {
                    "role": "assistant",
                    "content": [
                        {
                            "type": "tool_use",
                            "id": "tool_call_1",
                            "name": "bash",
                            "input": {"command": f"psql {secret_pass}"},
                        }
                    ],
                },
                {
                    "role": "user",
                    "content": [
                        {
                            "type": "tool_result",
                            "tool_use_id": "tool_call_1",
                            "content": f"Connected to PostgreSQL successfully using {secret_pass}",
                        }
                    ],
                },
            ],
        }
    )
    conn2 = http.client.HTTPConnection("127.0.0.1", proxy.port)
    conn2.request("POST", f"/{token}/v1/messages", body=turn2_body, headers={"Content-Type": "application/json"})
    resp2 = conn2.getresponse()
    assert resp2.status == 200
    conn2.close()

    # Verify both turns upstream: zero plaintext secrets in any outbound payload
    upstream.assert_zero_plaintext_leak([secret_pass])
    assert len(upstream.recorded_requests) == 2


def test_adversarial_forged_and_tampered_placeholder_rejection(test_setup):
    """Verify that forged tags, truncated tags, and category swaps are NEVER rehydrated."""
    vault = test_setup["vault"]
    secret_pass = test_setup["pass"]
    real_placeholder = test_setup["e_pass"].token

    # 1. Attacker crafts completely fake random 32-hex placeholder
    fake_tag = "CLOAKv1_DB_0123456789ABCDEF0123456789ABCDEF"
    out1, c1 = rehydrate_text_fragment(f"Result: {fake_tag}", vault)
    assert out1 == f"Result: {fake_tag}"
    assert c1 == 0
    assert secret_pass not in out1

    # 2. Attacker crafts category swap: real HMAC hex tag but prepended with ANTHROPIC instead of DB
    parts = real_placeholder.split("_")
    tag_hex = parts[-1]
    swapped_category_tag = f"CLOAKv1_ANTHROPIC_{tag_hex}"
    out2, c2 = rehydrate_text_fragment(f"Result: {swapped_category_tag}", vault)
    assert out2 == f"Result: {swapped_category_tag}"
    assert c2 == 0
    assert secret_pass not in out2

    # 3. Attacker crafts truncated tag
    truncated_tag = real_placeholder[:20]
    out3, c3 = rehydrate_text_fragment(f"Result: {truncated_tag}", vault)
    assert out3 == f"Result: {truncated_tag}"
    assert c3 == 0
    assert secret_pass not in out3


def test_unsupported_endpoints_and_verbs_blocked_fail_closed(test_setup):
    """Verify that batches, file uploads, non-allowlisted routes and verbs fail closed with 403."""
    proxy = test_setup["proxy"]
    token = proxy.url_token

    forbidden_targets = [
        ("POST", f"/{token}/v1/messages/batches"),
        ("POST", f"/{token}/v1/files"),
        ("POST", f"/{token}/v1/embeddings"),
        ("POST", f"/{token}/v1/audio/transcriptions"),
        ("DELETE", f"/{token}/v1/messages"),
        ("PUT", f"/{token}/v1/chat/completions"),
        ("GET", f"/{token}/v1/messages"),
        ("PATCH", f"/{token}/v1/messages"),
    ]

    for method, path in forbidden_targets:
        conn = http.client.HTTPConnection("127.0.0.1", proxy.port)
        conn.request(method, path, body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status in (403, 501), f"Expected 403/501 for {method} {path}, got {resp.status}"
        conn.close()

    # Upstream must receive 0 requests
    test_setup["upstream"].assert_zero_upstream_dispatches()


def test_overlapping_and_embedded_substring_secret_invariants():
    """Verify longest-first alternation prevents clobbering when one secret contains another."""
    vault = SecretVault()
    short_secret = "SecretKey123"
    long_secret = "SecretKey123_ExtendedEnterpriseEdition"
    e_short = vault.register_secret(short_secret, category="SHORT")
    e_long = vault.register_secret(long_secret, category="LONG")

    test_input = f"Using {long_secret} and {short_secret} together."
    cloaked, count = vault.cloak_text(test_input)

    assert short_secret not in cloaked
    assert long_secret not in cloaked
    assert count == 2

    assert e_short.token in cloaked
    assert e_long.token in cloaked

    # Rehydrate
    rehydrated, r_count = rehydrate_text_fragment(cloaked, vault)
    assert r_count == 2
    assert rehydrated == test_input


def test_punctuation_and_delimiter_boundaries_matrix():
    """Verify secrets adjacent to quotes, brackets, parentheses, colons, and slashes are cloaked."""
    vault = SecretVault()
    secret = "TopSecretApiKey9988!"
    vault.register_secret(secret, category="TEST")

    boundary_cases = [
        f'"{secret}"',
        f"'{secret}'",
        f"({secret})",
        f"[{secret}]",
        f"{{{secret}}}",
        f"<{secret}>",
        f"key={secret}&other=1",
        f"Bearer {secret}",
        f"password:{secret}",
        f"/{secret}/",
        f";{secret};",
        f"|{secret}|",
        f"!{secret}?",
        f"{secret}\n",
        f"{secret}\r\n",
    ]

    for case in boundary_cases:
        cloaked, count = vault.cloak_text(case)
        assert secret not in cloaked, f"Failed to cloak secret in boundary case: {case}"
        assert count == 1
        rehydrated, r_count = rehydrate_text_fragment(cloaked, vault)
        assert r_count == 1
        assert rehydrated == case, f"Failed to rehydrate boundary case: {case}"


def test_extreme_json_nesting_and_array_structures(test_setup):
    """Test cloaking and fail-closed security across deeply nested JSON objects and arrays."""
    proxy = test_setup["proxy"]
    upstream = test_setup["upstream"]
    secret_pass = test_setup["pass"]
    token = proxy.url_token

    # Build 25-level deep linear nesting containing secret at the deepest leaf
    nested_obj: Dict[str, Any] = {"leaf": f"Deploy with {secret_pass}"}
    for i in range(25):
        nested_obj = {f"level_{i}": nested_obj, "sibling_list": [1, 2, "item"]}

    payload = {
        "model": "claude-3-5-sonnet-20241022",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Deep nest test"},
                    {"type": "tool_result", "tool_use_id": "call_123", "content": json.dumps(nested_obj)},
                ],
            }
        ],
    }

    conn = http.client.HTTPConnection("127.0.0.1", proxy.port)
    conn.request("POST", f"/{token}/v1/messages", body=json.dumps(payload), headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    assert resp.status == 200
    conn.close()

    upstream.assert_zero_plaintext_leak([secret_pass])
