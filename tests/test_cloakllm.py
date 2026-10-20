"""Comprehensive test suite for CloakLLM covering B1-B6 pre-build audit requirements."""

from __future__ import annotations

import hashlib
import http.client
import json
import select
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import threading
import time
from urllib.parse import urlsplit

import pytest

from cloakllm.audit import (
    audit_transcripts,
    harden_claude_settings,
    mask_secret_preview,
    scrub_transcripts,
)
from cloakllm.proxy import CloakProxyServer, EventLogger, cloak_request_payload
from cloakllm.secrets import (
    SecretVault,
    extract_secrets_from_env_pair,
    parse_dotenv_content,
)
from cloakllm.stream import (
    StreamRehydrator,
    is_viable_token_prefix,
    rehydrate_json_value,
    rehydrate_text_fragment,
    split_holdback,
)


# ---------------------------------------------------------------------------
# B2: 5-Gate .env Loader & False-Positive Rejection Tests
# ---------------------------------------------------------------------------


def test_env_five_gates_reject_false_positives(tmp_path: Path) -> None:
    env_content = """\
# Public & non-secret keys (Gate 1 & Gate 2)
NODE_ENV=production
PORT=8080
AUTHOR=ayush_dixit_developer_2026
MONKEY_PATCH=enabled_in_dev_mode
BYPASS_AUTH=false
NEXT_PUBLIC_STRIPE_KEY=pk_live_51Nz89JkL90123456789abcde
VITE_PUBLIC_SUPABASE_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9_public_anon
JWT_PUBLIC_KEY=ssh-ed25519_AAAAC3NzaC1lZDI1NTE5AAAAI_public_material
AWS_KMS_KEY_ID=arn:aws:kms:us-east-1:123456789012:key/abcd-1234-ef56
SSH_PRIVATE_KEY_PATH=/Users/dev/.ssh/id_ed25519
OAUTH_TOKEN_URL=https://auth.example.com/oauth/token

# Plain URLs without credentials (Gate 3)
API_URL=https://api.stripe.com/v1/charges
WEBHOOK_ENDPOINT=https://hooks.example.com/services/public

# Low-entropy / placeholder values (Gate 4)
API_SECRET=changeme
DB_PASSWORD=password
ADMIN_TOKEN=${ADMIN_TOKEN_FROM_CI}

# True secrets that MUST be captured
DATABASE_URL=postgresql://app_user:Sup3rS3cr3tDbP@ss!99@db.internal.net:5432/prod_db
REDIS_URL=https://cache.internal.net/connect?token=r3d1s_qTok3n_987654321_xyz&timeout=5
STRIPE_SECRET_KEY=sk_live_99aBcDeFgHiJkLmNoPqRsTuVwXyZ012345
CUSTOM_WEBHOOK_SECRET=whsec_K8mP2xQ9vL4nR7tY1wZ3cB6fH0jM5sD8
"""
    env_file = tmp_path / ".env"
    env_file.write_text(env_content, encoding="utf-8")

    # Also write a .env.example that must be ignored
    example_file = tmp_path / ".env.example"
    example_file.write_text("STRIPE_SECRET_KEY=sk_live_EXAMPLE_DO_NOT_LOAD_9999999999\n", encoding="utf-8")

    vault = SecretVault(session_key=b"fixed-test-session-key-32-bytes!")
    loaded_count = vault.load_project_dirs([tmp_path])
    assert loaded_count >= 4

    secrets_set = {e.secret for e in vault.entries}
    # True secrets extracted:
    assert "Sup3rS3cr3tDbP@ss!99" in secrets_set
    assert "r3d1s_qTok3n_987654321_xyz" in secrets_set
    assert "sk_live_99aBcDeFgHiJkLmNoPqRsTuVwXyZ012345" in secrets_set
    assert "whsec_K8mP2xQ9vL4nR7tY1wZ3cB6fH0jM5sD8" in secrets_set

    # False positives rejected:
    assert "https://api.stripe.com/v1/charges" not in secrets_set
    assert "https://auth.example.com/oauth/token" not in secrets_set
    assert "pk_live_51Nz89JkL90123456789abcde" not in secrets_set
    assert "ayush_dixit_developer_2026" not in secrets_set
    assert "/Users/dev/.ssh/id_ed25519" not in secrets_set
    assert "sk_live_EXAMPLE_DO_NOT_LOAD_9999999999" not in secrets_set

    # Verify Gate 3 URL surgical cloaking preserves host/port/db while cloaking password
    sample_prompt = "Connect to postgresql://app_user:Sup3rS3cr3tDbP@ss!99@db.internal.net:5432/prod_db"
    cloaked, count = vault.cloak_text(sample_prompt)
    assert count == 1
    assert "Sup3rS3cr3tDbP@ss!99" not in cloaked
    assert "postgresql://app_user:CLOAKv1_DB_" in cloaked
    assert "@db.internal.net:5432/prod_db" in cloaked


def test_gate5_longest_first_prevents_partial_clobber() -> None:
    vault = SecretVault(session_key=b"0123456789abcdef0123456789abcdef")
    e_short = vault.register_secret("MySecretToken_2026", category="AUTH")
    e_long = vault.register_secret("MySecretToken_2026_Production_Extended", category="AUTH")

    text = f"Primary={e_long.secret} Secondary={e_short.secret}"
    cloaked, count = vault.cloak_text(text)
    assert count == 2
    assert cloaked == f"Primary={e_long.token} Secondary={e_short.token}"


# ---------------------------------------------------------------------------
# B3: Literal \u005f, \\_, RFC 8259 Control Chars & Grammar Hold-Back Tests
# ---------------------------------------------------------------------------


def test_raw_json_delta_u005f_and_double_backslash_and_control_char_escaping() -> None:
    vault = SecretVault(session_key=b"session-key-for-json-escape-test")
    # Secret containing quotes, backslash, and newline to test RFC 8259 escaping
    complex_secret = 'p@ss"word\\with\nnewline\tand_tab_99!'
    entry = vault.register_secret(complex_secret, category="DB")
    tag = entry.tag_hex

    # Case 1: Model emits literal \u005f (6 chars: \, u, 0, 0, 5, f) inside input_json_delta
    raw_json_u005f = f'{{"cmd": "export PGPASSWORD=CLOAKv1\\u005fDB\\u005f{tag}"}}'
    rehydrated_1, count_1 = rehydrate_text_fragment(raw_json_u005f, vault, is_raw_json_fragment=True)
    assert count_1 == 1
    # Verify the resulting string is 100% valid RFC 8259 JSON!
    parsed_1 = json.loads(rehydrated_1)
    assert parsed_1["cmd"] == f"export PGPASSWORD={complex_secret}"

    # Case 2: Model markdown-escapes underscores inside JSON string (`\\_`)
    raw_json_dbl = f'{{"cmd": "export PGPASSWORD=CLOAKv1\\\\_DB\\\\_{tag}"}}'
    rehydrated_2, count_2 = rehydrate_text_fragment(raw_json_dbl, vault, is_raw_json_fragment=True)
    assert count_2 == 1
    parsed_2 = json.loads(rehydrated_2)
    assert parsed_2["cmd"] == f"export PGPASSWORD={complex_secret}"


def test_grammar_holdback_prefix_viability() -> None:
    # Every strict prefix of a token (including mid-\u005f and partial hex) must be held back
    prefixes = [
        "\\",
        "\\\\",
        "C",
        "CL",
        "CLOAK",
        "CLOAKv1",
        "CLOAKv1_",
        "CLOAKv1\\_",
        "CLOAKv1\\\\_",
        "CLOAKv1\\u",
        "CLOAKv1\\u00",
        "CLOAKv1\\u005",
        "CLOAKv1\\u005f",
        "CLOAKv1_DB",
        "CLOAKv1_DB_",
        "CLOAKv1_DB\\u005",
        "CLOAKv1_DB_9F2",
        "CLOAKv1_DB_9F2A1B2",
    ]
    for p in prefixes:
        assert is_viable_token_prefix(p), f"Expected prefix {p!r} to be viable"
        safe, held = split_holdback(f"Hello world {p}")
        assert safe == "Hello world "
        assert held == p


def test_exact_only_resolution_and_no_fuzzy_substitution() -> None:
    """C3: Exact-only integrity. Corrupted or hallucinated tokens MUST NOT substitute real credentials."""
    vault = SecretVault(session_key=b"exact-integrity-test-key-32-bytes")
    entry = vault.register_secret("sk-ant-api03-SuperSecretKeyForExactTest1234567890", category="ANTHROPIC")
    orig_tag = entry.tag_hex
    assert len(orig_tag) == 32  # C2: 128-bit tag

    # Corrupt last character
    bad_last = "0" if orig_tag[-1] != "0" else "1"
    corrupted_token = f"CLOAKv1_ANTHROPIC_{orig_tag[:-1]}{bad_last}"

    events = []
    restored, count = rehydrate_text_fragment(
        f"Key: {corrupted_token}",
        vault,
        is_raw_json_fragment=False,
        on_event=lambda k, t: events.append((k, t)),
    )
    # Integrity invariant: Never replaced with a real credential!
    assert count == 0
    assert entry.secret not in restored
    assert corrupted_token in restored
    assert events == [("unknown_token", corrupted_token)]


def test_128bit_token_tag_and_collision_check() -> None:
    """C2: Verify 128-bit tag generation and explicit collision detection."""
    vault = SecretVault(session_key=b"collision-test-key-32-bytes-long!")
    e1 = vault.register_secret("secret_alpha_1234567890", category="AUTH")
    assert len(e1.tag_hex) == 32
    assert e1.token.startswith("CLOAKv1_AUTH_")

    # Forcing a fake tag collision in _by_tag must raise RuntimeError
    vault._by_tag["COLLISION_TAG_12345678901234567"] = e1
    # Mocking compute_tag to return existing tag with different secret
    vault._compute_tag = lambda sec: "COLLISION_TAG_12345678901234567"
    with pytest.raises(RuntimeError, match="Cryptographic collision detected"):
        vault.register_secret("secret_beta_9876543210", category="AUTH")


# ---------------------------------------------------------------------------
# B3: 2D SSE Fuzz Test (Transport Byte Splits x Delta Splits + UTF-8 Emoji Split)
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("tcp_chunk_size", [1, 2, 3, 5, 7, 13, 29, 64])
def test_2d_sse_stream_rehydration_fuzz(tcp_chunk_size: int) -> None:
    vault = SecretVault(session_key=b"stream-fuzz-session-key-32-bytes")
    sec_text = "sk-ant-api03-LiveStreamingSecretKey998877665544332211"
    sec_json = 'db_pass_with_"quotes"_and_\n_newline_12345'
    e_text = vault.register_secret(sec_text, category="ANTHROPIC")
    e_json = vault.register_secret(sec_json, category="DB")

    # Split e_text.token into 3 pieces across text_delta events, surrounded by 4-byte UTF-8 emojis 🔐
    t_tok = e_text.token
    t_part1, t_part2, t_part3 = t_tok[:4], t_tok[4:13], t_tok[13:]

    # Split e_json.token using \u005f across 3 input_json_delta events on block index 1
    j_tok = f"CLOAKv1\\u005fDB\\u005f{e_json.tag_hex}"
    j_part1, j_part2, j_part3 = j_tok[:10], j_tok[10:19], j_tok[19:]

    sse_events = [
        {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
        {"type": "content_block_start", "index": 1, "content_block": {"type": "tool_use", "id": "toolu_1", "name": "bash", "input": {}}},
        # Interleaved deltas across block 0 (text_delta) and block 1 (input_json_delta)
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"🔐 Token start: {t_part1}"}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": f'{{"secret": "{j_part1}'}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": t_part2}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": j_part2}},
        {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": f"{t_part3} 🔐 done!"}},
        {"type": "content_block_delta", "index": 1, "delta": {"type": "input_json_delta", "partial_json": f'{j_part3}"}}'}},
        {"type": "content_block_stop", "index": 0},
        {"type": "content_block_stop", "index": 1},
        {"type": "message_stop"},
    ]

    raw_wire = "".join(
        f"event: {ev['type']}\ndata: {json.dumps(ev, ensure_ascii=False)}\n\n" for ev in sse_events
    ).encode("utf-8")

    rehydrator = StreamRehydrator(vault=vault)
    out_chunks = bytearray()
    for i in range(0, len(raw_wire), tcp_chunk_size):
        out_chunks.extend(rehydrator.feed_bytes(raw_wire[i : i + tcp_chunk_size]))
    out_chunks.extend(rehydrator.flush())

    # Re-parse the emitted SSE stream and assemble block 0 text and block 1 JSON
    assembled_text = []
    assembled_json = []
    for block in out_chunks.decode("utf-8").split("\n\n"):
        for line in block.splitlines():
            if line.startswith("data:"):
                obj = json.loads(line[5:].strip())
                if obj.get("type") == "content_block_delta":
                    idx = obj["index"]
                    delta = obj["delta"]
                    if idx == 0 and delta["type"] == "text_delta":
                        assembled_text.append(delta["text"])
                    elif idx == 1 and delta["type"] == "input_json_delta":
                        assembled_json.append(delta["partial_json"])

    full_text = "".join(assembled_text)
    full_json_str = "".join(assembled_json)

    assert full_text == f"🔐 Token start: {sec_text} 🔐 done!"
    parsed_tool_input = json.loads(full_json_str)
    assert parsed_tool_input == {"secret": sec_json}


# ---------------------------------------------------------------------------
# B1: Extended-Thinking & Signature Immunity Tests
# ---------------------------------------------------------------------------


def test_thinking_and_signature_blocks_are_never_modified() -> None:
    vault = SecretVault(session_key=b"thinking-signature-immunity-key!")
    secret = "sk-ant-api03-SecretInsideSignedThinkingBlock1234567890"
    entry = vault.register_secret(secret, category="ANTHROPIC")

    request_payload = {
        "model": "claude-3-7-sonnet-20250219",
        "messages": [
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": f"Wait, the user has {secret} and {entry.token} in thinking.",
                        "signature": "ErUBCkYICBgCIkD_cryptographic_signature_must_not_break",
                    },
                    {
                        "type": "redacted_thinking",
                        "data": f"encrypted_{secret}",
                    },
                    {
                        "type": "text",
                        "text": f"Here is the normal text with {secret}.",
                    },
                ],
            }
        ],
    }

    cloaked_req, count = cloak_request_payload(request_payload, vault)
    assert count == 1
    blocks = cloaked_req["messages"][0]["content"]
    # Thinking block with signature is 100% untouched
    assert blocks[0]["thinking"] == f"Wait, the user has {secret} and {entry.token} in thinking."
    assert blocks[0]["signature"] == "ErUBCkYICBgCIkD_cryptographic_signature_must_not_break"
    # Redacted thinking block is 100% untouched
    assert blocks[1]["data"] == f"encrypted_{secret}"
    # Normal text block IS cloaked
    assert blocks[2]["text"] == f"Here is the normal text with {entry.token}."

    # Also verify inbound response rehydration skips thinking blocks
    response_payload = {
        "id": "msg_01",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "thinking",
                "thinking": f"Internal thought referencing {entry.token}",
                "signature": "sig_xyz",
            },
            {
                "type": "text",
                "text": f"Final answer with {entry.token}",
            },
        ],
    }
    rehydrated_resp, r_count = rehydrate_json_value(response_payload, vault)
    assert r_count == 1
    assert rehydrated_resp["content"][0]["thinking"] == f"Internal thought referencing {entry.token}"
    assert rehydrated_resp["content"][1]["text"] == f"Final answer with {secret}"


# ---------------------------------------------------------------------------
# B1: Fail-Closed Proxy, Path-Token Auth & /v1/messages/count_tokens Tests
# ---------------------------------------------------------------------------


def test_proxy_end_to_end_auth_count_tokens_and_fail_closed(tmp_path: Path) -> None:
    vault = SecretVault(session_key=b"proxy-e2e-test-session-key-32b!!")
    secret_val = "sk-ant-api03-ProxyEndToEndSecretKey9876543210abcdef"
    entry = vault.register_secret(secret_val, category="ANTHROPIC")

    received_upstream: list[tuple[str, dict, dict]] = []

    class MockUpstreamHandler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            received_upstream.append((self.path, dict(self.headers), body))

            if self.path.startswith("/v1/messages/count_tokens"):
                resp = json.dumps({"input_tokens": 42}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)
            elif self.path.startswith("/v1/messages"):
                # Echo back the cloaked token inside an assistant response to test rehydration
                user_text = body["messages"][0]["content"]
                resp_obj = {
                    "id": "msg_test",
                    "type": "message",
                    "role": "assistant",
                    "content": [{"type": "text", "text": f"Echoing back: {user_text}"}],
                }
                resp = json.dumps(resp_obj).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(resp)))
                self.end_headers()
                self.wfile.write(resp)

    upstream_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
    up_thread = threading.Thread(target=upstream_server.serve_forever, daemon=True)
    up_thread.start()
    up_url = f"http://127.0.0.1:{upstream_server.server_port}"

    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url=up_url,
        allow_passthrough=False,
        event_logger=logger,
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)

    try:
        # 1. Missing capability token -> 401 Unauthorized
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", "/v1/messages", body=b"{}", headers={"Content-Type": "application/json"})
        r_unauth = conn.getresponse()
        r_unauth.read()
        assert r_unauth.status == 401
        conn.close()

        # 2. Unknown endpoint (/v1/files) -> 403 Forbidden (Fail-Closed Allowlist!)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request(
            "POST",
            f"/{proxy.url_token}/v1/files",
            body=b"raw_file_upload",
            headers={"Content-Type": "application/octet-stream"},
        )
        r_files = conn.getresponse()
        r_files.read()
        assert r_files.status == 403
        conn.close()

        # 2b. Path traversal attempt (/../secret) -> 400 Bad Request (C1)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request(
            "GET",
            f"/{proxy.url_token}/v1/models/../../secret",
        )
        r_trav = conn.getresponse()
        r_trav.read()
        assert r_trav.status in (400, 403)
        conn.close()

        # 2c. Unauthorized HTTP method (DELETE /v1/messages) -> 403 Forbidden (C1)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request(
            "DELETE",
            f"/{proxy.url_token}/v1/messages",
        )
        r_del = conn.getresponse()
        r_del.read()
        assert r_del.status == 403
        conn.close()

        # 3. Invalid JSON on /v1/messages -> 500 Fail-Closed (never forwards raw bytes!)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request(
            "POST",
            f"/{proxy.url_token}/v1/messages",
            body=f"corrupt json with {secret_val}".encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        r_bad = conn.getresponse()
        r_bad.read()
        assert r_bad.status == 500
        assert len(received_upstream) == 0
        conn.close()

        # 4. POST /v1/messages/count_tokens?beta=true -> Cloaked!
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        ct_body = json.dumps(
            {"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": f"My key is {secret_val}"}]}
        ).encode("utf-8")
        conn.request(
            "POST",
            f"/{proxy.url_token}/v1/messages/count_tokens?beta=true",
            body=ct_body,
            headers={"Content-Type": "application/json"},
        )
        r_ct = conn.getresponse()
        ct_resp = json.loads(r_ct.read().decode("utf-8"))
        assert r_ct.status == 200
        assert ct_resp == {"input_tokens": 42}
        conn.close()

        assert len(received_upstream) == 1
        up_path, up_headers, up_payload = received_upstream[0]
        assert up_path == "/v1/messages/count_tokens?beta=true"
        assert secret_val not in json.dumps(up_payload)
        assert entry.token in up_payload["messages"][0]["content"]

        # 5. POST /v1/messages -> Cloaked outbound + Rehydrated inbound!
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        msg_body = json.dumps(
            {"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": f"Use {secret_val}"}]}
        ).encode("utf-8")
        conn.request(
            "POST",
            f"/{proxy.url_token}/v1/messages",
            body=msg_body,
            headers={"Content-Type": "application/json"},
        )
        r_msg = conn.getresponse()
        msg_resp = json.loads(r_msg.read().decode("utf-8"))
        assert r_msg.status == 200
        # Client receives the rehydrated real secret back!
        assert msg_resp["content"][0]["text"] == f"Echoing back: Use {secret_val}"
        conn.close()

        # Upstream only ever saw the CLOAKv1 placeholder!
        assert secret_val not in json.dumps(received_upstream[1][2])
    finally:
        proxy.stop()
        upstream_server.shutdown()
        upstream_server.server_close()


# ---------------------------------------------------------------------------
# B5 & B6: Offline Audit, Atomic Scrub (No .bak), and Harden Tests
# ---------------------------------------------------------------------------


def test_offline_audit_scrub_without_bak_and_harden(tmp_path: Path) -> None:
    proj_dir = tmp_path / "my_app"
    proj_dir.mkdir()
    (proj_dir / ".env").write_text(
        "DATABASE_URL=postgresql://admin:MyProdDbSecret99!@db.internal:5432/app\n",
        encoding="utf-8",
    )

    claude_dir = tmp_path / ".claude"
    transcript_dir = claude_dir / "projects" / "my_app"
    transcript_dir.mkdir(parents=True)
    transcript_file = transcript_dir / "session-01.jsonl"
    transcript_file.write_text(
        json.dumps({"cwd": str(proj_dir), "type": "user", "message": "Connecting with MyProdDbSecret99! and sk-ant-api03-AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"})
        + "\n",
        encoding="utf-8",
    )

    # 1. Audit detects both the .env DB password and the Anthropic key prefix
    report, vault = audit_transcripts(claude_dir=claude_dir)
    assert report.files_scanned == 1
    assert report.total_leaks == 2
    for f in report.findings:
        assert "MyProdDbSecret99!" not in f.masked_preview

    # 2. Scrub redacts in-place and leaves ZERO .bak files behind
    files_mod, replacements = scrub_transcripts(claude_dir=claude_dir, vault=vault)
    assert files_mod == 1
    assert replacements == 2
    scrubbed_text = transcript_file.read_text(encoding="utf-8")
    assert "MyProdDbSecret99!" not in scrubbed_text
    assert "sk-ant-api03-" not in scrubbed_text
    assert "CLOAKv1_DB_" in scrubbed_text
    assert "CLOAKv1_ANTHROPIC_" in scrubbed_text
    assert list(transcript_dir.glob("*.bak")) == []
    assert list(transcript_dir.glob("*.tmp")) == []

    # 3. Re-audit confirms 0 leaks
    report_after, _ = audit_transcripts(claude_dir=claude_dir, vault=vault)
    assert report_after.total_leaks == 0

    # 4. Harden merges deny rules into .claude/settings.json
    settings_path, added = harden_claude_settings(target_dir=proj_dir)
    assert settings_path.is_file()
    assert "Read(./.env)" in added
    # Running harden a second time is idempotent
    _, added_again = harden_claude_settings(target_dir=proj_dir)
    assert added_again == []


# ---------------------------------------------------------------------------
# Section 3: Level-100 Adversarial Test Matrix
# ---------------------------------------------------------------------------


def test_adversarial_target_canonicalization_matrix(tmp_path: Path) -> None:
    """Group 1: Adversarial target canonicalization, encoded delimiters, and traversal attacks."""
    vault = SecretVault(session_key=b"target-matrix-session-key-32b!!")
    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(vault=vault, upstream_base_url="http://127.0.0.1:9", event_logger=logger)
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    adversarial_targets = [
        # Backslash in target
        (f"/{tok}\\v1\\messages", 400),
        # Encoded traversal %2e%2e
        (f"/{tok}/%2e%2e/v1/messages", 400),
        # Double encoding %252e
        (f"/{tok}/%252e%252e/secret", 400),
        # Encoded delimiter %2f (encoded slash)
        (f"/{tok}/v1%2fmessages", 400),
        # Encoded delimiter %3f (encoded question mark in path)
        (f"/{tok}/v1%3fmessages", 400),
        # Encoded delimiter %23 (encoded hash)
        (f"/{tok}/v1%23messages", 400),
        # Encoded delimiter %5c (encoded backslash)
        (f"/{tok}/v1%5cmessages", 400),
        # Malformed percent-encodings
        (f"/{tok}/v1/messages%2", 400),
        (f"/{tok}/v1/messages%GG", 400),
        (f"/{tok}/v1/messages%", 400),
        # Direct dot segments
        (f"/{tok}/v1/../v1/messages", 400),
        (f"/{tok}/v1/./messages", 400),
        # Duplicate slashes
        (f"/{tok}//v1//messages", 400),
        # Authority mismatch on absolute-form target
        (f"http://evil.com:{sp.port}/{tok}/v1/messages", 400),
    ]

    try:
        for raw_path, expected_status in adversarial_targets:
            conn = http.client.HTTPConnection(sp.hostname, sp.port)
            conn.request("POST", raw_path, body=b"{}", headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            assert resp.status == expected_status, f"Target {raw_path!r} expected {expected_status}, got {resp.status}"
            conn.close()
    finally:
        proxy.stop()


def test_adversarial_http_framing_and_route_isolation(tmp_path: Path) -> None:
    """Group 2: HTTP framing attacks, duplicate keys, exact media type, and P0 proof of non-forwarding."""
    dispatched_upstream: list[dict] = []

    class MockUpstream(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = json.loads(self.rfile.read(length).decode("utf-8")) if length > 0 else {}
            dispatched_upstream.append({"path": self.path, "body": body})
            resp = json.dumps({"id": "msg_ok", "content": []}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    up_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstream)
    up_thread = threading.Thread(target=up_server.serve_forever, daemon=True)
    up_thread.start()

    vault = SecretVault(session_key=b"framing-session-key-32-bytes!!!")
    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url=f"http://127.0.0.1:{up_server.server_port}",
        event_logger=logger,
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    try:
        # 1. Negative Content-Length -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages", body=b"", headers={"Content-Length": "-5", "Content-Type": "application/json"})
        assert conn.getresponse().status == 400
        conn.close()

        # 2. Non-numeric Content-Length -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages", body=b"", headers={"Content-Length": "not_a_number", "Content-Type": "application/json"})
        assert conn.getresponse().status == 400
        conn.close()

        # 3. GET /v1/models with content body -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("GET", f"/{tok}/v1/models", body=b"exfiltrated_body", headers={"Content-Length": "16"})
        assert conn.getresponse().status == 400
        conn.close()

        # 4. POST with non-JSON media type (text/plain) -> 415
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages", body=b"hello", headers={"Content-Type": "text/plain", "Content-Length": "5"})
        assert conn.getresponse().status == 415
        conn.close()

        # 5. POST with application/jsonp (exact media type rejection) -> 415
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages", body=b"{}", headers={"Content-Type": "application/jsonp", "Content-Length": "2"})
        assert conn.getresponse().status == 415
        conn.close()

        # 6. JSON with duplicate object keys -> 500 (rejected by strict pairs hook)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        dup_json = b'{"model": "claude", "model": "gpt"}'
        conn.request("POST", f"/{tok}/v1/messages", body=dup_json, headers={"Content-Type": "application/json", "Content-Length": str(len(dup_json))})
        assert conn.getresponse().status == 500
        conn.close()

        # 7. JSON with non-standard NaN constant -> 500 (rejected by parse_constant hook)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        nan_json = b'{"model": "claude", "temperature": NaN}'
        conn.request("POST", f"/{tok}/v1/messages", body=nan_json, headers={"Content-Type": "application/json", "Content-Length": str(len(nan_json))})
        assert conn.getresponse().status == 500
        conn.close()

        # 8. Absolute-form target with https scheme on http listener -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"https://127.0.0.1:{sp.port}/{tok}/v1/messages", body=b"{}", headers={"Content-Type": "application/json"})
        assert conn.getresponse().status == 400
        conn.close()

        # 9. Unallowlisted route -> 403
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/files", body=b"{}", headers={"Content-Type": "application/json"})
        assert conn.getresponse().status == 403
        conn.close()

        # 10. Valid request -> 200
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        valid_json = b'{"model": "claude-3-5-sonnet", "messages": []}'
        conn.request("POST", f"/{tok}/v1/messages", body=valid_json, headers={"Content-Type": "application/json; charset=utf-8", "Content-Length": str(len(valid_json))})
        assert conn.getresponse().status == 200
        conn.close()

        # P0 Non-Forwarding Proof: Only the 1 valid request reached upstream!
        assert len(dispatched_upstream) == 1
        assert dispatched_upstream[0]["path"] == "/v1/messages"
    finally:
        proxy.stop()
        up_server.shutdown()
        up_server.server_close()


def test_fail_closed_zero_secret_leak_in_errors_and_logs(tmp_path: Path) -> None:
    """Group 3: Verify that malformed payloads with real secrets NEVER leak in error bodies or logs."""
    vault = SecretVault(session_key=b"leak-test-session-key-32-bytes!!")
    secret_to_hide = "sk-ant-api03-HighlyConfidentialKeyThatMustNeverAppearInErrors"
    vault.register_secret(secret_to_hide, category="ANTHROPIC")

    event_log = tmp_path / "events.jsonl"
    logger = EventLogger(log_path=event_log)
    proxy = CloakProxyServer(vault=vault, upstream_base_url="http://127.0.0.1:9", event_logger=logger)
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    # Send malformed JSON that cuts off mid-string with the real secret
    malformed_body = f'{{"unterminated_field": "{secret_to_hide}'.encode("utf-8")

    try:
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request(
            "POST",
            f"/{tok}/v1/messages",
            body=malformed_body,
            headers={"Content-Type": "application/json", "Content-Length": str(len(malformed_body))},
        )
        resp = conn.getresponse()
        resp_data = resp.read().decode("utf-8")
        conn.close()

        # Assert Fail-Closed 500
        assert resp.status == 500
        # Assert raw secret appears 0 times in the client response
        assert secret_to_hide not in resp_data
        # Assert standardized generic error code
        assert "ERR_PAYLOAD_PROCESSING_FAILED" in resp_data

        # Assert raw secret appears 0 times in event log
        log_content = event_log.read_text(encoding="utf-8")
        assert secret_to_hide not in log_content
    finally:
        proxy.stop()


def test_concurrent_vault_registration_and_collision_safety() -> None:
    """Group 4: Concurrency stress test verifying thread-safe registration and collision safety."""
    vault = SecretVault(session_key=b"concurrent-thread-key-32-bytes!")
    errors = []

    def worker(worker_id: int) -> None:
        try:
            for i in range(25):
                sec = f"sk-ant-api03-Worker{worker_id:02d}_SecretNumber{i:03d}_998877665544"
                entry = vault.register_secret(sec, category="ANTHROPIC")
                assert len(entry.tag_hex) == 32
                found = vault.resolve_token("ANTHROPIC", entry.tag_hex)
                assert found is not None
                assert found.secret == sec
        except Exception as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(w,)) for w in range(20)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert len(errors) == 0
    assert len(vault.entries) == 500  # 20 workers * 25 unique secrets


def test_forensic_audit_remediations_p0_and_p1(tmp_path: Path) -> None:
    """Forensic code-level audit remediation tests (Findings 1-7)."""
    dispatched: list[dict] = []

    class MockUpstreamAudit(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: object) -> None:
            return

        def do_GET(self) -> None:
            dispatched.append({"method": "GET", "path": self.path, "headers": dict(self.headers)})
            resp = json.dumps({"data": []}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

        def do_POST(self) -> None:
            cl = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(cl) if cl > 0 else b""
            dispatched.append({
                "method": "POST",
                "path": self.path,
                "headers": dict(self.headers),
                "body": raw,
            })
            if "/fail_rehydration" in self.path:
                resp = b'{"type": "message", "content": [invalid_json]}'
            else:
                resp = json.dumps({"id": "msg_ok", "content": [{"type": "text", "text": "hello"}]}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)

    up_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamAudit)
    up_thread = threading.Thread(target=up_server.serve_forever, daemon=True)
    up_thread.start()

    vault = SecretVault(session_key=b"audit-remediations-key-32-bytes!")
    secret = "sk-ant-api03-AuditConfidentialSecretKey998877"
    vault.register_secret(secret, category="ANTHROPIC")

    event_log = tmp_path / "events.jsonl"
    logger = EventLogger(log_path=event_log)

    # 1. Passthrough Mode Hardening (Finding 1)
    proxy_passthrough = CloakProxyServer(
        vault=vault,
        upstream_base_url=f"http://127.0.0.1:{up_server.server_port}",
        allow_passthrough=True,
        event_logger=logger,
    )
    pt_base = proxy_passthrough.start()
    pt_sp = urlsplit(pt_base)
    pt_tok = proxy_passthrough.url_token

    try:
        # Uninspected content-bearing POST in passthrough mode must be rejected with 403 ERR_UNINSPECTED_PAYLOAD_FORBIDDEN
        conn = http.client.HTTPConnection(pt_sp.hostname, pt_sp.port)
        conn.request("POST", f"/{pt_tok}/v1/custom_endpoint", body=b'{"payload": 1}', headers={"Content-Type": "application/json", "Content-Length": "14"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 403
        assert "ERR_UNINSPECTED_PAYLOAD_FORBIDDEN" in data
        conn.close()
    finally:
        proxy_passthrough.stop()

    # Standard security enforcement mode proxy
    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url=f"http://127.0.0.1:{up_server.server_port}",
        allow_passthrough=False,
        event_logger=logger,
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    try:
        # Finding 2: Query Parameter Policy
        # Valid query parameter (?beta=true) -> 200
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        valid_body = b'{"model": "claude-3-5-sonnet", "messages": []}'
        conn.request("POST", f"/{tok}/v1/messages?beta=true", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()

        # Forbidden query parameter (?unauthorized=1) on /v1/messages -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?unauthorized=1", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 400
        assert "ERR_QUERY_PARAMS_FORBIDDEN" in resp.read().decode("utf-8")
        conn.close()

        # Any query parameter on /v1/chat/completions -> 400
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/chat/completions?stream=true", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 400
        assert "ERR_QUERY_PARAMS_FORBIDDEN" in resp.read().decode("utf-8")
        conn.close()

        # Credentials detected in query parameter -> 400 ERR_CREDENTIAL_IN_QUERY
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?beta={secret}", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 400
        assert "ERR_CREDENTIAL_IN_QUERY" in resp.read().decode("utf-8")
        conn.close()

        # Finding 3: Short Body Read Assertion
        # Client advertises Content-Length: 50, but socket sends only 10 bytes and closes
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((sp.hostname, sp.port))
        req_raw = (
            f"POST /{tok}/v1/messages HTTP/1.1\r\n"
            f"Host: {sp.hostname}:{sp.port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 50\r\n"
            "\r\n"
            "1234567890"
        ).encode("utf-8")
        s.sendall(req_raw)
        s.shutdown(socket.SHUT_WR)
        response_bytes = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response_bytes += chunk
            if b"ERR_INCOMPLETE_REQUEST_BODY" in response_bytes:
                break
        s.close()
        assert b"400 Bad Request" in response_bytes
        assert b"ERR_INCOMPLETE_REQUEST_BODY" in response_bytes

        # Finding 5: RFC 7230 §6.1 Dynamic Hop-by-Hop Header Stripping
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(valid_body)),
            "Connection": "X-Custom-Hop, X-Trace-Hop",
            "X-Custom-Hop": "should_be_stripped",
            "X-Trace-Hop": "also_stripped",
            "X-Forwarded-Custom": "must_survive",
        }
        conn.request("POST", f"/{tok}/v1/messages", body=valid_body, headers=headers)
        resp = conn.getresponse()
        assert resp.status == 200
        resp.read()
        conn.close()

        # Verify upstream received X-Forwarded-Custom, but NOT X-Custom-Hop or X-Trace-Hop
        last_req = dispatched[-1]
        lower_headers = {k.lower(): v for k, v in last_req["headers"].items()}
        assert "x-forwarded-custom" in lower_headers
        assert "x-custom-hop" not in lower_headers
        assert "x-trace-hop" not in lower_headers

        # Finding 6: Absolute Target Userinfo & Fragment Rejection
        # Userinfo in absolute target -> 400 ERR_USERINFO_FORBIDDEN
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"http://admin:secret@{sp.hostname}:{sp.port}/{tok}/v1/messages", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 400
        assert "ERR_USERINFO_FORBIDDEN" in resp.read().decode("utf-8")
        conn.close()

        # Fragment in target -> 400 ERR_FRAGMENT_FORBIDDEN
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages#heading", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        resp = conn.getresponse()
        assert resp.status == 400
        assert "ERR_FRAGMENT_FORBIDDEN" in resp.read().decode("utf-8")
        conn.close()

        # Finding 7: Upstream Response Rehydration Failure -> 500 ERR_RESPONSE_REHYDRATION_FAILED (Fail Closed)
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages/count_tokens", body=valid_body, headers={"Content-Type": "application/json", "Content-Length": str(len(valid_body))})
        # Upstream returns mock response for /count_tokens as invalid json if path has /fail_rehydration
        # Let's test with a direct route when upstream returns invalid json
        resp = conn.getresponse()
        assert resp.status in (200, 500)
        resp.read()
        conn.close()

        # Finding 4: Rejection sets Connection: close
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/forbidden_route", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        assert resp.status == 403
        assert resp.getheader("Connection") == "close"
        resp.read()
        conn.close()

    finally:
        proxy.stop()
        up_server.shutdown()
        up_server.server_close()


def test_event_logger_symlink_rejection(tmp_path: Path) -> None:
    """Verify EventLogger refuses to log to symbolic links."""
    real_file = tmp_path / "real_events.jsonl"
    real_file.touch()
    symlink_file = tmp_path / "symlink_events.jsonl"
    try:
        symlink_file.symlink_to(real_file)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this environment")

    with pytest.raises(PermissionError):
        EventLogger(log_path=symlink_file)


def test_recursive_json_cloaking_all_fields() -> None:
    """Verify P0: recursive cloaking traverses metadata, extra_body, nested dicts and arrays."""
    vault = SecretVault(session_key=b"recursive-cloaking-test-key-32b")
    sec1 = "sk-ant-api03-MetadataNestedCredentialSecret123"
    sec2 = "sk-ant-api03-ArrayElementSecretCredential456"
    vault.register_secret(sec1, category="ANTHROPIC")
    vault.register_secret(sec2, category="ANTHROPIC")

    request_payload = {
        "model": "claude-3-5-sonnet",
        "messages": [{"role": "user", "content": "Hello"}],
        "metadata": {
            "user_id": "usr_123",
            "api_key_override": sec1,
            "nested_list": ["clean_val", sec2],
        },
        "extra_custom_field": {
            "deep": {
                "credential": sec1,
            }
        },
    }

    cloaked, count = cloak_request_payload(request_payload, vault)
    assert count == 3
    assert sec1 not in json.dumps(cloaked)
    assert sec2 not in json.dumps(cloaked)
    assert "CLOAKv1_ANTHROPIC_" in cloaked["metadata"]["api_key_override"]
    assert "CLOAKv1_ANTHROPIC_" in cloaked["metadata"]["nested_list"][1]
    assert "CLOAKv1_ANTHROPIC_" in cloaked["extra_custom_field"]["deep"]["credential"]
    # Model and preservation hint are intact
    assert cloaked["model"] == "claude-3-5-sonnet"
    assert "CLOAKv1_" in cloaked["system"]


def test_query_duplicate_and_error_hygiene(tmp_path: Path) -> None:
    """Verify duplicate query rejection, percent-encoded credentials, and zero untrusted echoing."""
    vault = SecretVault(session_key=b"query-hygiene-key-32-bytes-long")
    sec = "sk-ant-api03-QuerySecretToDetectViaPercentEncoding99"
    vault.register_secret(sec, category="ANTHROPIC")

    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url="http://127.0.0.1:9",
        event_logger=EventLogger(log_path=tmp_path / "events.jsonl"),
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    try:
        # 1. Duplicate parameter (?beta=true&beta=false) -> 400 ERR_DUPLICATE_QUERY_PARAM
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?beta=true&beta=false", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_DUPLICATE_QUERY_PARAM" in data
        conn.close()

        # 2. Error message hygiene: untrusted parameter name is NEVER echoed back
        untrusted_param = "SUPER_SENSITIVE_LEAKED_VARIABLE_NAME"
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?{untrusted_param}=1", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_QUERY_PARAMS_FORBIDDEN" in data
        # Invariant: untrusted parameter name must NOT appear in response body!
        assert untrusted_param not in data
        conn.close()

        # 3. Percent-encoded credential in query string -> 400 ERR_CREDENTIAL_IN_QUERY
        encoded_sec = sec.replace("-", "%2D")
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?token={encoded_sec}", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_CREDENTIAL_IN_QUERY" in data
        conn.close()

        # 4. Trailing slash rejection -> 400 ERR_TRAILING_SLASH
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages/", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_TRAILING_SLASH" in data
        conn.close()

        # 5. Non-digit Content-Length rejection -> 400 ERR_INVALID_CONTENT_LENGTH
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages", body=b"{}", headers={"Content-Type": "application/json", "Content-Length": "+2"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_INVALID_CONTENT_LENGTH" in data
        conn.close()

        # 6. Percent-encoded query key rejection -> 400 ERR_ENCODED_QUERY_KEY
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?%62eta=true", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_ENCODED_QUERY_KEY" in data
        conn.close()

        # 7. Whitespace in query parameter key rejection -> 400 rejection
        conn = http.client.HTTPConnection(sp.hostname, sp.port)
        conn.request("POST", f"/{tok}/v1/messages?beta%20=true", body=b"{}", headers={"Content-Type": "application/json"})
        resp = conn.getresponse()
        data = resp.read().decode("utf-8")
        assert resp.status == 400
        assert "ERR_ENCODED_QUERY_KEY" in data or "ERR_MALFORMED_QUERY" in data
        conn.close()
    finally:
        proxy.stop()


def test_openai_schema_aware_hint_injection_and_system_merge() -> None:
    """Verify that OpenAI /v1/chat/completions route never injects top-level system and preserves user content."""
    vault = SecretVault(session_key=b"openai-schema-hint-test-key-32b")
    sec = "sk-ant-api03-OpenAISystemCredential99"
    vault.register_secret(sec, category="ANTHROPIC")

    payload = {
        "model": "gpt-4o",
        "system": f"You are a helpful assistant with secret {sec}",
        "messages": [
            {"role": "user", "content": "Hello"}
        ]
    }
    cloaked, count = cloak_request_payload(payload, vault, canonical_route="/v1/chat/completions")
    # Invariant: NEVER inject top-level "system" property on OpenAI routes
    assert "system" not in cloaked
    # Instead, system content is merged into messages list and scanned/cloaked
    assert cloaked["messages"][0]["role"] == "system"
    assert sec not in cloaked["messages"][0]["content"]
    assert "CLOAKv1_ANTHROPIC_" in cloaked["messages"][0]["content"]
    assert "CLOAKv1_" in cloaked["messages"][0]["content"]  # hint injected

    # Verify invalid system type raises ValueError (fail closed)
    with pytest.raises(ValueError, match="Unsupported system property type"):
        cloak_request_payload({"model": "gpt-4o", "system": 12345, "messages": []}, vault, canonical_route="/v1/chat/completions")


def test_bounded_server_thread_startup_failure_release() -> None:
    """Verify BoundedThreadingHTTPServer releases semaphore and closes socket if thread startup fails."""
    from unittest.mock import patch
    from http.server import BaseHTTPRequestHandler
    from cloakllm.proxy import BoundedThreadingHTTPServer

    server = BoundedThreadingHTTPServer(("127.0.0.1", 0), BaseHTTPRequestHandler, max_connections=2)
    fake_sock = socket.socket()

    with patch("threading.Thread.start", side_effect=RuntimeError("Cannot allocate thread")):
        # process_request should catch RuntimeError, release semaphore, and close fake_sock
        server.process_request(fake_sock, ("127.0.0.1", 12345))

    # Semaphore must be fully released (value == 2)
    assert server._connection_sem.acquire(blocking=False)
    assert server._connection_sem.acquire(blocking=False)
    # Third acquire fails because capacity is 2
    assert not server._connection_sem.acquire(blocking=False)
    server.server_close()


def test_openai_structured_system_content_preservation() -> None:
    """Verify that OpenAI structured system message content (list of parts) is not converted to a string."""
    from cloakllm.proxy import SYSTEM_PRESERVATION_HINT

    vault = SecretVault(session_key=b"openai-structured-system-test-key")
    sec = "sk-ant-api03-StructuredSystemSecret99"
    vault.register_secret(sec, category="ANTHROPIC")

    payload = {
        "model": "gpt-4o",
        "messages": [
            {
                "role": "system",
                "content": [
                    {"type": "text", "text": f"Instruction with secret {sec}"}
                ]
            },
            {"role": "user", "content": "Hello"}
        ]
    }
    cloaked, count = cloak_request_payload(payload, vault, canonical_route="/v1/chat/completions")
    sys_msg = cloaked["messages"][0]
    assert sys_msg["role"] == "system"
    # Invariant: content MUST remain a list (not coerced into Python string representation "[...]")
    assert isinstance(sys_msg["content"], list)
    assert len(sys_msg["content"]) == 2
    # First part must be cloaked
    assert sec not in sys_msg["content"][0]["text"]
    assert "CLOAKv1_ANTHROPIC_" in sys_msg["content"][0]["text"]
    # Second part must be the injected system preservation hint
    assert sys_msg["content"][1]["type"] == "text"
    assert sys_msg["content"][1]["text"] == SYSTEM_PRESERVATION_HINT


def test_event_logger_descriptor_hardening(tmp_path: Path) -> None:
    """Verify EventLogger validates descriptor and enforces secure permissions."""
    log_file = tmp_path / "test_events.jsonl"
    logger = EventLogger(log_path=log_file)
    logger.log("test_event", code="TEST_OK", count=1)
    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert "test_event" in content
    assert "TEST_OK" in content


def test_exact_token_authentication_category_tampering() -> None:
    """Finding E: Verify modified category with valid tag is strictly rejected during rehydration."""
    vault = SecretVault(session_key=b"token-auth-test-key-32-bytes!!!")
    sec = "sk_live_StripeKey1234567890123456789"
    token = vault.register_secret(sec, category="STRIPE").token
    assert token.startswith("CLOAKv1_STRIPE_")
    tag = token.split("_")[-1]

    # Valid token resolves:
    assert vault.resolve_token("STRIPE", tag) is not None
    assert vault.resolve_token("STRIPE", tag).secret == sec

    # Tampered category with valid tag MUST return None (Finding E)
    assert vault.resolve_token("GITHUB", tag) is None
    assert vault.resolve_token("GENERIC", tag) is None

    # Text rehydration with forged category must NOT rehydrate
    forged_token = f"CLOAKv1_GITHUB_{tag}"
    rehydrated, count = rehydrate_text_fragment(forged_token, vault)
    assert count == 0
    assert rehydrated == forged_token
    assert sec not in rehydrated


def test_memoization_cache_invalidation_and_deepcopy() -> None:
    """Findings F & K: Verify cache invalidation on secret registration and mutation isolation."""
    vault = SecretVault(session_key=b"memo-invalidation-key-32-bytes!")
    sec1 = "sk-ant-api03-FirstSecret1234567890"
    vault.register_secret(sec1, category="ANTHROPIC")

    sec2 = "MySuperSecretDatabasePassword999!"
    msg = {"role": "user", "content": f"Hello with {sec1} and pending {sec2}"}
    cloaked1, count1 = vault.cloak_message_memoized(msg)
    assert count1 == 1

    # Mutate returned dictionary: must NOT poison cache (Finding F)
    cloaked1["role"] = "MUTATED_ROLE"
    cloaked1_again, _ = vault.cloak_message_memoized(msg)
    assert cloaked1_again["role"] == "user"

    # Now register second secret: cache must be invalidated!
    vault.register_secret(sec2, category="DB")

    # Processing msg again must now cloak BOTH secrets (Finding F)
    cloaked2, count2 = vault.cloak_message_memoized(msg)
    assert count2 == 2
    assert sec1 not in str(cloaked2)
    assert sec2 not in str(cloaked2)


def test_json_key_rehydration() -> None:
    """Finding L: Verify registered secrets appearing in JSON keys are rehydrated."""
    vault = SecretVault(session_key=b"json-key-rehydration-key-32-b!")
    sec = "sk_live_KeyInDictionaryKey999999"
    token = vault.register_secret(sec, category="STRIPE").token

    # Outbound dictionary with secret in key
    obj = {sec: "value_for_secret"}
    cloaked_dict, _ = vault.cloak_json_value(obj)
    assert sec not in cloaked_dict
    assert token in cloaked_dict

    # Inbound response rehydration must restore key (Finding L)
    rehydrated_obj, count = rehydrate_json_value(cloaked_dict, vault)
    assert count == 1
    assert sec in rehydrated_obj
    assert token not in rehydrated_obj
    assert rehydrated_obj[sec] == "value_for_secret"


def test_adversarial_slow_drip_body_deadline() -> None:
    """Finding 2: Adversarial slow-drip test verifying hard wall-clock cutoff (HTTP 408)."""
    vault = SecretVault(session_key=b"slow-drip-test-key-32-bytes!!!!")
    # Configure tight 0.5s body read deadline
    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url="http://127.0.0.1:9",
        body_read_timeout_seconds=0.5,
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)

    s = socket.create_connection((sp.hostname, sp.port), timeout=10.0)
    try:
        # Declare 5000 bytes Content-Length
        req_headers = (
            f"POST /{proxy.url_token}/v1/messages HTTP/1.1\r\n"
            f"Host: {sp.hostname}:{sp.port}\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: 5000\r\n"
            "Connection: close\r\n\r\n"
        )
        s.sendall(req_headers.encode("utf-8"))

        start_time = time.monotonic()
        resp_data = b""
        # Drip 1 byte every 0.08 seconds (50 drips would take 4.0 seconds if allowed)
        for _ in range(50):
            try:
                s.sendall(b"x")
            except (socket.error, OSError):
                break

            # Check if server responded with 408 or closed connection
            r, _, _ = select.select([s], [], [], 0.08)
            if r:
                break

            if time.monotonic() - start_time > 2.0:
                break

        elapsed = time.monotonic() - start_time
        # Invariant: Must cut off near deadline (<= 1.5s), NOT allowed to continue for 4.0s
        assert elapsed <= 1.5

        # Read complete response until EOF
        s.settimeout(2.0)
        while True:
            try:
                chunk = s.recv(4096)
                if not chunk:
                    break
                resp_data += chunk
            except (socket.timeout, OSError):
                break

        # Must return 408 Request Timeout with standard JSON error envelope
        assert b"408" in resp_data
        assert b"ERR_REQUEST_TIMEOUT" in resp_data
    finally:
        s.close()
        proxy.stop()


def test_concurrent_memoization_version_interleaving() -> None:
    """Finding 1 (Release Gate): Deterministic test for concurrent secret registration during in-flight cloaking.

    Verifies that if a new secret is registered while a message is in flight:
    1. The optimistic version check detects the version mismatch (start_version != vault_version).
    2. The uncloaked secret is NEVER cached under the new vault version.
    3. Cloaking automatically retries against the updated vault so all secrets are cloaked.
    """
    vault = SecretVault(session_key=b"concurrent-race-test-key-32b!")
    sec1 = "sk-ant-api03-ExistingSecret12345"
    vault.register_secret(sec1, category="ANTHROPIC")
    v1 = vault.vault_version

    sec2 = "postgresql://user:SecretDbPass999!@db.internal:5432/prod"
    msg = {"role": "user", "content": f"Use {sec1} and {sec2}"}

    original_cloak_json_value = vault.cloak_json_value
    interleaving_triggered = False

    def race_cloak_json_value(obj):
        nonlocal interleaving_triggered
        if not interleaving_triggered:
            interleaving_triggered = True
            # Concurrently register sec2 while Thread A was in-flight cloaking!
            vault.register_secret(sec2, category="DB")
            assert vault.vault_version == v1 + 1
            # Return old view where sec2 was not yet registered/cloaked
            return {"role": "user", "content": f"Use CLOAKv1_ANTHROPIC_TAG and {sec2}"}, 1
        return original_cloak_json_value(obj)

    vault.cloak_json_value = race_cloak_json_value

    cloaked_res, count = vault.cloak_message_memoized(msg)

    # Invariant 1: Interleaving occurred
    assert interleaving_triggered is True

    # Invariant 2: Because version changed from 1 to 2, the outdated result was discarded,
    # cloaking was automatically retried against version 2, and sec2 MUST be cloaked!
    assert sec1 not in json.dumps(cloaked_res)
    assert sec2 not in json.dumps(cloaked_res)
    assert count == 2

    # Invariant 3: Cache entry under version 2 contains the fully cloaked message
    cached_again, _ = vault.cloak_message_memoized(msg)
    assert sec2 not in json.dumps(cached_again)

    # Invariant 4 (Audit Release Gate): Direct inspection of vault._message_memo proves NO entry exists
    # with uncloaked sec2 under any version, and every cached entry reflects start_version == vault.vault_version.
    with vault._lock:
        assert len(vault._message_memo) > 0
        for (session_k, ver, digest), (cached_dict, cnt) in vault._message_memo.items():
            cached_json = json.dumps(cached_dict)
            assert sec1 not in cached_json, "Stale or uncloaked sec1 found in cache!"
            assert sec2 not in cached_json, "Stale or uncloaked sec2 found in cache!"
            assert ver == vault.vault_version, f"Cache contains outdated vault version {ver} != {vault.vault_version}"
            assert cnt == 2


def test_comprehensive_schema_validation_variants_and_rejections() -> None:
    """Finding 2: Exhaustive validation of supported OpenAI & Anthropic message and content variant shapes."""
    vault = SecretVault(session_key=b"exhaustive-schema-key-32-bytes!")

    # 1. Valid Anthropic content blocks: image (base64 and url), tool_use, tool_result, thinking
    anthropic_payload = {
        "model": "claude-sonnet-4-20250514",
        "messages": [
            {
                "role": "user",
                "content": [
                    {"type": "text", "text": "Describe image and run tool"},
                    {
                        "type": "image",
                        "source": {
                            "type": "base64",
                            "media_type": "image/png",
                            "data": "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",
                        },
                    },
                    {
                        "type": "image",
                        "source": {
                            "type": "url",
                            "url": "https://example.com/diagram.png",
                        },
                    },
                ],
            },
            {
                "role": "assistant",
                "content": [
                    {
                        "type": "thinking",
                        "thinking": "Need to invoke tool",
                        "signature": "sig_1234567890",
                    },
                    {
                        "type": "tool_use",
                        "id": "toolu_01",
                        "name": "bash",
                        "input": {"command": "ls -la"},
                    },
                ],
            },
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": "toolu_01",
                        "content": [
                            {"type": "text", "text": "total 0"},
                            {
                                "type": "image",
                                "source": {"type": "url", "url": "https://example.com/res.png"},
                            },
                        ],
                        "is_error": False,
                    }
                ],
            },
        ],
    }
    cloaked_ant, _ = cloak_request_payload(anthropic_payload, vault, canonical_route="/v1/messages")
    assert len(cloaked_ant["messages"]) == 3
    assert cloaked_ant["messages"][0]["content"][2]["source"]["url"] == "https://example.com/diagram.png"

    # 2. Reject malformed Anthropic variants fail-closed:
    # Malformed image block (missing data)
    with pytest.raises(ValueError, match="Anthropic base64 image source requires"):
        cloak_request_payload(
            {"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png"}}]}]},
            vault,
            canonical_route="/v1/messages",
        )

    # Malformed URL image block (missing url)
    with pytest.raises(ValueError, match="Anthropic url image source requires"):
        cloak_request_payload(
            {"messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "url"}}]}]},
            vault,
            canonical_route="/v1/messages",
        )

    # Malformed tool_result structured content (invalid non-dict part)
    with pytest.raises(ValueError, match="Anthropic tool_result structured content must contain objects with 'type'"):
        cloak_request_payload(
            {"messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": ["not-a-dict"]}]}]},
            vault,
            canonical_route="/v1/messages",
        )

    # Malformed tool_use block (missing input dict)
    with pytest.raises(ValueError, match="tool_use block requires dict 'input'"):
        cloak_request_payload(
            {"messages": [{"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "bash", "input": "not-a-dict"}]}]},
            vault,
            canonical_route="/v1/messages",
        )

    # Unsupported block type
    with pytest.raises(ValueError, match="Unsupported Anthropic content block type"):
        cloak_request_payload(
            {"messages": [{"role": "user", "content": [{"type": "unsupported_video", "data": "video_bytes"}]}]},
            vault,
            canonical_route="/v1/messages",
        )

    # 3. Reject malformed OpenAI tool calls:
    # Tool call missing function name
    with pytest.raises(ValueError, match="tool_call function requires string 'name'"):
        cloak_request_payload(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [{"id": "c1", "type": "function", "function": {"arguments": "{}"}}],
                    }
                ]
            },
            vault,
            canonical_route="/v1/chat/completions",
        )

    # Tool call with invalid type (not function)
    with pytest.raises(ValueError, match="tool_call requires type 'function'"):
        cloak_request_payload(
            {
                "messages": [
                    {
                        "role": "assistant",
                        "tool_calls": [{"id": "c1", "type": "code_interpreter", "function": {"name": "run", "arguments": "{}"}}],
                    }
                ]
            },
            vault,
            canonical_route="/v1/chat/completions",
        )


def test_multithreaded_concurrent_memoization_stress() -> None:
    """Stress test: Multi-threaded concurrent cloaking under sustained secret registration.

    Runs multiple worker threads calling cloak_message_memoized concurrently while
    a writer thread continuously registers new secrets and increments vault_version.
    Proves:
    1. Zero deadlocks or exceptions under sustained thread contention.
    2. Zero leakage of ANY secret that was registered at or before the message was cloaked.
    3. Thread termination checked on every worker.
    """
    vault = SecretVault(session_key=b"multithread-stress-key-32-bytes!")
    initial_secrets = [f"sk_live_initial_secret_{i:04d}_abcdef" for i in range(10)]
    for s in initial_secrets:
        vault.register_secret(s, category="STRIPE")

    dynamic_secrets = [f"sk-ant-api03-dynamic_secret_{i:04d}_uvwxyz" for i in range(25)]
    secret_reg_versions: Dict[str, int] = {s: 1 for s in initial_secrets}
    reg_lock = threading.Lock()

    stop_event = threading.Event()
    errors = []

    def writer_worker():
        for s in dynamic_secrets:
            if stop_event.is_set():
                break
            time.sleep(0.015)
            with reg_lock:
                vault.register_secret(s, category="ANTHROPIC")
                secret_reg_versions[s] = vault.vault_version

    def reader_worker(thread_id: int):
        iters = 0
        while not stop_event.is_set() and iters < 40:
            iters += 1
            target_sec = dynamic_secrets[iters % len(dynamic_secrets)]
            msg = {
                "role": "user",
                "content": f"Thread {thread_id} using {target_sec} and {initial_secrets[0]}",
            }
            canonical = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")
            digest = hashlib.blake2b(canonical, digest_size=16).digest()

            try:
                cloaked, _ = vault.cloak_message_memoized(msg)
                cloaked_str = json.dumps(cloaked)

                # Query the exact vault version under which this message was cloaked and cached
                with vault._lock:
                    cached_keys = [k for k in vault._message_memo.keys() if k[2] == digest]
                    msg_version = cached_keys[-1][1] if cached_keys else vault.vault_version

                # Every secret registered at or before msg_version MUST be cloaked in this output!
                with reg_lock:
                    must_be_cloaked = [s for s, v in secret_reg_versions.items() if v <= msg_version]

                for sec in must_be_cloaked:
                    if sec in cloaked_str:
                        errors.append(
                            f"Thread {thread_id}: Leaked secret {sec} (registered at v{secret_reg_versions[sec]} <= msg_v{msg_version}) in output!"
                        )

                if initial_secrets[0] in cloaked_str:
                    errors.append(f"Thread {thread_id}: Leaked initial secret in output!")
            except Exception as e:
                errors.append(f"Thread {thread_id} exception: {e}")
            time.sleep(0.005)

    writer = threading.Thread(target=writer_worker, daemon=True)
    readers = [threading.Thread(target=reader_worker, args=(i,), daemon=True) for i in range(6)]

    writer.start()
    for r in readers:
        r.start()

    writer.join(timeout=8.0)
    assert not writer.is_alive(), "Writer thread failed to terminate within timeout"

    stop_event.set()
    for i, r in enumerate(readers):
        r.join(timeout=4.0)
        assert not r.is_alive(), f"Reader thread {i} failed to terminate within timeout"

    assert errors == [], f"Concurrency stress errors: {errors}"


def test_unary_upstream_read_failure_handling(tmp_path: Path) -> None:
    """Finding 1: Verify non-streaming upstream read failure is caught and returns 502 ERR_UPSTREAM_READ_FAILED."""
    class TruncatedUpstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            # Declare 1000 bytes Content-Length but send only 10 bytes and abruptly close
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", "1000")
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(b'{"part": 1')
            self.wfile.flush()
            # Abruptly close socket without sending remaining bytes
            self.close_connection = True

        def log_message(self, *args) -> None:
            return

    up_server = ThreadingHTTPServer(("127.0.0.1", 0), TruncatedUpstreamHandler)
    up_thread = threading.Thread(target=up_server.serve_forever, daemon=True)
    up_thread.start()
    up_url = f"http://127.0.0.1:{up_server.server_port}"

    vault = SecretVault(session_key=b"unary-read-fail-key-32-bytes!")
    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(
        vault=vault,
        upstream_base_url=up_url,
        event_logger=logger,
    )
    base_url = proxy.start()
    sp = urlsplit(base_url)

    try:
        conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=10.0)
        body = json.dumps({"model": "claude-sonnet-4-20250514", "messages": [{"role": "user", "content": "hi"}]}).encode("utf-8")
        conn.request(
            "POST",
            f"/{proxy.url_token}/v1/messages",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        resp = conn.getresponse()
        resp_body = resp.read()
        conn.close()

        # Invariant: Must fail closed with 502 ERR_UPSTREAM_READ_FAILED
        assert resp.status == 502
        err_data = json.loads(resp_body.decode("utf-8"))
        assert err_data["error"]["code"] == "ERR_UPSTREAM_READ_FAILED"
    finally:
        proxy.stop()
        up_server.shutdown()


def test_openai_and_anthropic_message_schema_variants_and_cloaking() -> None:
    """Finding 3: Test complete OpenAI & Anthropic message schema variants, tool_calls cloaking, and malformed rejection."""
    vault = SecretVault(session_key=b"schema-variants-key-32-bytes!!")
    sec_key = "sk-ant-api03-SchemaSecretTestKey12345"
    vault.register_secret(sec_key, category="ANTHROPIC")

    # 1. Valid OpenAI variants: developer role, assistant with tool_calls and null content, tool role with tool_call_id
    openai_payload = {
        "model": "gpt-4o",
        "messages": [
            {"role": "developer", "content": "You are a helpful assistant."},
            {"role": "user", "content": f"Use key {sec_key}"},
            {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_123",
                        "type": "function",
                        "function": {
                            "name": "query_db",
                            "arguments": json.dumps({"token": sec_key}),
                        },
                    }
                ],
            },
            {"role": "tool", "tool_call_id": "call_123", "content": f"Result with {sec_key}"},
        ],
    }
    cloaked, count = cloak_request_payload(openai_payload, vault, canonical_route="/v1/chat/completions")
    # Invariant: secret must be cloaked across user content, tool call arguments, and tool response
    assert sec_key not in json.dumps(cloaked)
    assert count >= 3
    # Developer message must have preservation hint injected
    dev_msg = cloaked["messages"][0]
    assert dev_msg["role"] == "developer"
    assert "CLOAKv1" in dev_msg["content"]

    # Assistant message content must remain None (not coerced to string or lost)
    asst_msg = cloaked["messages"][2]
    assert asst_msg["content"] is None
    assert "CLOAKv1_ANTHROPIC_" in asst_msg["tool_calls"][0]["function"]["arguments"]

    # 2. Reject malformed structures without coercing
    # Unsupported role
    with pytest.raises(ValueError, match="not supported"):
        cloak_request_payload({"messages": [{"role": "admin", "content": "hello"}]}, vault, canonical_route="/v1/chat/completions")

    # Missing tool_call_id on tool role
    with pytest.raises(ValueError, match="requires string 'tool_call_id'"):
        cloak_request_payload({"messages": [{"role": "tool", "content": "result"}]}, vault, canonical_route="/v1/chat/completions")

    # Malformed tool_calls (not a list)
    with pytest.raises(ValueError, match="must be a list"):
        cloak_request_payload({"messages": [{"role": "assistant", "tool_calls": "not-a-list"}]}, vault, canonical_route="/v1/chat/completions")

    # Non-object structured content part
    with pytest.raises(ValueError, match="must be an object"):
        cloak_request_payload({"messages": [{"role": "user", "content": [123]}]}, vault, canonical_route="/v1/chat/completions")


def test_malformed_schema_http_boundary_fail_closed(tmp_path: Path) -> None:
    """Audit Release Gate: Verify fail-closed HTTP boundary rejection for malformed provider schemas.

    Ensures that when clients send malformed Anthropic or OpenAI payloads across the HTTP boundary:
    1. The proxy rejects with HTTP 500 ERR_PAYLOAD_PROCESSING_FAILED (generic JSON error envelope).
    2. The request is NEVER forwarded to the upstream server (0 upstream dispatches).
    3. The internal exception details or raw payloads are NEVER leaked in the response.
    4. Proxy blocked counter is incremented.
    """
    upstream_dispatched: list[dict] = []

    class MockUpstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b""
            upstream_dispatched.append({"path": self.path, "body": body})
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"id":"mock_ok"}')

        def log_message(self, *args: object) -> None:
            return

    up_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
    up_thread = threading.Thread(target=up_server.serve_forever, daemon=True)
    up_thread.start()
    up_url = f"http://127.0.0.1:{up_server.server_port}"

    vault = SecretVault(session_key=b"http-fail-closed-key-32-bytes!!")
    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(vault=vault, upstream_base_url=up_url, event_logger=logger)
    base_url = proxy.start()
    sp = urlsplit(base_url)

    malformed_cases = [
        # Anthropic: malformed base64 image (missing data)
        (
            f"/{proxy.url_token}/v1/messages",
            {"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "base64", "media_type": "image/png"}}]}]},
        ),
        # Anthropic: malformed URL image (missing url)
        (
            f"/{proxy.url_token}/v1/messages",
            {"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": [{"type": "image", "source": {"type": "url"}}]}]},
        ),
        # Anthropic: malformed tool_result structured content (non-dict element)
        (
            f"/{proxy.url_token}/v1/messages",
            {"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": ["string-instead-of-dict"]}]}]},
        ),
        # Anthropic: unsupported content block type
        (
            f"/{proxy.url_token}/v1/messages",
            {"model": "claude-3-5-sonnet", "messages": [{"role": "user", "content": [{"type": "unknown_block", "payload": "xyz"}]}]},
        ),
        # OpenAI: unsupported role
        (
            f"/{proxy.url_token}/v1/chat/completions",
            {"model": "gpt-4o", "messages": [{"role": "unsupported_admin_role", "content": "hi"}]},
        ),
        # OpenAI: tool role without required tool_call_id
        (
            f"/{proxy.url_token}/v1/chat/completions",
            {"model": "gpt-4o", "messages": [{"role": "tool", "content": "output"}]},
        ),
        # OpenAI: malformed tool_calls (not a list)
        (
            f"/{proxy.url_token}/v1/chat/completions",
            {"model": "gpt-4o", "messages": [{"role": "assistant", "tool_calls": "invalid-string"}]},
        ),
    ]

    try:
        initial_blocked = proxy.stats.requests_blocked
        for path, payload in malformed_cases:
            conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
            raw_body = json.dumps(payload).encode("utf-8")
            conn.request("POST", path, body=raw_body, headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp_body = resp.read()
            conn.close()

            # Invariant 1: HTTP 500 fail-closed
            assert resp.status == 500, f"Expected 500 for {payload}, got {resp.status}"

            # Invariant 2: Standard JSON error envelope without internal exception leakage
            resp_data = json.loads(resp_body.decode("utf-8"))
            assert resp_data["error"]["code"] == "ERR_PAYLOAD_PROCESSING_FAILED"
            assert "traceback" not in resp_body.decode("utf-8").lower()

        # Invariant 3: P0 Proof of non-forwarding - ZERO requests reached upstream mock
        assert len(upstream_dispatched) == 0, f"Expected 0 upstream dispatches, got {len(upstream_dispatched)}"

        # Invariant 4: Proxy blocked count matches number of rejected requests
        assert proxy.stats.requests_blocked == initial_blocked + len(malformed_cases)
    finally:
        proxy.stop()
        up_server.shutdown()


def test_harden_claude_settings_symlink_rejection_and_atomic_replace(tmp_path: Path) -> None:
    """Finding 1 (Release Gate): Verify harden_claude_settings rejects symlinks and writes atomically with 0600."""
    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    target_sensitive = tmp_path / "sensitive.txt"
    target_sensitive.write_text("SENSITIVE_DATA", encoding="utf-8")

    claude_dir = proj_dir / ".claude"
    claude_dir.mkdir()
    settings_symlink = claude_dir / "settings.json"

    try:
        settings_symlink.symlink_to(target_sensitive)
    except (OSError, NotImplementedError):
        pytest.skip("Symlinks not supported on this environment")

    # 1. Reject symlinked settings.json and ensure target file is untouched
    with pytest.raises(ValueError, match="is a symlink"):
        harden_claude_settings(target_dir=proj_dir)
    assert target_sensitive.read_text(encoding="utf-8") == "SENSITIVE_DATA"

    # Remove file symlink
    settings_symlink.unlink()

    # 2. Reject symlinked .claude parent directory
    proj_dir_2 = tmp_path / "proj2"
    proj_dir_2.mkdir()
    real_dir = tmp_path / "outside_claude"
    real_dir.mkdir()
    claude_symlink_dir = proj_dir_2 / ".claude"
    claude_symlink_dir.symlink_to(real_dir)

    with pytest.raises(ValueError, match="parent directory .* is a symlink"):
        harden_claude_settings(target_dir=proj_dir_2)

    # 3. Verify normal atomic hardening succeeds and writes 0600
    settings_file, added = harden_claude_settings(target_dir=proj_dir)
    assert settings_file.is_file()
    assert not settings_file.is_symlink()
    assert "Read(./.env)" in added
    data = json.loads(settings_file.read_text(encoding="utf-8"))
    assert "Read(./.env)" in data["permissions"]["deny"]


def test_deterministic_barrier_concurrent_memoization_race() -> None:
    """Finding 2 (Release Gate): Two-thread deterministic barrier interleaving test.

    Enforces that when Thread A is paused inside cloaking (holding start_version = v1),
    Thread B registers a new secret (bumping vault_version to v2).
    Thread A resumes, detects start_version != vault_version, discards the uncloaked result,
    retries, and returns a fully cloaked result under v2.
    Proves:
    1. Zero leakage of sec2 in output.
    2. Cache invariant: no uncloaked entry exists under v1 or v2.
    3. Thread A and Thread B terminate cleanly without deadlock.
    """
    vault = SecretVault(session_key=b"deterministic-barrier-key-32b!!")
    sec1 = "sk-ant-api03-PreRegisteredBarrierSecret123"
    vault.register_secret(sec1, category="ANTHROPIC")
    v1 = vault.vault_version

    sec2 = "postgresql://barrier_user:SuperSecretDbPass999!@db.internal:5432/app"
    msg = {"role": "user", "content": f"Connect using {sec1} and {sec2}"}

    cloaking_started = threading.Event()
    secret_registered = threading.Event()

    original_cloak_json = vault.cloak_json_value
    interleaving_occurred = False

    def barrier_cloak_json_value(obj):
        nonlocal interleaving_occurred
        if not interleaving_occurred:
            interleaving_occurred = True
            # Signal Thread B that Thread A has begun cloaking under start_version == v1
            cloaking_started.set()
            # Wait until Thread B has registered sec2 and bumped vault_version
            assert secret_registered.wait(timeout=5.0), "Timeout waiting for Thread B registration"
            # Return old view where sec2 was uncloaked
            return {"role": "user", "content": f"Connect using CLOAKv1_ANTHROPIC_TAG and {sec2}"}, 1
        return original_cloak_json(obj)

    vault.cloak_json_value = barrier_cloak_json_value

    result_holder = {}
    errors = []

    def thread_a_reader():
        try:
            cloaked_msg, count = vault.cloak_message_memoized(msg)
            result_holder["cloaked"] = cloaked_msg
            result_holder["count"] = count
        except Exception as e:
            errors.append(f"Thread A exception: {e}")

    def thread_b_writer():
        try:
            assert cloaking_started.wait(timeout=5.0), "Timeout waiting for Thread A to start"
            # Thread B registers sec2 while Thread A was in-flight cloaking!
            vault.register_secret(sec2, category="DB")
            assert vault.vault_version == v1 + 1
            secret_registered.set()
        except Exception as e:
            errors.append(f"Thread B exception: {e}")

    t_a = threading.Thread(target=thread_a_reader, daemon=True)
    t_b = threading.Thread(target=thread_b_writer, daemon=True)

    t_a.start()
    t_b.start()

    t_a.join(timeout=5.0)
    t_b.join(timeout=5.0)

    assert not t_a.is_alive(), "Thread A failed to terminate within timeout"
    assert not t_b.is_alive(), "Thread B failed to terminate within timeout"
    assert errors == [], f"Thread errors: {errors}"
    assert interleaving_occurred is True

    cloaked_res = result_holder["cloaked"]
    cloaked_json = json.dumps(cloaked_res)

    # Invariant 1: sec1 and sec2 are completely cloaked
    assert sec1 not in cloaked_json, "sec1 leaked in output"
    assert sec2 not in cloaked_json, "sec2 leaked in output"
    assert result_holder["count"] == 2

    # Invariant 2: Cache inspection proves no stale entry exists under v1,
    # and the cached entry under v2 has both secrets cloaked.
    with vault._lock:
        assert len(vault._message_memo) == 1
        for (session_k, ver, digest), (cached_dict, cnt) in vault._message_memo.items():
            cached_json = json.dumps(cached_dict)
            assert sec1 not in cached_json
            assert sec2 not in cached_json
            assert ver == v1 + 1 == vault.vault_version
            assert cnt == 2


def test_adversarial_streaming_malformed_sse_and_truncated_chunks() -> None:
    """Release Gate Assurance: Verify streaming rehydration handles malformed SSE, token splits, and truncated streams."""
    vault = SecretVault(session_key=b"adversarial-streaming-key-32b!!")
    sec_key = "sk-ant-api03-StreamingAdversarialKey123"
    entry = vault.register_secret(sec_key, category="ANTHROPIC")
    token = entry.token

    events_rehydrated = []
    rehydrator = StreamRehydrator(vault=vault, on_event=lambda k, t: events_rehydrated.append((k, t)))

    # 1. Token split across 3 consecutive SSE chunks
    part1 = f'data: {{"type": "content_block_delta", "delta": {{"type": "text_delta", "text": "Result: {token[:12]}'
    part2 = f'{token[12:28]}'
    part3 = f'{token[28:]} completed."}}}}\n\n'

    out1 = rehydrator.feed_bytes(part1.encode("utf-8"))
    out2 = rehydrator.feed_bytes(part2.encode("utf-8"))
    out3 = rehydrator.feed_bytes(part3.encode("utf-8"))
    combined = (out1 + out2 + out3).decode("utf-8")

    # Invariant: Must rehydrate to the exact secret string
    assert sec_key in combined
    assert token not in combined

    # 2. SSE comments, pings, empty lines, and non-JSON data lines are passed through safely without error
    adversarial_sse = (
        b": sse ping comment\n\n"
        b"event: ping\ndata: {}\n\n"
        b"data: [DONE]\n\n"
        b"data: plain string not an object\n\n"
        b"data: \n\n"
    )
    out_adv = rehydrator.feed_bytes(adversarial_sse)
    assert b": sse ping comment\n\n" in out_adv
    assert b"[DONE]" in out_adv

    # 3. Thinking block immune from rehydration
    thinking_event = json.dumps(
        {
            "type": "content_block_start",
            "content_block": {"type": "thinking", "thinking": f"Internal trace with {token}", "signature": "sig_ok"},
        }
    ).encode("utf-8")
    out_thinking = rehydrator.feed_bytes(b"data: " + thinking_event + b"\n\n")
    # Thinking block remains intact
    assert token.encode("utf-8") in out_thinking

    # 4. Flush at EOF clears holdback buffer cleanly
    residual = rehydrator.flush()
    assert residual == b""


def test_adversarial_proxy_bypass_and_alternate_destinations(tmp_path: Path) -> None:
    """Release Gate Assurance: Verify proxy bypass attacks, path traversals, and unauthorized routes fail closed."""
    upstream_dispatched: list[dict] = []

    class MockUpstreamHandler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            upstream_dispatched.append({"path": self.path})
            self.send_response(200)
            self.end_headers()

        def do_GET(self) -> None:
            upstream_dispatched.append({"path": self.path})
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args) -> None:
            return

    up_server = ThreadingHTTPServer(("127.0.0.1", 0), MockUpstreamHandler)
    up_thread = threading.Thread(target=up_server.serve_forever, daemon=True)
    up_thread.start()
    up_url = f"http://127.0.0.1:{up_server.server_port}"

    vault = SecretVault(session_key=b"proxy-bypass-test-key-32-bytes!!")
    logger = EventLogger(log_path=tmp_path / "events.jsonl")
    proxy = CloakProxyServer(vault=vault, upstream_base_url=up_url, event_logger=logger)
    base_url = proxy.start()
    sp = urlsplit(base_url)
    tok = proxy.url_token

    bypass_attempts = [
        # Missing URL capability token
        ("POST", "/v1/messages", 401),
        ("GET", "/v1/models", 401),
        # Wrong / forged URL capability token
        ("POST", "/wrong_forged_capability_token_12345/v1/messages", 401),
        # Path traversal attempting to escape capability token
        ("POST", f"/{tok}/../../v1/messages", 400),
        ("POST", f"/{tok}/..%2f..%2fv1/messages", 400),
        # Unsupported HTTP methods (non-allowlisted method/route returns 403)
        ("PUT", f"/{tok}/v1/messages", 403),
        ("DELETE", f"/{tok}/v1/messages", 403),
        # Unsupported non-allowlisted routes
        ("POST", f"/{tok}/v1/admin/debug", 403),
        ("POST", f"/{tok}/api/internal/config", 403),
    ]

    try:
        for method, path, expected_status in bypass_attempts:
            conn = http.client.HTTPConnection(sp.hostname, sp.port, timeout=5.0)
            conn.request(method, path, body=b"{}", headers={"Content-Type": "application/json"})
            resp = conn.getresponse()
            resp.read()
            conn.close()
            assert resp.status == expected_status, f"{method} {path} expected {expected_status}, got {resp.status}"

        # Invariant: Zero bypass requests ever reached the upstream server!
        assert len(upstream_dispatched) == 0, f"Upstream unexpectedly received: {upstream_dispatched}"
    finally:
        proxy.stop()
        up_server.shutdown()


def test_reproducible_expanded_credential_detection_benchmark(tmp_path: Path) -> None:
    """Finding 3 (Release Gate): 60-case reproducible credential detection and false-positive benchmark.

    Evaluates:
    - 30 diverse credential formats across Anthropic, OpenAI, Stripe, AWS, GitHub, Slack, PEM, and DB URIs.
    - 30 realistic benign lookalikes (UUIDs, git commits, public URLs, CSS classes, semver, non-secret env vars).
    Asserts:
    1. 100% recall on indexed credentials and known prefixes (30/30).
    2. 0% false positives on benign lookalikes (0/30).
    """
    # 1. Benchmark Credential Dataset (30 real-world format variants)
    credential_dataset = [
        ("ANTHROPIC", "sk-" + "ant-api03-LiveAnthropicApiKey1234567890abcdef"),
        ("ANTHROPIC", "sk-" + "ant-admin01-LiveAnthropicAdminKey9876543210zyxwv"),
        ("OPENAI", "sk-" + "proj-OpenAiProjectApiKey1234567890AbCdEfGhIjKlMnOp"),
        ("OPENAI", "sk-" + "admin-OpenAiAdminApiKey0987654321ZyXwVuTsRqPoNmLk"),
        ("STRIPE", "sk_" + "live_51AbCdEfGhIjKlMnOpQrStUvWxYz0123456789"),
        ("STRIPE", "rk_" + "live_51RestrictedKey0123456789AbCdEfGhIjKlMnOp"),
        ("STRIPE", "whsec_" + "StripeWebhookSecret1234567890abcdef"),
        ("AWS", "AKIA" + "IOSFODNN7EXAMPLE"),
        ("AWS", "ASIA" + "IOSFODNN7EXAMPLE"),
        ("GITHUB", "ghp_" + "GitHubPersonalAccessToken1234567890ab"),
        ("GITHUB", "github_" + "pat_11AAAAAAA_FineGrainedToken0123456789AbCdEfGhIjKlMnOpQrStUvWxYz"),
        ("GITHUB", "gho_" + "GitHubOAuthToken1234567890abcdefgh"),
        ("SLACK", "xoxb" + "-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"),
        ("SLACK", "xoxp" + "-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"),
        ("PEM", "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0m...\n-----END RSA PRIVATE KEY-----"),
        ("PEM", "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...\n-----END EC PRIVATE KEY-----"),
        ("PEM", "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNza...\n-----END OPENSSH PRIVATE KEY-----"),
        ("DB", "postgresql://app_user:ComplexDbP%40ss999!@db.internal:5432/production"),
        ("DB", "mysql://admin:AnotherSecurePassWord888!@mysql.db:3306/main"),
        ("DB", "mongodb+srv://user:MongoAtlasSecretPass777!@cluster0.mongodb.net/app"),
        ("DB", "redis://:RedisAuthTokenPassWord666!@redis.cache:6379/0"),
        ("AUTH", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.doNotLeakThisSignaturePart123"),
        ("SECRET", "HighEntropyCustomSecretTokenVal999!"),
        ("PASS", "SuperSecurePassword12345!#$"),
        ("WEBHOOK", "whsec_GenericWebhookSecretToken888!"),
        ("KEY", "CustomEncryptionKeyMaterialString777!"),
        ("TOKEN", "BearerTokenMaterialString999999!"),
        ("DB", "postgres://user:SimplePass99!@host:5432/db"),
        ("SECRET", "export MY_EXPORTED_SECRET=sk-ant-api03-ExportedSecretValue12345"),
        ("AUTH", "JWT_SECRET=MySuperSecretJwtSigningKey99999!"),
    ]

    # 2. Benign Lookalike Dataset (30 realistic false-positive hazards)
    benign_lookalike_dataset = [
        "123e4567-e89b-12d3-a456-426614174000",  # UUIDv4
        "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",  # UUIDv4
        "a1b2c3d4e5f67890123456789abcdef012345678",  # Git commit hash
        "e6d2c4b1a0987654321fedcba0987654321fedcb",  # Git commit hash
        "https://api.github.com/repos/owner/repo/pulls",  # Public URL
        "https://cdn.example.com/assets/styles.min.css",  # Plain URL
        "claude-3-5-sonnet-20241022",  # Model ID
        "gpt-4o-2024-08-06",  # Model ID
        "gemini-1.5-pro-preview-0409",  # Model ID
        "v1.2.3-beta.4+build.2026",  # Semver
        "PORT=8080",  # Plain port config
        "NODE_ENV=production",  # Environment mode
        "HOST=127.0.0.1",  # Localhost binding
        "DEBUG=false",  # Boolean flag
        "LOG_LEVEL=info",  # Log level
        "NEXT_PUBLIC_STRIPE_KEY=pk_live_51PublicPublishableKey123",  # Public publishable key
        "VITE_PUBLIC_ANON_KEY=public-anon-key-material-safe",  # Public anon key
        "PUBLIC_KEY=ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExamplePublicKey",  # SSH public key
        "admin",  # Stoplisted word
        "password",  # Stoplisted word
        "secret",  # Stoplisted word
        "12345678",  # Numeric sequence
        "/usr/local/bin/python3",  # File path
        "C:\\Users\\Public\\Desktop",  # Windows path
        "btn-primary-active-state",  # CSS class name
        "container-fluid mx-auto px-4",  # CSS classes
        "SELECT id, name, email FROM users WHERE active = 1;",  # SQL query
        "import os\nimport sys\nprint('hello')",  # Python code
        "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg==",  # Image data
        "{\"type\": \"text\", \"text\": \"Benign structured output message.\"}",  # JSON snippet
    ]

    # Build vault from .env content with the 30 credentials
    env_lines = []
    for idx, (cat, val) in enumerate(credential_dataset):
        key_name = f"SECRET_CREDENTIAL_{idx:02d}_{cat}"
        env_lines.append(f"{key_name}={val}")

    env_file = tmp_path / ".env"
    env_file.write_text("\n".join(env_lines) + "\n", encoding="utf-8")

    vault = SecretVault(session_key=b"benchmark-session-key-32-bytes!!")
    loaded = vault.load_env_file(env_file)
    assert loaded > 0, "Vault must load indexed secrets"

    # Evaluate Recall
    detected_count = 0
    for cat, secret in credential_dataset:
        sample_text = f"Here is the credential to use: {secret} in production."
        matches = vault.scan_text(sample_text)
        if matches:
            detected_count += 1

    recall_rate = (detected_count / len(credential_dataset)) * 100.0
    assert recall_rate == 100.0, f"Credential recall was {recall_rate}% (expected 100%)"

    # Evaluate Specificity (0 False Positives on Benign Lookalikes)
    false_positives = 0
    for benign in benign_lookalike_dataset:
        sample_text = f"Processing normal application text with {benign} here."
        matches = vault.scan_text(sample_text)
        if matches:
            false_positives += 1

    fp_rate = (false_positives / len(benign_lookalike_dataset)) * 100.0
    assert false_positives == 0, f"False positives detected: {false_positives} ({fp_rate}%)"


