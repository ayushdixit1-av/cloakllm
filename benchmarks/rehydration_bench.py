"""Reproducible benchmark suite for CloakLLM:
1. 5-Gate .env Precision & False-Positive Rate
2. 200-Case Streaming & Tool-Call Rehydration Survival Benchmark
3. 100k-Token Multi-Turn Memoization Latency Benchmark
"""

from __future__ import annotations

import json
import time
from typing import List, Tuple

from cloakllm.proxy import cloak_request_payload
from cloakllm.secrets import SecretVault, extract_secrets_from_env_pair
from cloakllm.stream import StreamRehydrator, rehydrate_text_fragment


def run_env_gate_benchmark() -> dict:
    # 25 Benign / Public / Config entries (MUST NOT trigger)
    benign_pairs: List[Tuple[str, str]] = [
        ("NODE_ENV", "production"),
        ("PORT", "3000"),
        ("HOST", "0.0.0.0"),
        ("DEBUG", "false"),
        ("LOG_LEVEL", "info"),
        ("AUTHOR", "ayush_dixit_engineering_lead"),
        ("MONKEY_PATCH", "enabled_for_legacy_adapter"),
        ("BYPASS_AUTH", "false"),
        ("AUTH_ENABLED", "true"),
        ("API_URL", "https://api.stripe.com/v1/payment_intents"),
        ("GRAPHQL_ENDPOINT", "https://api.github.com/graphql"),
        ("OAUTH_TOKEN_URL", "https://oauth2.googleapis.com/token"),
        ("JWKS_URI", "https://auth.mycorp.com/.well-known/jwks.json"),
        ("NEXT_PUBLIC_API_KEY", "AIzaSyPublicFrontendKeyDoNotCloak999"),
        ("VITE_STRIPE_PUBLIC_KEY", "pk_live_51Nz89JkL90123456789abcde"),
        ("STRIPE_PUBLISHABLE_KEY", "pk_test_51Nz89JkL90123456789abcde"),
        ("SUPABASE_ANON_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.anon"),
        ("JWT_PUBLIC_KEY", "-----BEGIN PUBLIC KEY-----MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A"),
        ("AWS_KMS_KEY_ID", "arn:aws:kms:us-east-1:111122223333:key/1234abcd-56ef"),
        ("SSH_PRIVATE_KEY_PATH", "/home/ubuntu/.ssh/id_ed25519"),
        ("TLS_KEY_FILE", "./certs/server.key"),
        ("DATABASE_URL", "postgresql://localhost:5432/dev_db"),
        ("REDIS_URI", "redis://127.0.0.1:6379/0"),
        ("API_SECRET", "changeme"),
        ("WEBHOOK_SECRET", "${WEBHOOK_SECRET_FROM_VAULT}"),
    ]

    # 25 Real Secret entries (MUST trigger)
    secret_pairs: List[Tuple[str, str]] = [
        ("ANTHROPIC_API_KEY", "sk-ant-api03-9kL2mN4pQ6rS8tU0vW2xY4zA6bC8dE0fG2hI4jK6"),
        ("OPENAI_API_KEY", "sk-proj-7mP9qR2tV4xZ6bN8cM0kL3jH5gF7dS9aW1eR3tY5"),
        ("GITHUB_TOKEN", "ghp_1234567890abcdefghijklmnopqrstuvwxyzABCD"),
        ("AWS_SECRET_ACCESS_KEY", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY99"),
        ("STRIPE_SECRET_KEY", "sk_live_51M9qR2tV4xZ6bN8cM0kL3jH5gF7dS9aW1eR3tY5"),
        ("SLACK_BOT_TOKEN", "xoxb-123456789012-345678901234-AbCdEfGhIjKlMnOpQrStUvWx"),
        ("DATABASE_URL", "postgresql://prod_user:K9#mP2$vL8@nQ4!xR7z@db.prod.internal:5432/core"),
        ("REDIS_URL", "redis://default:R3d1sPr0dP@ssw0rd_99887766@cache.internal:6379/0"),
        ("WEBHOOK_URL", "https://hooks.internal.net/ingest?token=wh_tok_9876543210abcdefXYZ"),
        ("JWT_SECRET", "8f9a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9c1d3e"),
        ("SESSION_SECRET", "s3ss10n_k3y_v3ry_h1gh_3ntr0py_9876543210!@#"),
        ("DB_PASSWORD", "Pr0d_PgSql#2026!"),
        ("ADMIN_PASSWD", "Adm1n$P@ssw0rd99"),
        ("REDIS_PWD", "R3d1s#Auth!2026"),
        ("SENDGRID_API_KEY", "SG.aBcDeFgHiJkLmNoPqRsTuV.wXyZ0123456789aBcDeFgHiJkLmNoPqRsTuVwXyZ"),
        ("TWILIO_AUTH_TOKEN", "9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d"),
        ("CLOUDFLARE_API_TOKEN", "cf_tok_K8mP2xQ9vL4nR7tY1wZ3cB6fH0jM5sD8aE2gJ"),
        ("DATADOG_API_KEY", "dd_api_9876543210abcdef1234567890abcdef"),
        ("SUPABASE_SERVICE_ROLE_KEY", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.service_role_secret_998877"),
        ("DISCORD_WEBHOOK_SECRET", "dwh_7kL9mN2pQ4rS6tU8vW0xY2zA4bC6dE8f"),
        ("ENCRYPTION_PRIVATE_KEY", "priv_k3y_A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6"),
        ("OAUTH_CLIENT_SECRET", "GOCSPX-9aBcDeFgHiJkLmNoPqRsTuVwXyZ01234"),
        ("SENTRY_DSN", "https://public_key:S3ntryPr1v@t3S3cr3t99@o1234.ingest.sentry.io/5678"),
        ("MONGO_URI", "mongodb+srv://svc_app:M0ng0Pr0d#Secret99@cluster0.example.mongodb.net/app"),
        ("HF_API_TOKEN", "hf_aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789"),
    ]

    fp = sum(1 for k, v in benign_pairs if extract_secrets_from_env_pair(k, v))
    tp = sum(1 for k, v in secret_pairs if extract_secrets_from_env_pair(k, v))
    return {
        "benign_tested": len(benign_pairs),
        "false_positives": fp,
        "false_positive_rate_pct": round(100.0 * fp / len(benign_pairs), 2),
        "secrets_tested": len(secret_pairs),
        "true_positives": tp,
        "recall_pct": round(100.0 * tp / len(secret_pairs), 2),
    }


def run_rehydration_survival_benchmark() -> dict:
    vault = SecretVault(session_key=b"benchmark-session-key-32-bytes!!")
    secrets_list = [
        f"sk-ant-api03-BenchSecretKeyNumber{i:03d}_AbCdEfGhIjKlMnOpQrStUvWxYz"
        for i in range(40)
    ]
    entries = [vault.register_secret(s, category="ANTHROPIC") for s in secrets_list]

    categories = {
        "1_exact_prose_and_code": [0, 0],
        "2_markdown_escaped_underscores": [0, 0],
        "3_json_tool_call_u005f_and_dbl_backslash": [0, 0],
        "4_split_across_1_to_5_byte_sse_chunks": [0, 0],
        "5_corrupted_token_non_substitution_integrity": [0, 0],
    }

    for idx, entry in enumerate(entries):
        # Category 1: Exact prose/code
        categories["1_exact_prose_and_code"][1] += 1
        out, _ = rehydrate_text_fragment(f"export KEY='{entry.token}'", vault)
        if entry.secret in out:
            categories["1_exact_prose_and_code"][0] += 1

        # Category 2: Markdown backslash-escaped underscores (`\_`)
        categories["2_markdown_escaped_underscores"][1] += 1
        md_tok = entry.token.replace("_", r"\_")
        out_md, _ = rehydrate_text_fragment(f"Use `{md_tok}` in your config", vault)
        if entry.secret in out_md:
            categories["2_markdown_escaped_underscores"][0] += 1

        # Category 3: Raw JSON tool-call delta with \u005f and \\_
        categories["3_json_tool_call_u005f_and_dbl_backslash"][1] += 1
        raw_j = (
            f'{{"cmd": "curl -H \\"X-Key: CLOAKv1\\u005fANTHROPIC\\u005f{entry.tag_hex}\\" '
            f'CLOAKv1\\\\_ANTHROPIC\\\\_{entry.tag_hex}"}}'
        )
        out_j, c_j = rehydrate_text_fragment(raw_j, vault, is_raw_json_fragment=True)
        parsed = json.loads(out_j)
        if c_j == 2 and parsed["cmd"].count(entry.secret) == 2:
            categories["3_json_tool_call_u005f_and_dbl_backslash"][0] += 1

        # Category 4: Split across tiny 1-5 byte TCP/SSE chunks
        categories["4_split_across_1_to_5_byte_sse_chunks"][1] += 1
        tok = entry.token
        p1, p2, p3 = tok[:12], tok[12:28], tok[28:]
        sse_events = [
            {"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p1}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p2}},
            {"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": p3}},
            {"type": "content_block_stop", "index": 0},
            {"type": "message_stop"},
        ]
        wire = "".join(f"event: {e['type']}\ndata: {json.dumps(e)}\n\n" for e in sse_events).encode("utf-8")
        rehydrator = StreamRehydrator(vault=vault)
        buf = bytearray()
        step = (idx % 5) + 1
        for pos in range(0, len(wire), step):
            buf.extend(rehydrator.feed_bytes(wire[pos : pos + step]))
        buf.extend(rehydrator.flush())
        if entry.secret.encode("utf-8") in buf:
            categories["4_split_across_1_to_5_byte_sse_chunks"][0] += 1

        # Category 5: C3 Credential Non-Substitution Integrity
        # Corrupted or unknown tokens MUST NEVER trigger credential substitution
        categories["5_corrupted_token_non_substitution_integrity"][1] += 1
        bad_char = "0" if entry.tag_hex[-1] != "0" else "1"
        corrupted_tok = f"CLOAKv1_ANTHROPIC_{entry.tag_hex[:-1]}{bad_char}"
        out_c, count_c = rehydrate_text_fragment(f"key={corrupted_tok}", vault)
        if count_c == 0 and entry.secret not in out_c and corrupted_tok in out_c:
            categories["5_corrupted_token_non_substitution_integrity"][0] += 1

    total_passed = sum(v[0] for v in categories.values())
    total_cases = sum(v[1] for v in categories.values())
    return {
        "total_cases": total_cases,
        "total_passed": total_passed,
        "overall_survival_pct": round(100.0 * total_passed / total_cases, 2),
        "breakdown": {k: f"{v[0]}/{v[1]} ({100.0*v[0]/v[1]:.1f}%)" for k, v in categories.items()},
    }


def run_latency_benchmark() -> dict:
    vault = SecretVault(session_key=b"latency-bench-session-key-32byte")
    for i in range(15):
        vault.register_secret(f"sk-ant-api03-LatencyBenchSecret{i:02d}_9876543210abcdef", category="ANTHROPIC")

    # Build a 50-turn conversation (~100k tokens / ~400 KB of code & prose)
    turn_text = ("def process_payment(user_id: str, amount: int) -> dict:\n    " + ("x = 42 # padding line\n    " * 180))
    messages = [
        {"role": "user" if i % 2 == 0 else "assistant", "content": f"Turn {i}: {turn_text}"}
        for i in range(50)
    ]
    payload = {"model": "claude-sonnet-4-20250514", "system": "You are a coding assistant.", "messages": messages}

    # 1. Cold full-conversation scan
    t0 = time.perf_counter()
    cloak_request_payload(payload, vault)
    cold_ms = (time.perf_counter() - t0) * 1000.0

    # 2. Warm next-turn scan (49 cached turns + 1 new turn with a secret)
    messages_next = list(messages) + [
        {
            "role": "user",
            "content": "Here is the new turn with sk-ant-api03-LatencyBenchSecret01_9876543210abcdef",
        }
    ]
    payload_next = {"model": "claude-sonnet-4-20250514", "system": "You are a coding assistant.", "messages": messages_next}
    t1 = time.perf_counter()
    cloak_request_payload(payload_next, vault)
    warm_ms = (time.perf_counter() - t1) * 1000.0

    return {
        "conversation_turns": len(messages_next),
        "payload_kilobytes": round(len(json.dumps(payload_next)) / 1024.0, 1),
        "cold_scan_ms": round(cold_ms, 2),
        "memoized_next_turn_ms": round(warm_ms, 2),
    }


def main() -> None:
    env_res = run_env_gate_benchmark()
    surv_res = run_rehydration_survival_benchmark()
    lat_res = run_latency_benchmark()
    report = {
        "env_5_gate_benchmark": env_res,
        "rehydration_200_case_benchmark": surv_res,
        "latency_100k_token_benchmark": lat_res,
    }
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
