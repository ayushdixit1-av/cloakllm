"""Command-line interface for CloakLLM: audit, scrub, harden, run, and status."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
from pathlib import Path
from typing import List, Optional

from cloakllm import __version__
from cloakllm.audit import (
    audit_transcripts,
    default_claude_dir,
    harden_claude_settings,
    scrub_transcripts,
)
from cloakllm.proxy import CloakProxyServer, EventLogger
from cloakllm.secrets import SecretVault


def _cmd_audit(args: argparse.Namespace) -> int:
    claude_dir = Path(args.claude_dir) if args.claude_dir else None
    project_dirs = [Path(p) for p in args.project_dir] if args.project_dir else [Path.cwd()]
    extra_paths = [Path(p) for p in args.transcript] if args.transcript else None

    report, _ = audit_transcripts(
        claude_dir=claude_dir,
        project_dirs=project_dirs,
        extra_transcript_paths=extra_paths,
    )

    if args.json:
        payload = {
            "files_scanned": report.files_scanned,
            "lines_scanned": report.lines_scanned,
            "env_secrets_loaded": report.env_secrets_loaded,
            "total_leaks": report.total_leaks,
            "by_category": report.by_category,
            "by_file": report.by_file,
            "findings": [
                {
                    "file": str(f.file_path),
                    "line": f.line_number,
                    "category": f.category,
                    "source": f.source,
                    "masked_preview": f.masked_preview,
                    "token": f.token,
                }
                for f in report.findings
            ],
        }
        print(json.dumps(payload, indent=2))
        return 1 if report.total_leaks > 0 else 0

    print(f"CloakLLM v{__version__} -- Offline Claude Code Transcript Audit")
    print("=" * 64)
    print(f"  Transcripts scanned : {report.files_scanned} files ({report.lines_scanned:,} lines)")
    print(f"  .env secrets indexed: {report.env_secrets_loaded} high-confidence credentials")
    print("-" * 64)

    if report.total_leaks == 0:
        print("  STATUS: CLEAN (0 plaintext secrets found in transcripts)")
        return 0

    print(f"  STATUS: LEAKS DETECTED ({report.total_leaks} plaintext secret occurrences)")
    print("\n  Breakdown by Category:")
    for cat, count in sorted(report.by_category.items(), key=lambda x: -x[1]):
        print(f"    - {cat:<12}: {count} leak(s)")

    print("\n  Sample Findings (masked for terminal safety):")
    for finding in report.findings[:15]:
        short_file = finding.file_path.name
        print(
            f"    [{finding.category}] {short_file}:{finding.line_number} "
            f"({finding.source}) -> {finding.masked_preview}"
        )
    if len(report.findings) > 15:
        print(f"    ... and {len(report.findings) - 15} more occurrences.")

    print("\n  Next Steps:")
    print("    1. Run `cloakllm scrub` to atomically redact transcripts in-place (0600, no .bak).")
    print("    2. Run `cloakllm harden` to add Read(.env*) deny rules to .claude/settings.json.")
    print("    3. Launch sessions with `cloakllm run -- claude` for live bidirectional cloaking.")
    return 1


def _cmd_scrub(args: argparse.Namespace) -> int:
    claude_dir = Path(args.claude_dir) if args.claude_dir else None
    project_dirs = [Path(p) for p in args.project_dir] if args.project_dir else [Path.cwd()]
    extra_paths = [Path(p) for p in args.transcript] if args.transcript else None

    files_modified, total_replacements = scrub_transcripts(
        claude_dir=claude_dir,
        project_dirs=project_dirs,
        extra_transcript_paths=extra_paths,
    )
    print(
        f"CloakLLM Scrub Complete: Redacted {total_replacements} secret(s) "
        f"across {files_modified} transcript file(s) (atomic 0600 replace, zero .bak files)."
    )
    return 0


def _cmd_harden(args: argparse.Namespace) -> int:
    target_dir = Path(args.dir) if args.dir else Path.cwd()
    settings_path, added = harden_claude_settings(target_dir=target_dir, use_global=args.global_settings)
    if added:
        print(f"CloakLLM Harden: Added {len(added)} secret-file deny rule(s) to {settings_path}:")
        for r in added:
            print(f"  + {r}")
    else:
        print(f"CloakLLM Harden: All secret-file deny rules already present in {settings_path}.")
    print(
        "Note: .claude/settings.json blocks direct Read(.env) tool calls. "
        "Always pair with `cloakllm run -- claude` to intercept secrets emitted by Bash commands or test logs."
    )
    return 0


def _cmd_status(args: argparse.Namespace) -> int:
    logger = EventLogger()
    if not logger.log_path.is_file():
        print(f"No CloakLLM event log found at {logger.log_path}")
        return 0

    lines = logger.log_path.read_text(encoding="utf-8", errors="replace").splitlines()
    events = []
    for line in lines:
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue

    redacted = sum(int(e.get("redacted_count", 0)) for e in events if e.get("event") == "request_cloaked")
    rehydrated = sum(1 for e in events if e.get("event") == "rehydrated")
    blocked = sum(1 for e in events if e.get("event") in ("auth_rejected", "endpoint_blocked", "request_cloak_error"))

    print(f"CloakLLM Status ({logger.log_path})")
    print("=" * 60)
    print(f"  Total logged events       : {len(events)}")
    print(f"  Outbound secrets cloaked  : {redacted}")
    print(f"  Inbound tokens rehydrated : {rehydrated}")
    print(f"  Fail-closed blocks        : {blocked}")
    tail_n = max(1, int(args.tail))
    if events:
        print(f"\n  Last {min(tail_n, len(events))} Event(s):")
        for ev in events[-tail_n:]:
            ev_name = ev.get("event", "unknown")
            details = {k: v for k, v in ev.items() if k not in ("ts", "event")}
            print(f"    - {ev_name}: {json.dumps(details)}")
    return 0


def _cmd_run(args: argparse.Namespace) -> int:
    cmd: List[str] = list(args.command)
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        print("Error: Specify a command to run, e.g. `cloakllm run -- claude`", file=sys.stderr)
        return 2

    project_dirs = [Path(p) for p in args.project_dir] if args.project_dir else [Path.cwd()]
    vault = SecretVault()
    vault.load_project_dirs(project_dirs)

    upstream = args.upstream or os.environ.get("CLOAKLLM_UPSTREAM_URL", "https://api.anthropic.com")
    server = CloakProxyServer(
        vault=vault,
        upstream_base_url=upstream,
        allow_passthrough=bool(args.allow_passthrough),
    )
    proxy_base_url = server.start()

    env = os.environ.copy()
    env["ANTHROPIC_BASE_URL"] = proxy_base_url
    if args.set_openai_base_url:
        env["OPENAI_BASE_URL"] = f"{proxy_base_url}/v1"

    exe = shutil.which(cmd[0]) or cmd[0]
    exit_code = 0
    old_sigint = signal.getsignal(signal.SIGINT)
    try:
        proc = subprocess.Popen([exe, *cmd[1:]], env=env)
        # Ignore SIGINT in parent while child interactive TUI is running so Ctrl+C
        # cancels the child's current operation without killing the proxy mid-session (B6)
        signal.signal(signal.SIGINT, signal.SIG_IGN)
        exit_code = proc.wait()
    except FileNotFoundError:
        print(f"CloakLLM Error: Command not found: {cmd[0]}", file=sys.stderr)
        exit_code = 127
    finally:
        signal.signal(signal.SIGINT, old_sigint)
        server.stop()

    if not args.quiet:
        sys.stderr.write(
            f"[CloakLLM] Session closed -- {server.stats.secrets_redacted_outbound} outbound secret(s) cloaked, "
            f"{server.stats.tokens_rehydrated_inbound} inbound token(s) rehydrated.\n"
        )
    return exit_code


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cloakllm",
        description=(
            "CloakLLM: Local-first secret & credential firewall for Claude Code. "
            "Audit and scrub ~/.claude transcripts offline, and cloak secrets in real time."
        ),
    )
    parser.add_argument("--version", action="version", version=f"cloakllm {__version__}")
    sub = parser.add_subparsers(dest="subcommand")

    # audit
    p_audit = sub.add_parser("audit", help="Scan ~/.claude transcripts offline for leaked project secrets")
    p_audit.add_argument("--claude-dir", help="Override ~/.claude directory path")
    p_audit.add_argument("--project-dir", action="append", help="Additional project directory with .env files")
    p_audit.add_argument("--transcript", action="append", help="Specific transcript file or directory to scan")
    p_audit.add_argument("--json", action="store_true", help="Emit machine-readable JSON report")

    # scrub
    p_scrub = sub.add_parser("scrub", help="Atomically redact leaked secrets in-place across ~/.claude transcripts")
    p_scrub.add_argument("--claude-dir", help="Override ~/.claude directory path")
    p_scrub.add_argument("--project-dir", action="append", help="Additional project directory with .env files")
    p_scrub.add_argument("--transcript", action="append", help="Specific transcript file or directory to scrub")

    # harden
    p_harden = sub.add_parser("harden", help="Add secret-file Read(...) deny rules to .claude/settings.json")
    p_harden.add_argument("--global", dest="global_settings", action="store_true", help="Modify ~/.claude/settings.json")
    p_harden.add_argument("--dir", help="Target project directory (default: current working directory)")

    # status
    p_status = sub.add_parser("status", help="Inspect ~/.cloakllm/events.jsonl metrics and recent events")
    p_status.add_argument("--tail", type=int, default=10, help="Number of recent events to display")

    # run
    p_run = sub.add_parser("run", help="Run a command (e.g. `cloakllm run -- claude`) behind the fail-closed cloaking proxy")
    p_run.add_argument("--upstream", help="Upstream API base URL (default: https://api.anthropic.com)")
    p_run.add_argument("--project-dir", action="append", help="Project directory with .env files to load")
    p_run.add_argument(
        "--allow-passthrough",
        action="store_true",
        help="Allow non-messages endpoints (/v1/files, /v1/batches) to pass through uncloaked",
    )
    p_run.add_argument(
        "--set-openai-base-url",
        action="store_true",
        help="Also set OPENAI_BASE_URL for OpenAI-compatible CLI tools",
    )
    p_run.add_argument("--quiet", action="store_true", help="Suppress the 1-line post-session summary")
    p_run.add_argument("command", nargs=argparse.REMAINDER, help="Command and arguments to execute (after --)")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "audit":
        return _cmd_audit(args)
    if args.subcommand == "scrub":
        return _cmd_scrub(args)
    if args.subcommand == "harden":
        return _cmd_harden(args)
    if args.subcommand == "status":
        return _cmd_status(args)
    if args.subcommand == "run":
        return _cmd_run(args)
    parser.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
