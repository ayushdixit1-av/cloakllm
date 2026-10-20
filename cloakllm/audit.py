"""100% Stdlib Offline Transcript Auditor, Atomic Scrubber & Claude Code Hardener."""

from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple

from cloakllm.secrets import SecretEntry, SecretVault


def mask_secret_preview(secret: str) -> str:
    """Mask a secret for safe terminal display (e.g. sk-ant-...9f2a). Never prints full secret."""
    clean = secret.replace("\n", "\\n").replace("\r", "")
    if len(clean) <= 10:
        return clean[:2] + "***" + clean[-2:]
    return f"{clean[:6]}...{clean[-4:]}"


@dataclass
class LeakFinding:
    file_path: Path
    line_number: int
    category: str
    source: str
    masked_preview: str
    token: str


@dataclass
class AuditReport:
    files_scanned: int = 0
    lines_scanned: int = 0
    env_secrets_loaded: int = 0
    findings: List[LeakFinding] = field(default_factory=list)
    by_category: Dict[str, int] = field(default_factory=dict)
    by_file: Dict[str, int] = field(default_factory=dict)

    @property
    def total_leaks(self) -> int:
        return len(self.findings)


def default_claude_dir() -> Path:
    return Path(os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))


def discover_transcript_files(claude_dir: Optional[Path] = None, extra_paths: Optional[Iterable[Path]] = None) -> List[Path]:
    """Find all Claude Code JSONL transcripts under ~/.claude/projects/**/*.jsonl and history.jsonl."""
    base = claude_dir or default_claude_dir()
    files: List[Path] = []
    seen: Set[Path] = set()

    candidates: List[Path] = []
    projects_dir = base / "projects"
    if projects_dir.is_dir():
        candidates.extend(sorted(projects_dir.rglob("*.jsonl")))
    history_file = base / "history.jsonl"
    if history_file.is_file():
        candidates.append(history_file)

    if extra_paths:
        for p in extra_paths:
            if p.is_file():
                candidates.append(p)
            elif p.is_dir():
                candidates.extend(sorted(p.rglob("*.jsonl")))

    for f in candidates:
        try:
            # C4: Reject symlinks to prevent symlink traversal attacks
            if f.is_symlink():
                continue
            r = f.resolve()
        except OSError:
            continue
        if r not in seen and f.is_file() and not f.is_symlink():
            seen.add(r)
            files.append(f)
    return files


def extract_cwds_from_transcripts(transcript_files: Iterable[Path]) -> Set[Path]:
    """Extract unique project working directories (`cwd`) referenced inside Claude Code JSONL files."""
    cwds: Set[Path] = {Path.cwd()}
    for tf in transcript_files:
        if tf.is_symlink():
            continue
        try:
            with tf.open("r", encoding="utf-8", errors="replace") as fh:
                for idx, line in enumerate(fh):
                    if idx > 250:  # cwd is recorded in the initial messages of every session
                        break
                    if '"cwd"' not in line:
                        continue
                    try:
                        obj = json.loads(line)
                        if isinstance(obj, dict) and isinstance(obj.get("cwd"), str):
                            p = Path(obj["cwd"])
                            if p.is_dir() and not p.is_symlink():
                                cwds.add(p)
                    except json.JSONDecodeError:
                        continue
        except OSError:
            continue
    return cwds


def audit_transcripts(
    claude_dir: Optional[Path] = None,
    project_dirs: Optional[Iterable[Path]] = None,
    extra_transcript_paths: Optional[Iterable[Path]] = None,
    vault: Optional[SecretVault] = None,
) -> Tuple[AuditReport, SecretVault]:
    """Scan local Claude Code transcripts against project .env secrets + high-precision prefixes."""
    transcript_files = discover_transcript_files(claude_dir=claude_dir, extra_paths=extra_transcript_paths)
    discovered_cwds = extract_cwds_from_transcripts(transcript_files)
    if project_dirs:
        for d in project_dirs:
            if not d.is_symlink() and d.is_dir():
                discovered_cwds.add(d)

    active_vault = vault or SecretVault()
    env_loaded = active_vault.load_project_dirs(discovered_cwds)

    report = AuditReport(
        files_scanned=len(transcript_files),
        env_secrets_loaded=env_loaded,
    )

    for tf in transcript_files:
        if tf.is_symlink():
            continue
        try:
            with tf.open("r", encoding="utf-8", errors="replace") as fh:
                for line_no, line in enumerate(fh, start=1):
                    report.lines_scanned += 1
                    matches = active_vault.scan_text(line)
                    for _, _, entry in matches:
                        finding = LeakFinding(
                            file_path=tf,
                            line_number=line_no,
                            category=entry.category,
                            source=entry.source,
                            masked_preview=mask_secret_preview(entry.secret),
                            token=entry.token,
                        )
                        report.findings.append(finding)
                        report.by_category[entry.category] = report.by_category.get(entry.category, 0) + 1
                        key_path = str(tf)
                        report.by_file[key_path] = report.by_file.get(key_path, 0) + 1
        except OSError:
            continue

    return report, active_vault


def scrub_transcripts(
    claude_dir: Optional[Path] = None,
    project_dirs: Optional[Iterable[Path]] = None,
    extra_transcript_paths: Optional[Iterable[Path]] = None,
    vault: Optional[SecretVault] = None,
) -> Tuple[int, int]:
    """Atomically perform logical in-place redaction across Claude Code JSONL transcripts (C4).

    Safety Guarantees & Boundaries:
    - Atomically replaces files via same-directory tempfile + os.replace() with 0600 permissions.
    - Leaves ZERO plaintext .bak files on disk.
    - Explicitly rejects symlinks to prevent symlink traversal attacks.
    - Note on Storage: This is logical file redaction. Remnants in raw filesystem journals,
      copy-on-write storage snapshots, or external cloud backups are outside software redaction scope.
    Returns `(files_modified, total_replacements)`.
    """
    transcript_files = discover_transcript_files(claude_dir=claude_dir, extra_paths=extra_transcript_paths)
    discovered_cwds = extract_cwds_from_transcripts(transcript_files)
    if project_dirs:
        for d in project_dirs:
            if not d.is_symlink() and d.is_dir():
                discovered_cwds.add(d)

    active_vault = vault or SecretVault()
    active_vault.load_project_dirs(discovered_cwds)

    files_modified = 0
    total_replacements = 0

    for tf in transcript_files:
        # C4: Reject symlinks
        if tf.is_symlink() or not tf.is_file():
            continue

        try:
            original_lines = tf.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
        except OSError:
            continue

        new_lines: List[str] = []
        file_replacements = 0
        for line in original_lines:
            cloaked_line, count = active_vault.cloak_text(line)
            new_lines.append(cloaked_line)
            file_replacements += count

        if file_replacements > 0:
            # Atomic write in same directory with 0600 permissions and zero .bak retention
            fd, tmp_name = tempfile.mkstemp(dir=str(tf.parent), prefix=".cloakllm_scrub_", suffix=".tmp")
            tmp_path = Path(tmp_name)
            try:
                try:
                    os.chmod(tmp_path, 0o600)
                except OSError:
                    pass
                with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp_fh:
                    tmp_fh.writelines(new_lines)
                    tmp_fh.flush()
                    os.fsync(tmp_fh.fileno())
                os.replace(str(tmp_path), str(tf))
                files_modified += 1
                total_replacements += file_replacements
            finally:
                if tmp_path.exists():
                    try:
                        tmp_path.unlink()
                    except OSError:
                        pass

    return files_modified, total_replacements


HARDEN_DENY_RULES: Tuple[str, ...] = (
    "Read(./.env)",
    "Read(./.env.*)",
    "Read(**/.env)",
    "Read(**/.env.*)",
    "Read(**/secrets/**)",
    "Read(**/*.pem)",
    "Read(**/*.key)",
)


def harden_claude_settings(target_dir: Optional[Path] = None, use_global: bool = False) -> Tuple[Path, List[str]]:
    """Add secret-file Read(...) deny rules to .claude/settings.json (or ~/.claude/settings.json).

    Preserves existing keys and allow-lists `.env.example` / `.env.sample` / `.env.template`.
    Safely rejects symlinks in settings_path and its parent directories.
    Performs atomic replacement with 0600 permissions.
    Returns `(settings_file_path, newly_added_rules)`.
    """
    if use_global:
        base = default_claude_dir()
        settings_path = base / "settings.json"
    else:
        base = target_dir or Path.cwd()
        settings_path = base / ".claude" / "settings.json"

    # 1. Comprehensive Ancestor Path Check:
    # Walk every directory component from settings_path up to the filesystem root to reject any symlinks!
    curr = settings_path
    while curr != curr.parent:
        if curr.is_symlink():
            raise ValueError(f"Refusing to harden settings: path component '{curr}' is a symlink")
        curr = curr.parent

    if base.is_symlink():
        raise ValueError(f"Refusing to harden settings: base directory '{base}' is a symlink")

    parent_dir = settings_path.parent
    if parent_dir.is_symlink():
        raise ValueError(f"Refusing to harden settings: parent directory '{parent_dir}' is a symlink")

    parent_dir.mkdir(parents=True, exist_ok=True)

    if parent_dir.is_symlink():
        raise ValueError(f"Refusing to harden settings: parent directory '{parent_dir}' is a symlink")

    # 2. Symlink defense for settings.json itself
    if settings_path.is_symlink():
        raise ValueError(f"Refusing to harden settings: '{settings_path}' is a symlink")

    data: dict = {}
    if settings_path.exists():
        if not settings_path.is_file() or settings_path.is_symlink():
            raise ValueError(f"Refusing to harden settings: '{settings_path}' is not a regular file")
        try:
            loaded = json.loads(settings_path.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                data = loaded
        except (OSError, json.JSONDecodeError):
            data = {}

    perms = data.setdefault("permissions", {})
    if not isinstance(perms, dict):
        perms = {}
        data["permissions"] = perms

    deny_list = perms.setdefault("deny", [])
    if not isinstance(deny_list, list):
        deny_list = []
        perms["deny"] = deny_list

    added: List[str] = []
    for rule in HARDEN_DENY_RULES:
        if rule not in deny_list:
            deny_list.append(rule)
            added.append(rule)

    # 3. Safe atomic write with 0600 permissions and zero .bak retention
    content = json.dumps(data, indent=2) + "\n"
    fd, tmp_name = tempfile.mkstemp(dir=str(parent_dir), prefix=".cloakllm_harden_", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        try:
            os.chmod(tmp_path, 0o600)
        except OSError:
            pass
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as tmp_fh:
            tmp_fh.write(content)
            tmp_fh.flush()
            os.fsync(tmp_fh.fileno())
        # Re-check settings_path is not a symlink before replacing
        if settings_path.is_symlink():
            raise ValueError(f"Refusing to harden settings: target '{settings_path}' became a symlink")
        os.replace(str(tmp_path), str(settings_path))
    finally:
        if tmp_path.exists():
            try:
                tmp_path.unlink()
            except OSError:
                pass

    return settings_path, added
