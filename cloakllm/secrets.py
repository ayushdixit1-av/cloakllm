"""Hardened 5-Gate .env & Credential Loader + Prefix Scanners + HMAC-SHA256 Token Vault."""

from __future__ import annotations

import collections
import copy
import hashlib
import hmac
import json
import math
import os
import re
import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, unquote, urlsplit

# ---------------------------------------------------------------------------
# Threat Model & Design Invariants (Finding J)
# ---------------------------------------------------------------------------
# CloakLLM is a local-first credential firewall protecting REGISTERED project
# credentials (indexed from .env files and recognized high-confidence API prefixes).
# It does NOT guarantee heuristic detection of arbitrary unindexed strings.
# ---------------------------------------------------------------------------

MAX_MEMO_CACHE_SIZE = 4096


SKIP_ENV_FILENAMES: Set[str] = {
    ".env.example",
    ".env.sample",
    ".env.template",
    ".env.dist",
    ".env.test",
}

# Gate 1: Explicit Public / Non-Secret Key Denylist
PUBLIC_KEY_SUBSTRINGS: Tuple[str, ...] = (
    "PUBLIC",
    "PUBLISHABLE",
    "ANON_KEY",
    "NEXT_PUBLIC_",
    "VITE_",
    "REACT_APP_PUBLIC_",
    "EXPO_PUBLIC_",
    "NUXT_PUBLIC_",
)
NON_SECRET_KEY_SUFFIXES: Tuple[str, ...] = (
    "_KEY_ID",
    "_KEY_PATH",
    "_KEY_NAME",
    "_KEY_FILE",
    "_KEY_ALIAS",
    "_KEY_ARN",
    "_TOKEN_URL",
    "_TOKEN_URI",
    "_TOKEN_ENDPOINT",
    "_SECRET_NAME",
    "_SECRET_ID",
    "_SECRET_ARN",
)
PUBLIC_VALUE_PREFIXES: Tuple[str, ...] = (
    "pk_live_",
    "pk_test_",
    "pk_",
)

# Gate 2: Token-Boundary Secret Key Regex
SECRET_KEY_TOKEN_RE = re.compile(
    r"(?:^|_)(KEY|SECRET|TOKEN|PASSWORD|PASSWD|PWD|CREDENTIAL|CREDENTIALS|PRIVATE|WEBHOOK|DSN)(?:$|_)",
    re.IGNORECASE,
)
PASSWORD_KEY_TOKEN_RE = re.compile(
    r"(?:^|_)(PASSWORD|PASSWD|PWD)(?:$|_)",
    re.IGNORECASE,
)
URL_KEY_TOKEN_RE = re.compile(
    r"(?:^|_)(URL|URI|CONNECTION|CONN|DSN|ENDPOINT)(?:$|_)",
    re.IGNORECASE,
)

SENSITIVE_URL_QUERY_KEYS: Set[str] = {
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "key",
    "secret",
    "client_secret",
    "sig",
    "signature",
    "password",
    "passwd",
    "pwd",
    "auth",
}

# Gate 4: Value Stoplist
VALUE_STOPLIST: Set[str] = {
    "secret",
    "password",
    "passwd",
    "test",
    "testing",
    "dev",
    "local",
    "production",
    "prod",
    "development",
    "staging",
    "admin",
    "root",
    "postgres",
    "localhost",
    "changeme",
    "change_me",
    "your-key-here",
    "your_key_here",
    "replace_me",
    "replaceme",
    "todo",
    "xxx",
    "xxxx",
    "null",
    "none",
    "true",
    "false",
    "example",
    "sample",
    "default",
    "placeholder",
}

# High-Precision Prefix Scanners (B4 - Stateless & Additive)
PREFIX_PATTERNS: List[Tuple[str, re.Pattern[str]]] = [
    ("ANTHROPIC", re.compile(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{20,120}")),
    ("OPENAI", re.compile(r"sk-(?:proj|svcacct|live|test)-[A-Za-z0-9_-]{20,160}")),
    ("OPENAI", re.compile(r"(?<![A-Za-z0-9_-])sk-[A-Za-z0-9]{32,64}(?![A-Za-z0-9_-])")),
    ("GITHUB", re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,50}")),
    ("GITHUB", re.compile(r"github_pat_[A-Za-z0-9_]{40,120}")),
    ("AWS", re.compile(r"(?<![A-Za-z0-9])(?:AKIA|ASIA)[A-Z0-9]{16}(?![A-Za-z0-9])")),
    ("SLACK", re.compile(r"xox[baprs]-[A-Za-z0-9-]{20,120}")),
    ("STRIPE", re.compile(r"(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{20,120}")),
    ("GOOGLE", re.compile(r"AIza[0-9A-Za-z_-]{35}")),
    ("HF", re.compile(r"hf_[A-Za-z0-9]{30,60}")),
    ("GROQ", re.compile(r"gsk_[A-Za-z0-9]{30,80}")),
    (
        "PEM",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----[\s\S]+?-----END (?:RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----"
        ),
    ),
]


def shannon_entropy(s: str) -> float:
    """Compute Shannon entropy in bits per character."""
    if not s:
        return 0.0
    length = len(s)
    counts: Dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def count_char_classes(s: str) -> int:
    """Count distinct character classes (lower, upper, digit, symbol) in s."""
    classes = 0
    if any(c.islower() for c in s):
        classes += 1
    if any(c.isupper() for c in s):
        classes += 1
    if any(c.isdigit() for c in s):
        classes += 1
    if any(not c.isalnum() for c in s):
        classes += 1
    return classes


def is_likely_file_path_or_plain_url(val: str) -> bool:
    """Return True if val looks like a filesystem path or credential-free URL."""
    if val.startswith(("/", "./", "../", "~/", "C:\\", "D:\\", "file://")):
        return True
    if val.startswith(("http://", "https://", "ws://", "wss://")):
        try:
            sp = urlsplit(val)
            if not sp.password and not any(
                k.lower() in SENSITIVE_URL_QUERY_KEYS for k, _ in parse_qsl(sp.query)
            ):
                return True
        except ValueError:
            pass
    return False


def categorize_key(key_name: str) -> str:
    """Map an environment variable name to a short uppercase category tag."""
    upper = key_name.upper()
    if any(k in upper for k in ("DB", "DATABASE", "POSTGRES", "MYSQL", "MONGO", "REDIS", "DSN")):
        return "DB"
    if "AWS" in upper:
        return "AWS"
    if "GITHUB" in upper or "GH_" in upper:
        return "GITHUB"
    if "ANTHROPIC" in upper or "CLAUDE" in upper:
        return "ANTHROPIC"
    if "OPENAI" in upper:
        return "OPENAI"
    if "STRIPE" in upper:
        return "STRIPE"
    if "JWT" in upper or "SESSION" in upper or "AUTH" in upper or "TOKEN" in upper:
        return "AUTH"
    if "WEBHOOK" in upper:
        return "WEBHOOK"
    if "PASS" in upper or "PWD" in upper:
        return "PASS"
    return "SECRET"


def passes_value_gate(val: str, is_password_key: bool = False) -> bool:
    """Gate 4: Check minimum length, character classes, stoplist, and Shannon entropy."""
    stripped = val.strip()
    if not stripped:
        return False
    lower = stripped.lower()
    if lower in VALUE_STOPLIST:
        return False
    if any(lower.startswith(p) for p in PUBLIC_VALUE_PREFIXES):
        return False
    # Reject pure integers / floats / booleans
    if re.fullmatch(r"[+-]?\d+(?:\.\d+)?", stripped):
        return False
    # Reject template placeholders like ${VAR} or {{VAR}} or <VAR>
    if (
        (stripped.startswith("${") and stripped.endswith("}"))
        or (stripped.startswith("{{") and stripped.endswith("}}"))
        or (stripped.startswith("<") and stripped.endswith(">"))
    ):
        return False
    if is_likely_file_path_or_plain_url(stripped):
        return False

    min_len = 8 if is_password_key else 12
    if len(stripped) < min_len:
        return False
    if is_password_key and count_char_classes(stripped) < 2:
        return False

    # Entropy gate: >= 2.8 bits/char (or >= 2.5 for passwords >= 10 chars with >= 2 classes)
    ent = shannon_entropy(stripped)
    min_entropy = 2.5 if (is_password_key and len(stripped) >= 10) else 2.8
    if ent < min_entropy:
        return False

    return True


def extract_secrets_from_env_pair(key: str, raw_val: str) -> List[Tuple[str, str]]:
    """Apply Gates 1-4 to a single (KEY, VALUE) pair from a .env file.

    Returns a list of (category, secret_string) tuples.
    For URL/URI keys (Gate 3), extracts ONLY the embedded password or sensitive
    query token rather than the entire URL so the LLM preserves host/port/db context.
    """
    key_clean = key.strip()
    val_clean = raw_val.strip()
    if not key_clean or not val_clean:
        return []

    upper_key = key_clean.upper()

    # Gate 1: Explicit Public / Non-Secret Key Denylist
    if any(pub in upper_key for pub in PUBLIC_KEY_SUBSTRINGS):
        return []
    if any(upper_key.endswith(suf) for suf in NON_SECRET_KEY_SUFFIXES):
        return []
    if any(val_clean.startswith(pref) for pref in PUBLIC_VALUE_PREFIXES):
        return []

    # Check if value looks like a URI/URL or key is a URL/URI/CONNECTION/DSN key (Gate 3)
    is_url_value = "://" in val_clean
    is_url_key = bool(URL_KEY_TOKEN_RE.search(upper_key))

    if is_url_value or is_url_key:
        if not is_url_value:
            return []
        extracted: List[Tuple[str, str]] = []
        cat = categorize_key(key_clean)
        seen_cands: Set[str] = set()

        # Extract userinfo password between `scheme://user:` and the last `@host` before path
        # Handles passwords that contain unencoded `@` or `#` in .env files
        userinfo_match = re.match(r"^[A-Za-z][A-Za-z0-9+.-]*://[^/:@\s]+:(.+)@[^/@\s]+", val_clean)
        if userinfo_match:
            raw_pw = userinfo_match.group(1)
            for candidate in (raw_pw, unquote(raw_pw)):
                if candidate not in seen_cands and passes_value_gate(candidate, is_password_key=True):
                    seen_cands.add(candidate)
                    extracted.append((cat, candidate))

        try:
            sp = urlsplit(val_clean)
        except ValueError:
            return extracted

        if sp.password:
            for candidate in (sp.password, unquote(sp.password)):
                if candidate not in seen_cands and passes_value_gate(candidate, is_password_key=True):
                    seen_cands.add(candidate)
                    extracted.append((cat, candidate))
        for qk, qv in parse_qsl(sp.query, keep_blank_values=False):
            if qk.lower() in SENSITIVE_URL_QUERY_KEYS:
                for candidate in (qv, unquote(qv)):
                    if candidate not in seen_cands and passes_value_gate(candidate, is_password_key=True):
                        seen_cands.add(candidate)
                        extracted.append((cat, candidate))
        return extracted

    # Gate 2: Token-Boundary Secret Key Match
    if not SECRET_KEY_TOKEN_RE.search(upper_key):
        return []

    is_pwd = bool(PASSWORD_KEY_TOKEN_RE.search(upper_key))
    if not passes_value_gate(val_clean, is_password_key=is_pwd):
        return []

    cat = categorize_key(key_clean)
    results = [(cat, val_clean)]
    unquoted = unquote(val_clean)
    if unquoted != val_clean and passes_value_gate(unquoted, is_password_key=is_pwd):
        results.append((cat, unquoted))
    return results


def parse_dotenv_content(content: str) -> List[Tuple[str, str]]:
    """Parse .env file content handling UTF-8 BOM, CRLF, export prefix, quotes, inline #, and multiline."""
    if content.startswith("\ufeff"):
        content = content[1:]
    content = content.replace("\r\n", "\n").replace("\r", "\n")

    pairs: List[Tuple[str, str]] = []
    lines = content.split("\n")
    i = 0
    n = len(lines)

    while i < n:
        line = lines[i].strip()
        i += 1
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue

        key, rest = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", key):
            continue

        rest = rest.lstrip()
        if not rest:
            continue

        if rest[0] in ('"', "'"):
            quote_char = rest[0]
            buf = [rest[1:]]
            # Accumulate until unescaped closing quote
            while True:
                current = "\n".join(buf)
                # Find unescaped quote_char
                m = re.search(rf"(?<!\\){re.escape(quote_char)}", current)
                if m:
                    raw_val = current[: m.start()]
                    break
                if i >= n:
                    raw_val = current
                    break
                buf.append(lines[i])
                i += 1
            if quote_char == '"':
                raw_val = (
                    raw_val.replace(r"\"", '"')
                    .replace(r"\n", "\n")
                    .replace(r"\r", "\r")
                    .replace(r"\t", "\t")
                    .replace(r"\\", "\\")
                )
            pairs.append((key, raw_val))
        else:
            # Unquoted value: strip inline comment preceded by whitespace
            comment_match = re.search(r"\s+#", rest)
            raw_val = rest[: comment_match.start()].strip() if comment_match else rest.strip()
            pairs.append((key, raw_val))

    return pairs


@dataclass
class SecretEntry:
    secret: str
    category: str
    token: str
    tag_hex: str
    source: str


class SecretVault:
    """Session-scoped deterministic HMAC-SHA256 secret vault (B2, B3, B4)."""

    def __init__(self, session_key: Optional[bytes] = None) -> None:
        self.session_key: bytes = session_key or os.urandom(32)
        self.vault_version: int = 1
        self._lock: threading.RLock = threading.RLock()
        self._by_secret: Dict[str, SecretEntry] = {}
        self._by_token: Dict[str, SecretEntry] = {}
        self._by_tag: Dict[str, SecretEntry] = {}
        self._exact_regex: Optional[re.Pattern[str]] = None
        # Bounded LRU Memoization cache: (session_key, vault_version, blake2b_digest) -> (cloaked_dict, count)
        self._message_memo: collections.OrderedDict[Tuple[bytes, int, bytes], Tuple[dict, int]] = collections.OrderedDict()

    def _compute_tag(self, secret: str) -> str:
        # 128-bit HMAC-SHA256 (32 hex chars) - eliminates 32-bit birthday collision hazard (C2)
        return hmac.new(self.session_key, secret.encode("utf-8"), hashlib.sha256).hexdigest()[:32].upper()

    def register_secret(
        self, secret: str, category: str = "SECRET", source: str = "env", rebuild_exact: bool = True
    ) -> SecretEntry:
        """Register a secret in the vault with atomic thread synchronization and collision defense."""
        with self._lock:
            if secret in self._by_secret:
                return self._by_secret[secret]

            clean_cat = re.sub(r"[^A-Z0-9]", "", category.upper()) or "SECRET"
            tag_hex = self._compute_tag(secret)

            # C2 & Finding M: Explicit collision detection against different secrets
            if tag_hex in self._by_tag and self._by_tag[tag_hex].secret != secret:
                raise RuntimeError(f"Cryptographic collision detected for tag {tag_hex}!")

            token = f"CLOAKv1_{clean_cat}_{tag_hex}"

            entry = SecretEntry(
                secret=secret,
                category=clean_cat,
                token=token,
                tag_hex=tag_hex,
                source=source,
            )
            self._by_secret[secret] = entry
            self._by_token[token] = entry
            self._by_tag[tag_hex] = entry

            # Finding F: Always bump vault_version and invalidate memo cache on ANY secret registration
            self.vault_version += 1
            self._message_memo.clear()

            if rebuild_exact:
                self._compile_exact_regex()

            return entry

    def _compile_exact_regex(self) -> None:
        """Gate 5: Sort exact-match secrets longest-first with alphanumeric lookarounds."""
        with self._lock:
            if not self._by_secret:
                self._exact_regex = None
                return
            # Sort longest-first so full secret always wins over a substring secret
            sorted_secrets = sorted(self._by_secret.keys(), key=lambda s: -len(s))
            escaped = [re.escape(s) for s in sorted_secrets]
            pattern = r"(?<![A-Za-z0-9_])(?:" + "|".join(escaped) + r")(?![A-Za-z0-9_])"
            self._exact_regex = re.compile(pattern)

    def load_env_file(self, path: Path) -> int:
        """Load secrets from a .env file using the 5-Gate pipeline."""
        if path.name.lower() in SKIP_ENV_FILENAMES:
            return 0
        if not path.is_file():
            return 0
        try:
            content = path.read_text(encoding="utf-8-sig", errors="replace")
        except OSError:
            return 0

        pairs = parse_dotenv_content(content)
        candidates: List[Tuple[str, str, str]] = []
        for key, raw_val in pairs:
            for cat, secret_val in extract_secrets_from_env_pair(key, raw_val):
                candidates.append((cat, secret_val, f"{path.name}:{key}"))
            # Also scan raw_val with prefix scanners in case a composite string contains an API key
            for cat, pat in PREFIX_PATTERNS:
                for m in pat.finditer(raw_val):
                    candidates.append((cat, m.group(0), f"{path.name}:{key}"))

        with self._lock:
            added = 0
            for cat, secret_val, src in candidates:
                if secret_val not in self._by_secret:
                    self.register_secret(secret_val, category=cat, source=src, rebuild_exact=False)
                    added += 1

            if added > 0:
                self.vault_version += 1
                self._message_memo.clear()
                self._compile_exact_regex()
            return added

    def load_project_dirs(self, dirs: Iterable[Path]) -> int:
        """Scan project directories for .env* files (excluding .env.example etc.)."""
        total = 0
        seen_files: Set[Path] = set()
        for d in dirs:
            if not d.is_dir():
                continue
            for candidate in sorted(d.glob(".env*")):
                try:
                    resolved = candidate.resolve()
                except OSError:
                    continue
                if resolved in seen_files or candidate.name.lower() in SKIP_ENV_FILENAMES:
                    continue
                if candidate.is_file():
                    seen_files.add(resolved)
                    total += self.load_env_file(candidate)
        return total

    def scan_text(self, text: str) -> List[Tuple[int, int, SecretEntry]]:
        """Find all secret occurrences in text (both frozen .env exact matches and stateless prefix matches).

        Returns non-overlapping [(start, end, SecretEntry), ...] sorted by start index.
        """
        if not text:
            return []

        raw_matches: List[Tuple[int, int, SecretEntry]] = []

        with self._lock:
            exact_re = self._exact_regex

        # 1. Exact matches from .env vault (Gate 5 longest-first)
        if exact_re is not None:
            for m in exact_re.finditer(text):
                sec = m.group(0)
                with self._lock:
                    entry = self._by_secret.get(sec)
                if entry is not None:
                    raw_matches.append((m.start(), m.end(), entry))

        # 2. Stateless additive prefix scanners (B4: registers in token map without bumping exact_regex)
        for cat, pat in PREFIX_PATTERNS:
            for m in pat.finditer(text):
                sec = m.group(0)
                if any(sec.startswith(p) for p in PUBLIC_VALUE_PREFIXES):
                    continue
                with self._lock:
                    entry = self._by_secret.get(sec)
                if entry is None:
                    # Register additively without invalidating exact_regex / prompt cache
                    entry = self.register_secret(sec, category=cat, source=f"prefix:{cat}", rebuild_exact=False)
                raw_matches.append((m.start(), m.end(), entry))

        if not raw_matches:
            return []

        # Deduplicate overlapping matches: sort by start asc, then length desc (longest match wins)
        raw_matches.sort(key=lambda item: (item[0], -(item[1] - item[0])))
        merged: List[Tuple[int, int, SecretEntry]] = []
        last_end = -1
        for start, end, entry in raw_matches:
            if start >= last_end:
                merged.append((start, end, entry))
                last_end = end
        return merged

    def cloak_text(self, text: str) -> Tuple[str, int]:
        """Replace all secrets in text with their deterministic CLOAKv1_<CAT>_<8HEX> tokens."""
        matches = self.scan_text(text)
        if not matches:
            return text, 0
        out: List[str] = []
        cursor = 0
        for start, end, entry in matches:
            out.append(text[cursor:start])
            out.append(entry.token)
            cursor = end
        out.append(text[cursor:])
        return "".join(out), len(matches)

    def cloak_json_value(self, obj: object) -> Tuple[object, int]:
        """Recursively cloak strings inside JSON structures, skipping thinking/signed blocks (B1)."""
        if isinstance(obj, str):
            return self.cloak_text(obj)
        if isinstance(obj, list):
            total = 0
            new_list = []
            for item in obj:
                cloaked_item, count = self.cloak_json_value(item)
                new_list.append(cloaked_item)
                total += count
            return new_list, total
        if isinstance(obj, dict):
            # Extended-Thinking & Signature Immunity (B1):
            # Never touch any content block with type in ("thinking", "redacted_thinking") or "signature"
            block_type = obj.get("type")
            if block_type in ("thinking", "redacted_thinking") or "signature" in obj:
                return obj, 0

            total = 0
            new_dict = {}
            for k, v in obj.items():
                # Do not cloak metadata keys like "type", "role", "id", "model", "cache_control"
                if k in ("type", "role", "id", "model", "cache_control", "stop_reason"):
                    new_dict[k] = v
                else:
                    cloaked_k, k_cnt = self.cloak_text(str(k))
                    cloaked_v, count = self.cloak_json_value(v)
                    new_dict[cloaked_k] = cloaked_v
                    total += k_cnt + count
            return new_dict, total
        return obj, 0

    def cloak_message_memoized(self, msg: dict) -> Tuple[dict, int]:
        """Memoize cloaking per message with LRU bounding, optimistic concurrency version check, and defensive copying.

        Protects against concurrent secret registration interleavings: if the vault version changes while
        cloaking is in flight, the outdated result is discarded and cloaking is retried against the updated vault.
        """
        canonical = json.dumps(msg, sort_keys=True, separators=(",", ":")).encode("utf-8")
        digest = hashlib.blake2b(canonical, digest_size=16).digest()

        while True:
            with self._lock:
                start_version = self.vault_version
                cache_key = (self.session_key, start_version, digest)
                cached = self._message_memo.get(cache_key)
                if cached is not None:
                    self._message_memo.move_to_end(cache_key)
                    cached_dict, count = cached
                    return copy.deepcopy(cached_dict), count

            # Cloak outside lock corresponding to start_version
            cloaked_msg, count = self.cloak_json_value(msg)
            assert isinstance(cloaked_msg, dict)

            with self._lock:
                # Concurrent mutation check: if vault contents changed during cloaking, retry!
                if self.vault_version != start_version:
                    continue

                self._message_memo[cache_key] = (copy.deepcopy(cloaked_msg), count)
                while len(self._message_memo) > MAX_MEMO_CACHE_SIZE:
                    self._message_memo.popitem(last=False)

                return cloaked_msg, count

    def resolve_token(self, category: str, tag_hex: str) -> Optional[SecretEntry]:
        """Finding E: Exact-only token resolution: category AND tag MUST match the registered token."""
        clean_cat = re.sub(r"[^A-Z0-9]", "", category.upper())
        tag_clean = tag_hex.upper()
        token = f"CLOAKv1_{clean_cat}_{tag_clean}"
        with self._lock:
            entry = self._by_token.get(token)
            if entry is not None and entry.tag_hex == tag_clean and entry.category == clean_cat:
                return entry
            return None

    @property
    def entries(self) -> List[SecretEntry]:
        with self._lock:
            return list(self._by_secret.values())
