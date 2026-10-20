"""Fail-Closed Local Cloaking Proxy with Path-Token Auth & Zero-TTY-Noise Logging (B1, B6)."""

from __future__ import annotations

import http.client
import json
import os
import re
import secrets
import socket
import ssl
import stat
import threading
import time
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Callable, Dict, List, Optional, Tuple
from urllib.parse import unquote, urlsplit

from cloakllm.secrets import SecretVault
from cloakllm.stream import StreamRehydrator, rehydrate_json_value

SYSTEM_PRESERVATION_HINT = (
    "Tokens matching CLOAKv1_<CATEGORY>_<32HEX> are opaque credential placeholders. "
    "Reproduce them verbatim and reference environment variables rather than hardcoding secrets."
)

# C1: Explicit Route-and-Method Allowlist. Everything else rejected by default.
ALLOWLISTED_ROUTES = {
    ("POST", "/v1/messages"),
    ("POST", "/v1/messages/count_tokens"),
    ("POST", "/v1/chat/completions"),
    ("GET", "/v1/models"),
}

CLOAKED_POST_PATHS = {
    "/v1/messages",
    "/v1/messages/count_tokens",
    "/v1/chat/completions",
}

HOP_BY_HOP_HEADERS = {
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailers",
    "transfer-encoding",
    "upgrade",
    "content-length",
    "host",
    "accept-encoding",
}


@dataclass
class ProxyStats:
    requests_total: int = 0
    requests_cloaked: int = 0
    requests_blocked: int = 0
    secrets_redacted_outbound: int = 0
    tokens_rehydrated_inbound: int = 0
    unknown_tokens_seen: int = 0
    lock: threading.Lock = field(default_factory=threading.Lock)


def inject_system_hint(payload: dict, is_openai_format: bool = False) -> None:
    """Append a constant system-prompt hint without violating provider schema contracts."""
    if "messages" not in payload:
        return

    if is_openai_format:
        # OpenAI schema: NEVER inject a top-level "system" property.
        # Inject into system role message inside messages list.
        msgs = payload.get("messages")
        if not isinstance(msgs, list):
            raise ValueError("OpenAI route requires messages to be a list")
        for m in msgs:
            if not isinstance(m, dict) or "role" not in m or not isinstance(m.get("role"), str):
                raise ValueError("OpenAI messages list must contain objects with string role")
            if m.get("role") == "system":
                content = m.get("content")
                if isinstance(content, str):
                    if SYSTEM_PRESERVATION_HINT not in content:
                        m["content"] = f"{content}\n\n{SYSTEM_PRESERVATION_HINT}" if content else SYSTEM_PRESERVATION_HINT
                    return
                elif isinstance(content, list):
                    for part in content:
                        if not isinstance(part, dict) or "type" not in part:
                            raise ValueError("Invalid structured content part in OpenAI system message")
                    already = any(
                        isinstance(part, dict) and SYSTEM_PRESERVATION_HINT in str(part.get("text", ""))
                        for part in content
                    )
                    if not already:
                        content.append({"type": "text", "text": SYSTEM_PRESERVATION_HINT})
                    return
                elif content is None:
                    m["content"] = SYSTEM_PRESERVATION_HINT
                    return
                else:
                    raise ValueError("Unsupported OpenAI system message content format")
        # If no system message found, prepend one
        msgs.insert(0, {"role": "system", "content": SYSTEM_PRESERVATION_HINT})
    else:
        # Anthropic schema: top-level "system"
        sys_val = payload.get("system")
        if sys_val is None:
            payload["system"] = SYSTEM_PRESERVATION_HINT
        elif isinstance(sys_val, str):
            if SYSTEM_PRESERVATION_HINT not in sys_val:
                payload["system"] = f"{sys_val}\n\n{SYSTEM_PRESERVATION_HINT}"
        elif isinstance(sys_val, list):
            already = any(
                isinstance(b, dict) and SYSTEM_PRESERVATION_HINT in str(b.get("text", ""))
                for b in sys_val
            )
            if not already:
                sys_val.append({"type": "text", "text": SYSTEM_PRESERVATION_HINT})


def cloak_request_payload(
    payload: dict,
    vault: SecretVault,
    canonical_route: str = "/v1/messages",
) -> Tuple[dict, int]:
    """Recursively cloak an outbound JSON payload across ALL fields with ZERO exemptions.

    Every single string value in the object graph (including model, metadata, operational fields)
    is inspected and cloaked by vault.cloak_json_value().
    Raises ValueError if payload is not a JSON object so caller can fail closed.
    """
    if not isinstance(payload, dict):
        raise ValueError("Expected JSON object payload")

    out: Dict[str, object] = {}
    total_redacted = 0
    is_openai = canonical_route.startswith("/v1/chat/completions")

    # 1. System prompt handling:
    # On OpenAI routes, if user supplies top-level "system", merge it into messages list so NO user content is lost!
    if "system" in payload:
        if is_openai:
            sys_content = payload["system"]
            if sys_content is not None:
                if "messages" in payload and not isinstance(payload["messages"], list):
                    raise ValueError("OpenAI route requires messages to be a list")
                msgs = payload.setdefault("messages", [])
                if isinstance(sys_content, str):
                    msgs.insert(0, {"role": "system", "content": sys_content})
                elif isinstance(sys_content, list):
                    for item in reversed(sys_content):
                        if isinstance(item, dict):
                            if "text" in item and isinstance(item["text"], str):
                                msgs.insert(0, {"role": "system", "content": item["text"]})
                            else:
                                raise ValueError("Unsupported dictionary block in OpenAI system list")
                        elif isinstance(item, str):
                            msgs.insert(0, {"role": "system", "content": item})
                        else:
                            raise ValueError("Unsupported item type in OpenAI system list")
                elif isinstance(sys_content, dict):
                    if "text" in sys_content and isinstance(sys_content["text"], str):
                        msgs.insert(0, {"role": "system", "content": sys_content["text"]})
                    elif "content" in sys_content and isinstance(sys_content["content"], str):
                        msgs.insert(0, {"role": "system", "content": sys_content["content"]})
                    else:
                        raise ValueError("Unsupported dictionary shape or non-string content for OpenAI system")
                else:
                    raise ValueError(f"Unsupported system property type on OpenAI route: {type(sys_content).__name__}")
        else:
            cloaked_sys, c = vault.cloak_json_value(payload["system"])
            out["system"] = cloaked_sys
            total_redacted += c

    # 2. Messages handling with per-message memoization optimization
    if "messages" in payload:
        raw_msgs = payload["messages"]
        if is_openai:
            if not isinstance(raw_msgs, list):
                raise ValueError("OpenAI route requires messages to be a list")
            for m in raw_msgs:
                if not isinstance(m, dict) or "role" not in m or not isinstance(m.get("role"), str):
                    raise ValueError("OpenAI messages must contain objects with string role")
                if "content" in m and isinstance(m["content"], list):
                    for part in m["content"]:
                        if not isinstance(part, dict) or "type" not in part:
                            raise ValueError("OpenAI structured content parts must be objects with type")
        if isinstance(raw_msgs, list):
            new_msgs = []
            for msg in raw_msgs:
                if isinstance(msg, dict):
                    c_msg, c = vault.cloak_message_memoized(msg)
                    new_msgs.append(c_msg)
                    total_redacted += c
                else:
                    c_msg, c = vault.cloak_json_value(msg)
                    new_msgs.append(c_msg)
                    total_redacted += c
            out["messages"] = new_msgs
        else:
            cloaked_m, c = vault.cloak_json_value(raw_msgs)
            out["messages"] = cloaked_m
            total_redacted += c

    # 3. Schema-aware system preservation hint injection
    inject_system_hint(out, is_openai_format=is_openai)

    # 4. Recursive cloaking across ALL other fields with ZERO EXEMPTIONS
    for k, v in payload.items():
        if k in ("system", "messages"):
            continue
        cloaked_v, c = vault.cloak_json_value(v)
        out[k] = cloaked_v
        total_redacted += c

    return out, total_redacted


MAX_REQUEST_BODY_BYTES = 15 * 1024 * 1024  # 15 MB boundary limit
MAX_RESPONSE_BODY_BYTES = 50 * 1024 * 1024  # 50 MB upstream response limit
MAX_CONCURRENT_REQUESTS = 64  # Concurrency admission control

FORBIDDEN_ENCODED_OCTETS = {
    "%25",  # encoded %
    "%2f", "%2F",  # encoded /
    "%2e", "%2E",  # encoded .
    "%3f", "%3F",  # encoded ?
    "%23",  # encoded #
    "%5c", "%5C",  # encoded \
}

ASCII_DIGITS_REGEX = re.compile(r"^[0-9]+$")
SAFE_QUERY_PARAM_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]+$")


def validate_and_inspect_query(
    canonical_route: str,
    query_part: str,
    vault: SecretVault,
) -> Tuple[Optional[str], Optional[Tuple[int, str, str]]]:
    """Strictly validate, scan, and canonically reconstruct query parameters per route (Finding 2).

    Inspects both raw and percent-decoded values, rejects duplicates and whitespace,
    and returns (canonical_reconstructed_query, error_tuple_or_none).
    """
    if not query_part:
        return "", None

    # Global: Check for credentials in raw and unquoted query strings
    unquoted_query = unquote(query_part)
    for q_candidate in (query_part, unquoted_query):
        _, redacted_count = vault.cloak_text(q_candidate)
        if redacted_count > 0:
            return None, (400, "ERR_CREDENTIAL_IN_QUERY", "Credentials detected in query parameters are strictly forbidden.")

    # Parse query pairs with normalized duplicate detection
    pairs = query_part.split("&")
    seen_norm_params: set[str] = set()
    canonical_pairs: List[str] = []

    for pair in pairs:
        if not pair:
            return None, (400, "ERR_MALFORMED_QUERY", "Empty query parameter segment is forbidden.")
        if "=" in pair:
            k, v = pair.split("=", 1)
        else:
            k, v = pair, ""

        # Reject whitespace in raw key or value outright to prevent upstream parsing differentials
        if k != k.strip() or v != v.strip() or any(c.isspace() for c in k):
            return None, (400, "ERR_MALFORMED_QUERY", "Whitespace is forbidden in query parameter keys or values.")

        # Reject percent-encoded parameter keys outright to guarantee canonical representation
        if "%" in k:
            return None, (400, "ERR_ENCODED_QUERY_KEY", "Percent-encoded parameter keys are forbidden.")

        norm_k = unquote(k).strip()
        # Normalized duplicate detection
        if norm_k in seen_norm_params:
            return None, (400, "ERR_DUPLICATE_QUERY_PARAM", "Duplicate query parameters are forbidden.")
        seen_norm_params.add(norm_k)

        # Scan individual keys and values (raw and unquoted) for credentials
        for item in (k, v, unquote(k), unquote(v)):
            _, red = vault.cloak_text(item)
            if red > 0:
                return None, (400, "ERR_CREDENTIAL_IN_QUERY", "Credentials detected in query parameters are strictly forbidden.")

        # Route-specific query allowlists (100% static error messages - zero user input interpolation)
        if canonical_route in ("/v1/messages", "/v1/messages/count_tokens"):
            if norm_k != "beta" or not SAFE_QUERY_PARAM_REGEX.match(v):
                return None, (400, "ERR_QUERY_PARAMS_FORBIDDEN", "Query parameter is not permitted on this route.")
        elif canonical_route == "/v1/chat/completions":
            return None, (400, "ERR_QUERY_PARAMS_FORBIDDEN", "Query parameters are forbidden on /v1/chat/completions.")
        elif canonical_route == "/v1/models":
            if norm_k not in ("limit", "before_id", "after_id") or not SAFE_QUERY_PARAM_REGEX.match(v):
                return None, (400, "ERR_QUERY_PARAMS_FORBIDDEN", "Query parameter is not permitted on /v1/models.")
        else:
            return None, (400, "ERR_QUERY_PARAMS_FORBIDDEN", "Query parameters are not permitted on this route.")

        canonical_pairs.append(f"{norm_k}={v}" if v else norm_k)

    # Return reconstructed canonical query string to guarantee zero forwarding discrepancy!
    return "&".join(canonical_pairs), None


def canonicalize_and_validate_target(
    raw_target: str,
    local_port: int,
    expected_token: str,
) -> Tuple[Optional[str], Optional[str], Optional[Tuple[int, str, str]]]:
    """Strictly canonicalize and validate request target per Section 2.A & Findings 2, 6.

    Rejects ambiguous or dangerous forms outright instead of attempting unsafe repair.
    Returns: (canonical_path, query_string, error_tuple_or_none)
    """
    if not raw_target:
        return None, None, (400, "ERR_EMPTY_TARGET", "Request target cannot be empty.")

    # 1. Reject backslashes outright
    if "\\" in raw_target:
        return None, None, (400, "ERR_INVALID_PATH_SEPARATOR", "Backslashes are forbidden in request target.")

    # 2. Reject URI fragment identifiers (RFC 7230 §5.3 forbids fragments in request targets)
    if "#" in raw_target:
        return None, None, (400, "ERR_FRAGMENT_FORBIDDEN", "URI fragments are forbidden in request targets.")

    # 3. Check for malformed percent-encodings (e.g., % not followed by two hex digits)
    if re.search(r"%(?![0-9a-fA-F]{2})", raw_target):
        return None, None, (400, "ERR_MALFORMED_PERCENT_ENCODING", "Malformed percent-encoding in target.")

    # 4. Reject ambiguous encoded delimiters and double encoding
    for octet in FORBIDDEN_ENCODED_OCTETS:
        if octet in raw_target:
            return None, None, (400, "ERR_AMBIGUOUS_ENCODED_DELIMITER", "Encoded delimiters are forbidden in target.")

    # 5. Handle Absolute-Form Targets (e.g., http://127.0.0.1:8080/token/v1/messages)
    path_part = raw_target
    query_part = ""
    if raw_target.startswith(("http://", "https://")):
        try:
            sp = urlsplit(raw_target)
        except ValueError:
            return None, None, (400, "ERR_INVALID_ABSOLUTE_URI", "Malformed absolute-URI target.")
        if sp.username or sp.password:
            return None, None, (400, "ERR_USERINFO_FORBIDDEN", "Userinfo components are forbidden in request target.")
        if sp.fragment:
            return None, None, (400, "ERR_FRAGMENT_FORBIDDEN", "URI fragments are forbidden in request target.")
        if sp.scheme.lower() != "http":
            return None, None, (400, "ERR_INVALID_ABSOLUTE_SCHEME", "Absolute URI scheme must be http for local proxy listener.")
        if sp.hostname not in ("127.0.0.1", "localhost") or sp.port != local_port:
            return None, None, (400, "ERR_INVALID_ABSOLUTE_AUTHORITY", "Absolute URI authority does not match local proxy.")
        path_part = sp.path
        query_part = sp.query
    else:
        # Separate path and query explicitly
        if "?" in raw_target:
            path_part, query_part = raw_target.split("?", 1)
        else:
            query_part = ""

    # 6. Require origin-form leading slash
    if not path_part.startswith("/"):
        return None, None, (400, "ERR_INVALID_PATH_FORMAT", "Path must begin with a forward slash.")

    # 7. Reject direct traversal dot-segments
    if (
        "/../" in path_part
        or "/./" in path_part
        or path_part.endswith("/..")
        or path_part.endswith("/.")
        or path_part == ".."
        or path_part == "."
    ):
        return None, None, (400, "ERR_PATH_TRAVERSAL", "Path traversal dot-segments are forbidden.")

    # 8. Reject duplicate slashes
    if "//" in path_part:
        return None, None, (400, "ERR_DUPLICATE_SLASHES", "Duplicate slashes are forbidden.")

    # 9. Reject trailing slashes (enforce strict canonical paths)
    if path_part != "/" and path_part.endswith("/"):
        return None, None, (400, "ERR_TRAILING_SLASH", "Trailing slash is forbidden in request target.")

    # 10. Validate Capability Token Placement: Must be exactly /<token>/<endpoint>
    segments = [s for s in path_part.strip("/").split("/") if s]
    if not segments:
        return None, None, (401, "ERR_MISSING_CAPABILITY_TOKEN", "Missing session capability token.")

    token_candidate = segments[0]
    if not secrets.compare_digest(token_candidate, expected_token):
        return None, None, (401, "ERR_UNAUTHORIZED", "Invalid session capability token.")

    canonical_route = "/" + "/".join(segments[1:]) if len(segments) > 1 else "/"
    return canonical_route, query_part, None


class EventLogger:
    """Append-only 0600 JSONL event logger with structured allowlisted schema (C4, D)."""

    def __init__(self, log_path: Optional[Path] = None) -> None:
        base_dir = Path(os.environ.get("CLOAKLLM_HOME", str(Path.home() / ".cloakllm")))
        if base_dir.is_symlink():
            raise PermissionError(f"Log directory cannot be a symbolic link: {base_dir}")
        base_dir.mkdir(parents=True, exist_ok=True)
        if hasattr(os, "chmod") and hasattr(os, "getuid"):
            try:
                os.chmod(base_dir, 0o700)
            except OSError as exc:
                raise PermissionError(f"Failed to enforce private permissions on log directory: {base_dir}") from exc

        self.log_path = log_path or (base_dir / "events.jsonl")
        self._lock = threading.Lock()
        self._validate_path(self.log_path)
        self._ensure_permissions()

    def _validate_path(self, path: Path) -> None:
        if path.is_symlink():
            raise PermissionError(f"Log path cannot be a symbolic link: {path}")
        parent = path.parent
        if parent.is_symlink():
            raise PermissionError(f"Log parent directory cannot be a symbolic link: {parent}")
        if not parent.is_dir():
            raise PermissionError(f"Log parent is not a directory: {parent}")
        # POSIX directory ownership and permission verification
        if hasattr(os, "getuid"):
            st_p = parent.stat()
            if st_p.st_uid != os.getuid():
                raise PermissionError(f"Log directory not owned by current user: {parent}")
            if st_p.st_mode & 0o077 != 0:
                try:
                    os.chmod(parent, 0o700)
                except OSError as exc:
                    raise PermissionError(f"Failed to enforce private directory permissions on {parent}") from exc

    def _ensure_permissions(self) -> None:
        self._validate_path(self.log_path)
        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        try:
            fd = os.open(str(self.log_path), flags, 0o600)
            try:
                st = os.fstat(fd)
                if not stat.S_ISREG(st.st_mode):
                    raise PermissionError(f"Log target is not a regular file: {self.log_path}")
                # Descriptor-based chmod (immune to pathname race replacement)
                if hasattr(os, "fchmod"):
                    os.fchmod(fd, 0o600)
                if hasattr(os, "getuid"):
                    st_after = os.fstat(fd)
                    if st_after.st_mode & 0o077 != 0:
                        raise PermissionError(f"Failed to enforce private permissions on log file: {self.log_path}")
            finally:
                os.close(fd)
        except OSError as exc:
            if isinstance(exc, PermissionError):
                raise
            if self.log_path.is_symlink():
                raise PermissionError(f"Log path cannot be a symbolic link: {self.log_path}")
            raise

    def log(self, event_type: str, **fields: object) -> None:
        """Log structured event with allowlisted numeric/boolean/scalar attributes only.

        Excludes raw bodies, headers, and exception text by construction.
        """
        record: Dict[str, object] = {
            "ts": round(time.time(), 3),
            "event": str(event_type),
        }
        for k, v in fields.items():
            if isinstance(v, (int, float, bool)):
                record[k] = v
            elif isinstance(v, str) and len(v) <= 64 and "\n" not in v:
                record[k] = v
        line = (json.dumps(record, ensure_ascii=False) + "\n").encode("utf-8")

        flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        if hasattr(os, "O_BINARY"):
            flags |= os.O_BINARY

        with self._lock:
            try:
                self._validate_path(self.log_path)
                fd = os.open(str(self.log_path), flags, 0o600)
                try:
                    st = os.fstat(fd)
                    if not stat.S_ISREG(st.st_mode):
                        return
                    if hasattr(os, "fchmod"):
                        os.fchmod(fd, 0o600)
                    if hasattr(os, "getuid"):
                        st_after = os.fstat(fd)
                        if st_after.st_mode & 0o077 != 0:
                            return
                    os.write(fd, line)
                finally:
                    os.close(fd)
            except OSError:
                pass


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """ThreadingHTTPServer that enforces connection admission control BEFORE spawning threads."""

    def __init__(
        self,
        server_address: Tuple[str, int],
        RequestHandlerClass: type[BaseHTTPRequestHandler],
        max_connections: int = 64,
    ) -> None:
        super().__init__(server_address, RequestHandlerClass)
        self._connection_sem = threading.Semaphore(max_connections)

    def process_request(self, request: socket.socket, client_address: Tuple[str, int]) -> None:
        # Enforce connection bounding at socket accept level before spawning any thread!
        if not self._connection_sem.acquire(blocking=False):
            try:
                err_body = b'{"error":{"type":"overloaded_error","message":"Too many connections"}}'
                resp = (
                    b"HTTP/1.1 429 Too Many Requests\r\n"
                    b"Content-Type: application/json\r\n"
                    + f"Content-Length: {len(err_body)}\r\n".encode("ascii")
                    + b"Connection: close\r\n\r\n"
                    + err_body
                )
                request.sendall(resp)
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.close_request(request)
            return

        # Guard thread creation to prevent socket and semaphore leaks on thread startup failure
        try:
            worker = threading.Thread(
                target=self._guarded_process_request_thread,
                args=(request, client_address),
                daemon=True,
            )
            worker.start()
        except Exception:
            self._connection_sem.release()
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            finally:
                self.close_request(request)

    def _guarded_process_request_thread(self, request: socket.socket, client_address: Tuple[str, int]) -> None:
        try:
            self.finish_request(request, client_address)
        except Exception:
            self.handle_error(request, client_address)
        finally:
            self.close_request(request)
            self._connection_sem.release()


class CloakProxyServer:
    """Local HTTP/1.1 reverse proxy bound to 127.0.0.1 with per-run path token auth (B1)."""

    def __init__(
        self,
        vault: SecretVault,
        upstream_base_url: str = "https://api.anthropic.com",
        allow_passthrough: bool = False,
        url_token: Optional[str] = None,
        event_logger: Optional[EventLogger] = None,
        port: int = 0,
    ) -> None:
        self.vault = vault
        self.upstream_base_url = upstream_base_url.rstrip("/")
        self.allow_passthrough = allow_passthrough
        self.url_token = url_token or secrets.token_urlsafe(18)
        self.logger = event_logger or EventLogger()
        self.stats = ProxyStats()
        self._server: Optional[BoundedThreadingHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._requested_port = port
        self._concurrency_sem = threading.BoundedSemaphore(MAX_CONCURRENT_REQUESTS)

    @property
    def port(self) -> int:
        if self._server is None:
            raise RuntimeError("Proxy server is not started")
        return int(self._server.server_port)

    @property
    def base_url(self) -> str:
        """Return the capability-authenticated local base URL for ANTHROPIC_BASE_URL."""
        return f"http://127.0.0.1:{self.port}/{self.url_token}"

    def start(self) -> str:
        proxy_ref = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            timeout = 15.0

            def setup(self) -> None:
                super().setup()
                if self.connection is not None:
                    try:
                        self.connection.settimeout(15.0)
                    except OSError:
                        # Fail closed: never operate without enforced socket timeouts!
                        self.close_connection = True

            def handle_one_request(self) -> None:
                try:
                    super().handle_one_request()
                except (socket.timeout, TimeoutError):
                    self.close_connection = True

            def log_message(self, format: str, *args: object) -> None:
                # Zero TTY writes! Never corrupt Claude Code's raw ink/ncurses TUI (B6)
                return

            def do_GET(self) -> None:
                proxy_ref._handle_request(self, "GET")

            def do_POST(self) -> None:
                proxy_ref._handle_request(self, "POST")

            def do_PUT(self) -> None:
                proxy_ref._handle_request(self, "PUT")

            def do_DELETE(self) -> None:
                proxy_ref._handle_request(self, "DELETE")

        self._server = BoundedThreadingHTTPServer(
            ("127.0.0.1", self._requested_port),
            Handler,
            max_connections=MAX_CONCURRENT_REQUESTS,
        )
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        self.logger.log("proxy_started", port=self.port, upstream=self.upstream_base_url)
        return self.base_url

    def stop(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None
        if self._thread is not None:
            self._thread.join(timeout=2.0)
            self._thread = None
        self.logger.log(
            "proxy_stopped",
            requests_total=self.stats.requests_total,
            secrets_redacted=self.stats.secrets_redacted_outbound,
            tokens_rehydrated=self.stats.tokens_rehydrated_inbound,
        )

    def _send_json_error(
        self,
        handler: BaseHTTPRequestHandler,
        status: int,
        error_code: str,
        generic_message: str,
    ) -> None:
        """Return standardized, static error payload without leaking internal error strings or secrets."""
        # Finding 4: Close connection on error to avoid framing desync on unread bytes
        handler.close_connection = True
        body = json.dumps(
            {
                "type": "error",
                "error": {
                    "type": "cloakllm_proxy_error",
                    "code": error_code,
                    "message": generic_message,
                },
            }
        ).encode("utf-8")
        try:
            handler.send_response(status)
            handler.send_header("Content-Type", "application/json")
            handler.send_header("Content-Length", str(len(body)))
            handler.send_header("Connection", "close")
            handler.end_headers()
            handler.wfile.write(body)
            handler.wfile.flush()
        except OSError:
            pass

    def _handle_request(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        # Concurrency admission control
        if not self._concurrency_sem.acquire(blocking=False):
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("concurrency_exceeded", status=429)
            self._send_json_error(
                handler,
                429,
                "ERR_CONCURRENCY_LIMIT_EXCEEDED",
                "Too many concurrent requests to local proxy.",
            )
            return

        try:
            self._process_request(handler, method)
        finally:
            self._concurrency_sem.release()

    def _process_request(self, handler: BaseHTTPRequestHandler, method: str) -> None:
        with self.stats.lock:
            self.stats.requests_total += 1

        method_upper = method.upper()

        # 1. Canonicalize and Validate Request Target (Section 2.A & Findings 2, 6)
        canonical_route, query_part, target_err = canonicalize_and_validate_target(
            raw_target=handler.path,
            local_port=self.port,
            expected_token=self.url_token,
        )
        if target_err:
            status, code, msg = target_err
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("request_rejected", status=status, code=code)
            self._send_json_error(handler, status, code, msg)
            return

        assert canonical_route is not None

        # 2. Strict Query Parameter Policy & Secret Scanning (Finding 2)
        canonical_query, query_err = validate_and_inspect_query(canonical_route, query_part or "", self.vault)
        if query_err:
            status, code, msg = query_err
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("query_rejected", status=status, code=code)
            self._send_json_error(handler, status, code, msg)
            return

        # 3. Enforce Route-and-Method Allowlist with Passthrough Hardening (Section 2.C & Finding 1)
        route_key = (method_upper, canonical_route)
        if route_key not in ALLOWLISTED_ROUTES:
            if not self.allow_passthrough:
                with self.stats.lock:
                    self.stats.requests_blocked += 1
                self.logger.log("endpoint_blocked", status=403, method=method_upper, route=canonical_route)
                self._send_json_error(
                    handler,
                    403,
                    "ERR_ROUTE_FORBIDDEN",
                    "The requested method and route are not permitted by the allowlist policy.",
                )
                return
            else:
                # Finding 1: Passthrough MUST NEVER silently forward uninspected content
                if method_upper in ("POST", "PUT", "PATCH", "DELETE"):
                    with self.stats.lock:
                        self.stats.requests_blocked += 1
                    self.logger.log("passthrough_blocked", status=403, method=method_upper, route=canonical_route)
                    self._send_json_error(
                        handler,
                        403,
                        "ERR_UNINSPECTED_PAYLOAD_FORBIDDEN",
                        "Passthrough mode cannot forward uninspected content-bearing requests.",
                    )
                    return

        # 4. HTTP Message Framing & Header Validation (Section 2.B)
        cl_headers = handler.headers.get_all("Content-Length") or []
        if len(cl_headers) > 1:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_DUPLICATE_CONTENT_LENGTH")
            self._send_json_error(
                handler,
                400,
                "ERR_DUPLICATE_CONTENT_LENGTH",
                "Duplicate Content-Length headers are forbidden.",
            )
            return

        te_header = handler.headers.get("Transfer-Encoding")
        if te_header and cl_headers:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_CONFLICTING_FRAMING_HEADERS")
            self._send_json_error(
                handler,
                400,
                "ERR_CONFLICTING_FRAMING_HEADERS",
                "Cannot combine Transfer-Encoding and Content-Length headers.",
            )
            return

        if te_header:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_UNSUPPORTED_TRANSFER_ENCODING")
            self._send_json_error(
                handler,
                400,
                "ERR_UNSUPPORTED_TRANSFER_ENCODING",
                "Chunked transfer encoding is not supported for upstream requests.",
            )
            return

        content_len_str = handler.headers.get("Content-Length", "0").strip()
        if not ASCII_DIGITS_REGEX.fullmatch(content_len_str):
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_INVALID_CONTENT_LENGTH")
            self._send_json_error(
                handler,
                400,
                "ERR_INVALID_CONTENT_LENGTH",
                "Content-Length header must be a valid sequence of ASCII digits.",
            )
            return

        try:
            content_len = int(content_len_str)
        except ValueError:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_INVALID_CONTENT_LENGTH")
            self._send_json_error(
                handler,
                400,
                "ERR_INVALID_CONTENT_LENGTH",
                "Content-Length header must be a valid integer.",
            )
            return

        if content_len < 0:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_NEGATIVE_CONTENT_LENGTH")
            self._send_json_error(
                handler,
                400,
                "ERR_NEGATIVE_CONTENT_LENGTH",
                "Content-Length header cannot be negative.",
            )
            return

        if content_len > MAX_REQUEST_BODY_BYTES:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=413, code="ERR_PAYLOAD_TOO_LARGE")
            self._send_json_error(
                handler,
                413,
                "ERR_PAYLOAD_TOO_LARGE",
                "Request payload exceeds the maximum allowed boundary.",
            )
            return

        # Reject payload on GET /v1/models or any passthrough GET
        if method_upper in ("GET", "HEAD") and content_len > 0:
            with self.stats.lock:
                self.stats.requests_blocked += 1
            self.logger.log("framing_rejected", status=400, code="ERR_CONTENT_NOT_ALLOWED_ON_GET")
            self._send_json_error(
                handler,
                400,
                "ERR_CONTENT_NOT_ALLOWED_ON_GET",
                "GET requests must not contain a message body.",
            )
            return

        is_cloaked_endpoint = method_upper == "POST" and canonical_route in CLOAKED_POST_PATHS
        if is_cloaked_endpoint:
            raw_ctype = handler.headers.get("Content-Type") or ""
            parsed_ctype = raw_ctype.split(";")[0].strip().lower()
            if parsed_ctype != "application/json":
                with self.stats.lock:
                    self.stats.requests_blocked += 1
                self.logger.log("framing_rejected", status=415, code="ERR_UNSUPPORTED_MEDIA_TYPE")
                self._send_json_error(
                    handler,
                    415,
                    "ERR_UNSUPPORTED_MEDIA_TYPE",
                    "Content-Type must be application/json for content-bearing requests.",
                )
                return

        # 5. Read Request Body with Short-Read Assertion & Hard Total Deadline (Finding 1 & Invariant 4)
        if content_len > 0:
            read_chunks = []
            bytes_read = 0
            body_read_deadline = time.monotonic() + 30.0  # Hard 30s total request deadline
            original_timeout = handler.timeout
            try:
                while bytes_read < content_len:
                    remaining_deadline = body_read_deadline - time.monotonic()
                    if remaining_deadline <= 0:
                        handler.close_connection = True
                        with self.stats.lock:
                            self.stats.requests_blocked += 1
                        self.logger.log("framing_rejected", status=408, code="ERR_REQUEST_TIMEOUT")
                        if handler.connection is not None:
                            try:
                                handler.connection.settimeout(original_timeout)
                            except OSError:
                                pass
                        self._send_json_error(
                            handler,
                            408,
                            "ERR_REQUEST_TIMEOUT",
                            "Client exceeded total request body read deadline.",
                        )
                        return

                    # Dynamically clamp socket timeout so the blocking read cannot exceed total deadline!
                    chunk_timeout = min(15.0, remaining_deadline)
                    if handler.connection is not None:
                        try:
                            handler.connection.settimeout(chunk_timeout)
                        except OSError:
                            handler.close_connection = True
                            with self.stats.lock:
                                self.stats.requests_blocked += 1
                            self.logger.log("framing_rejected", status=500, code="ERR_SOCKET_TIMEOUT_FAILED")
                            self._send_json_error(
                                handler,
                                500,
                                "ERR_SOCKET_TIMEOUT_FAILED",
                                "Failed to configure socket read timeout.",
                            )
                            return

                    to_read = min(8192, content_len - bytes_read)
                    try:
                        # Use read1 to return immediately after at most one underlying read (Finding G)
                        read_fn = getattr(handler.rfile, "read1", handler.rfile.read)
                        chunk = read_fn(to_read)
                    except (socket.timeout, TimeoutError):
                        handler.close_connection = True
                        with self.stats.lock:
                            self.stats.requests_blocked += 1
                        self.logger.log("framing_rejected", status=408, code="ERR_REQUEST_TIMEOUT")
                        if handler.connection is not None:
                            try:
                                handler.connection.settimeout(original_timeout)
                            except OSError:
                                pass
                        self._send_json_error(
                            handler,
                            408,
                            "ERR_REQUEST_TIMEOUT",
                            "Socket timed out while reading request body.",
                        )
                        return

                    # Post-read deadline check: assert total deadline after chunk read finishes
                    if time.monotonic() > body_read_deadline:
                        handler.close_connection = True
                        with self.stats.lock:
                            self.stats.requests_blocked += 1
                        self.logger.log("framing_rejected", status=408, code="ERR_REQUEST_TIMEOUT")
                        if handler.connection is not None:
                            try:
                                handler.connection.settimeout(original_timeout)
                            except OSError:
                                pass
                        self._send_json_error(
                            handler,
                            408,
                            "ERR_REQUEST_TIMEOUT",
                            "Client exceeded total request body read deadline.",
                        )
                        return

                    if not chunk:
                        break
                    read_chunks.append(chunk)
                    bytes_read += len(chunk)
            finally:
                if handler.connection is not None:
                    try:
                        handler.connection.settimeout(original_timeout)
                    except OSError:
                        pass

            raw_body = b"".join(read_chunks)
            if len(raw_body) != content_len:
                handler.close_connection = True
                with self.stats.lock:
                    self.stats.requests_blocked += 1
                self.logger.log("framing_rejected", status=400, code="ERR_INCOMPLETE_REQUEST_BODY")
                self._send_json_error(
                    handler,
                    400,
                    "ERR_INCOMPLETE_REQUEST_BODY",
                    "Client sent fewer bytes than declared in Content-Length.",
                )
                return
        else:
            raw_body = b""

        # 6. Cloak Request Payload (Fail Closed without Leaking Exceptions!) (Section 2.D)
        is_streaming_request = False
        outbound_body = raw_body

        if is_cloaked_endpoint:
            try:
                def _pairs_hook(pairs):
                    seen = set()
                    out = {}
                    for k, v in pairs:
                        if k in seen:
                            raise ValueError(f"Duplicate JSON key: {k}")
                        seen.add(k)
                        out[k] = v
                    return out

                def _const_hook(c):
                    raise ValueError(f"Non-standard constant: {c}")

                parsed_json = json.loads(
                    raw_body.decode("utf-8"),
                    object_pairs_hook=_pairs_hook,
                    parse_constant=_const_hook,
                )
                if not isinstance(parsed_json, dict):
                    raise ValueError("JSON root must be an object")
                is_streaming_request = bool(parsed_json.get("stream") is True)
                cloaked_json, redacted_count = cloak_request_payload(
                    parsed_json, self.vault, canonical_route=canonical_route
                )
                outbound_body = json.dumps(cloaked_json, ensure_ascii=False).encode("utf-8")
                with self.stats.lock:
                    self.stats.requests_cloaked += 1
                    self.stats.secrets_redacted_outbound += redacted_count
                self.logger.log(
                    "request_cloaked",
                    status=200,
                    method=method_upper,
                    route=canonical_route,
                    redacted=redacted_count,
                    stream=is_streaming_request,
                )
            except Exception:
                # D: Zero secret leakage in error output or logs
                with self.stats.lock:
                    self.stats.requests_blocked += 1
                self.logger.log("request_cloak_error", status=500, route=canonical_route)
                self._send_json_error(
                    handler,
                    500,
                    "ERR_PAYLOAD_PROCESSING_FAILED",
                    "Failed to process and cloak request payload safely.",
                )
                return

        upstream_target_path = (
            f"{canonical_route}?{canonical_query}" if canonical_query else canonical_route
        )

        # 7. Forward to Upstream with Dynamic Hop-by-Hop & Stream Isolation (Section 2.E & Findings 5, 7)
        self._forward_upstream(
            handler=handler,
            method=method_upper,
            path_and_query=upstream_target_path,
            outbound_body=outbound_body,
            is_cloaked_endpoint=is_cloaked_endpoint,
            is_streaming_request=is_streaming_request,
        )

    def _on_rehydrate_event(self, kind: str, token: str) -> None:
        with self.stats.lock:
            if kind == "rehydrated":
                self.stats.tokens_rehydrated_inbound += 1
            elif kind == "unknown_token":
                self.stats.unknown_tokens_seen += 1
        self.logger.log(kind, token=token)

    def _forward_upstream(
        self,
        handler: BaseHTTPRequestHandler,
        method: str,
        path_and_query: str,
        outbound_body: bytes,
        is_cloaked_endpoint: bool,
        is_streaming_request: bool,
    ) -> None:
        up_split = urlsplit(self.upstream_base_url)
        use_https = up_split.scheme.lower() == "https"
        host = up_split.hostname or "api.anthropic.com"
        port = up_split.port or (443 if use_https else 80)
        base_prefix = up_split.path.rstrip("/")
        target_path = f"{base_prefix}{path_and_query}"

        # Finding 5: Parse dynamic hop-by-hop headers from Connection header per RFC 7230 §6.1
        conn_header = handler.headers.get("Connection", "")
        dynamic_hop = set()
        if conn_header:
            for item in conn_header.split(","):
                s = item.strip().lower()
                if s:
                    dynamic_hop.add(s)

        forward_headers: Dict[str, str] = {}
        for k, v in handler.headers.items():
            k_lower = k.lower()
            if k_lower not in HOP_BY_HOP_HEADERS and k_lower not in dynamic_hop:
                forward_headers[k] = v
        forward_headers["Host"] = host if port in (80, 443) else f"{host}:{port}"
        forward_headers["Accept-Encoding"] = "identity"
        if outbound_body:
            forward_headers["Content-Length"] = str(len(outbound_body))

        conn: http.client.HTTPConnection
        try:
            if use_https:
                ctx = ssl.create_default_context()
                conn = http.client.HTTPSConnection(host, port, context=ctx, timeout=120)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=120)

            conn.request(method, target_path, body=outbound_body, headers=forward_headers)
            resp = conn.getresponse()
        except Exception:
            self.logger.log("upstream_error", status=502)
            self._send_json_error(handler, 502, "ERR_UPSTREAM_CONNECTION_FAILED", "Failed to connect to upstream service.")
            return

        try:
            resp_content_type = (resp.getheader("Content-Type") or "").lower()
            is_sse = "text/event-stream" in resp_content_type

            # Dynamic hop-by-hop parsing for upstream response
            up_conn_header = resp.getheader("Connection") or ""
            up_dynamic_hop = set()
            if up_conn_header:
                for item in up_conn_header.split(","):
                    s = item.strip().lower()
                    if s:
                        up_dynamic_hop.add(s)

            if is_cloaked_endpoint and is_sse and resp.status == 200:
                handler.send_response(resp.status)
                for hk, hv in resp.getheaders():
                    hk_lower = hk.lower()
                    if hk_lower not in HOP_BY_HOP_HEADERS and hk_lower not in up_dynamic_hop:
                        handler.send_header(hk, hv)
                handler.send_header("Cache-Control", "no-cache")
                handler.send_header("Connection", "close")
                handler.end_headers()

                rehydrator = StreamRehydrator(
                    vault=self.vault, on_event=self._on_rehydrate_event
                )
                stream_aborted = False
                try:
                    total_streamed = 0
                    while True:
                        try:
                            chunk = resp.read(4096)
                        except Exception:
                            self.logger.log("upstream_stream_read_error", status=502)
                            stream_aborted = True
                            handler.close_connection = True
                            break

                        if not chunk:
                            break
                        total_streamed += len(chunk)
                        if total_streamed > MAX_RESPONSE_BODY_BYTES:
                            self.logger.log("streaming_limit_exceeded", status=502, bytes=total_streamed)
                            stream_aborted = True
                            handler.close_connection = True
                            try:
                                handler.wfile.close()
                            except OSError:
                                pass
                            return

                        out_bytes = rehydrator.feed_bytes(chunk, final=False)
                        if out_bytes:
                            try:
                                handler.wfile.write(out_bytes)
                                handler.wfile.flush()
                            except OSError:
                                stream_aborted = True
                                handler.close_connection = True
                                break

                    if not stream_aborted:
                        final_bytes = rehydrator.flush()
                        if final_bytes:
                            try:
                                handler.wfile.write(final_bytes)
                                handler.wfile.flush()
                            except OSError:
                                pass
                except Exception:
                    self.logger.log("streaming_rehydration_error", status=500)
                    handler.close_connection = True
                    try:
                        handler.wfile.close()
                    except OSError:
                        pass
                    return
            else:
                # Bounded response read up to MAX_RESPONSE_BODY_BYTES (50 MB)
                resp_chunks = []
                total_read = 0
                while True:
                    chunk = resp.read(65536)
                    if not chunk:
                        break
                    total_read += len(chunk)
                    if total_read > MAX_RESPONSE_BODY_BYTES:
                        self.logger.log("upstream_response_too_large", status=502)
                        self._send_json_error(
                            handler,
                            502,
                            "ERR_UPSTREAM_RESPONSE_TOO_LARGE",
                            "Upstream response exceeded maximum permitted body size.",
                        )
                        return
                    resp_chunks.append(chunk)
                raw_resp_body = b"".join(resp_chunks)

                # Finding 7: Fail closed on response rehydration failure!
                if is_cloaked_endpoint and "application/json" in resp_content_type and resp.status == 200:
                    try:
                        resp_json = json.loads(raw_resp_body.decode("utf-8"))
                        rehydrated_json, _ = rehydrate_json_value(
                            resp_json, self.vault, on_event=self._on_rehydrate_event
                        )
                        raw_resp_body = json.dumps(
                            rehydrated_json, ensure_ascii=False
                        ).encode("utf-8")
                    except Exception:
                        self.logger.log("rehydration_failed", status=500)
                        self._send_json_error(
                            handler,
                            500,
                            "ERR_RESPONSE_REHYDRATION_FAILED",
                            "Failed to safely rehydrate secrets in upstream response.",
                        )
                        return

                handler.send_response(resp.status)
                for hk, hv in resp.getheaders():
                    hk_lower = hk.lower()
                    if hk_lower not in HOP_BY_HOP_HEADERS and hk_lower not in up_dynamic_hop:
                        handler.send_header(hk, hv)
                handler.send_header("Content-Length", str(len(raw_resp_body)))
                handler.send_header("Connection", "close")
                handler.end_headers()
                if raw_resp_body:
                    handler.wfile.write(raw_resp_body)
                    handler.wfile.flush()
        finally:
            conn.close()
