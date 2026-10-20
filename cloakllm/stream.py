"""Grammar-Driven Prefix-Viability Hold-Back & SSE Stream Rehydrator (B3)."""

from __future__ import annotations

import codecs
import json
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Tuple

from cloakllm.secrets import SecretVault

# ---------------------------------------------------------------------------
# Token Matchers (C2: 128-bit / 32-hex tag, C3: Exact-Only Resolution)
# ---------------------------------------------------------------------------
DECODED_TOKEN_RE = re.compile(
    r"\\?CLOAKv1(?:\\?_)(?P<cat>[A-Z0-9]{2,12})(?:\\?_)(?P<tag>[0-9a-fA-F]{32})",
    re.IGNORECASE,
)

RAW_JSON_SEP = r"(?:\\\\_|\\_|\\u005[fF]|_)"
RAW_JSON_TOKEN_RE = re.compile(
    rf"(?:\\\\|\\)?CLOAKv1{RAW_JSON_SEP}(?P<cat>[A-Z0-9]{{2,12}}){RAW_JSON_SEP}(?P<tag>[0-9a-fA-F]{{32}})",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Grammar-Driven Prefix-Viability State Machine for Hold-Back (B3)
# ---------------------------------------------------------------------------
_SEP_PREFIXES = (
    r"\\\\_|\\\\|\\_|\\u005[fF]|\\u005|\\u00|\\u0|\\u|\\|_"
)
_FULL_SEP = r"(?:\\\\_|\\_|\\u005[fF]|_)"

VIABLE_PREFIX_RE = re.compile(
    rf"^(?:\\\\|\\)?(?:"
    rf"C(?:L(?:O(?:A(?:K(?:v(?:1(?:"
    rf"(?:{_SEP_PREFIXES})"
    rf"|(?:{_FULL_SEP})[A-Za-z0-9]{{1,12}}"
    rf"|(?:{_FULL_SEP})[A-Za-z0-9]{{2,12}}(?:{_SEP_PREFIXES})"
    rf"|(?:{_FULL_SEP})[A-Za-z0-9]{{2,12}}(?:{_FULL_SEP})[0-9a-fA-F]{{1,31}}"
    rf")?)?)?)?)?)?)?"
    rf")$",
    re.IGNORECASE,
)

MAX_TOKEN_PREFIX_LEN = 72


def is_viable_token_prefix(s: str) -> bool:
    """Return True if string s can still grow into a valid CLOAKv1_<CAT>_<32HEX> token."""
    if not s or len(s) > MAX_TOKEN_PREFIX_LEN:
        return False
    if s in ("\\", "\\\\"):
        return True
    first = s[0]
    if first not in ("\\", "c", "C"):
        return False
    return bool(VIABLE_PREFIX_RE.match(s))


def split_holdback(text: str) -> Tuple[str, str]:
    """Split `text` into `(safe_to_emit, holdback_suffix)` using the grammar prefix checker."""
    if not text:
        return "", ""
    n = len(text)
    start_min = max(0, n - MAX_TOKEN_PREFIX_LEN)
    for idx in range(start_min, n):
        candidate = text[idx:]
        if candidate[0] in ("\\", "c", "C") and is_viable_token_prefix(candidate):
            return text[:idx], candidate
    return text, ""


def escape_for_json_string(secret: str) -> str:
    """RFC 8259 compliant escaping for injecting a secret into a raw JSON string fragment."""
    return json.dumps(secret)[1:-1]


def rehydrate_text_fragment(
    text: str,
    vault: SecretVault,
    is_raw_json_fragment: bool = False,
    on_event: Optional[Callable[[str, str], None]] = None,
) -> Tuple[str, int]:
    r"""Replace all CLOAKv1_<CAT>_<32HEX> tokens in `text` with their original secrets.

    - C3: Exact-only match. Unknown/corrupted tokens are NEVER substituted with real credentials.
    - If `is_raw_json_fragment=True`, uses `RAW_JSON_TOKEN_RE` and escapes restored
      secrets via `json.dumps(secret)[1:-1]`.
    - Otherwise uses `DECODED_TOKEN_RE` and inserts the raw secret directly.
    """
    if not text or ("cloak" not in text.lower()):
        return text, 0

    pattern = RAW_JSON_TOKEN_RE if is_raw_json_fragment else DECODED_TOKEN_RE
    restored_count = 0

    def _repl(match: re.Match[str]) -> str:
        nonlocal restored_count
        cat = match.group("cat")
        tag = match.group("tag")

        # C3: Strict exact-only lookup
        entry = vault.resolve_token(cat, tag)
        if entry is None:
            if on_event:
                on_event("unknown_token", match.group(0))
            return match.group(0)

        restored_count += 1
        if on_event:
            on_event("rehydrated", entry.token)
        return escape_for_json_string(entry.secret) if is_raw_json_fragment else entry.secret

    return pattern.sub(_repl, text), restored_count


def rehydrate_json_value(
    obj: object,
    vault: SecretVault,
    on_event: Optional[Callable[[str, str, bool], None]] = None,
) -> Tuple[object, int]:
    """Recursively rehydrate tokens in a non-streaming JSON response, skipping thinking/signed blocks (B1)."""
    if isinstance(obj, str):
        return rehydrate_text_fragment(obj, vault, is_raw_json_fragment=False, on_event=on_event)
    if isinstance(obj, list):
        total = 0
        out_list = []
        for item in obj:
            r_item, c = rehydrate_json_value(item, vault, on_event=on_event)
            out_list.append(r_item)
            total += c
        return out_list, total
    if isinstance(obj, dict):
        # Extended-Thinking & Signature Immunity (B1):
        block_type = obj.get("type")
        if block_type in ("thinking", "redacted_thinking") or "signature" in obj:
            return obj, 0

        total = 0
        out_dict = {}
        for k, v in obj.items():
            # Finding L: Rehydrate dictionary keys as well as values
            r_k, k_c = rehydrate_text_fragment(str(k), vault, is_raw_json_fragment=False, on_event=on_event)
            total += k_c
            if k in ("type", "role", "id", "model", "stop_reason", "signature"):
                out_dict[r_k] = v
            elif k == "input" and isinstance(v, dict):
                r_v, c = rehydrate_json_value(v, vault, on_event=on_event)
                out_dict[r_k] = r_v
                total += c
            else:
                r_v, c = rehydrate_json_value(v, vault, on_event=on_event)
                out_dict[r_k] = r_v
                total += c
        return out_dict, total
    return obj, 0


@dataclass
class StreamSlotBuffer:
    """Independent per-(choice_idx, block_idx, tool_idx) hold-back buffer."""

    pending: str = ""
    is_raw_json: bool = False
    is_thinking_or_signed: bool = False


class StreamRehydrator:
    """Stateful SSE stream rehydrator with UTF-8 incremental decoding & per-index hold-back (B3)."""

    def __init__(
        self,
        vault: SecretVault,
        on_event: Optional[Callable[[str, str], None]] = None,
    ) -> None:
        self.vault = vault
        self.on_event = on_event
        self._utf8_decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self._sse_buffer: str = ""
        # Keyed by (choice_idx, block_idx, tool_idx, kind)
        self._slots: Dict[Tuple[int, int, int, str], StreamSlotBuffer] = {}
        # Track block indices that are thinking / redacted_thinking / signed
        self._immune_blocks: Dict[int, bool] = {}
        self.total_rehydrated: int = 0

    def feed_bytes(self, chunk: bytes, final: bool = False) -> bytes:
        """Feed raw TCP bytes from upstream and return rehydrated SSE bytes ready for client."""
        decoded = self._utf8_decoder.decode(chunk, final=final)
        self._sse_buffer += decoded
        return self._drain_sse_events(flush_all=final).encode("utf-8")

    def flush(self) -> bytes:
        """Flush any remaining UTF-8 bytes and held-back slot suffixes at stream end."""
        tail = self._utf8_decoder.decode(b"", final=True)
        self._sse_buffer += tail
        return self._drain_sse_events(flush_all=True).encode("utf-8")

    def _drain_sse_events(self, flush_all: bool = False) -> str:
        """Parse complete SSE events separated by blank lines (\\n\\n or \\r\\n\\r\\n)."""
        out_events: List[str] = []

        while True:
            # Find earliest SSE event boundary (\r\n\r\n or \n\n)
            m = re.search(r"\r?\n\r?\n", self._sse_buffer)
            if not m:
                break
            raw_event = self._sse_buffer[: m.start()]
            sep = self._sse_buffer[m.start() : m.end()]
            self._sse_buffer = self._sse_buffer[m.end() :]
            processed = self._process_single_sse_event(raw_event, sep)
            out_events.append(processed)

        if flush_all:
            # Flush any held-back slot characters as synthetic delta events before final tail
            flushed_events = self._flush_all_slots()
            out_events.extend(flushed_events)
            if self._sse_buffer:
                out_events.append(self._process_single_sse_event(self._sse_buffer, ""))
                self._sse_buffer = ""

        return "".join(out_events)

    def _process_fragment_in_slot(
        self,
        slot_key: Tuple[int, int, int, str],
        incoming: str,
        is_raw_json: bool,
        flush: bool = False,
    ) -> str:
        slot = self._slots.setdefault(slot_key, StreamSlotBuffer(is_raw_json=is_raw_json))
        combined = slot.pending + incoming
        rehydrated, count = rehydrate_text_fragment(
            combined,
            self.vault,
            is_raw_json_fragment=is_raw_json,
            on_event=self.on_event,
        )
        self.total_rehydrated += count

        if flush:
            slot.pending = ""
            return rehydrated

        safe_emit, holdback = split_holdback(rehydrated)
        slot.pending = holdback
        return safe_emit

    def _flush_all_slots(self) -> List[str]:
        """Emit synthetic SSE delta events for any non-empty slot holdbacks."""
        synthetic: List[str] = []
        for (choice_idx, block_idx, tool_idx, kind), slot in list(self._slots.items()):
            if not slot.pending:
                continue
            flushed_text, count = rehydrate_text_fragment(
                slot.pending,
                self.vault,
                is_raw_json_fragment=slot.is_raw_json,
                on_event=self.on_event,
            )
            self.total_rehydrated += count
            slot.pending = ""
            if not flushed_text:
                continue
            if kind == "anthropic_text":
                payload = {
                    "type": "content_block_delta",
                    "index": block_idx,
                    "delta": {"type": "text_delta", "text": flushed_text},
                }
                synthetic.append(f"event: content_block_delta\ndata: {json.dumps(payload)}\n\n")
            elif kind == "anthropic_json":
                payload = {
                    "type": "content_block_delta",
                    "index": block_idx,
                    "delta": {"type": "input_json_delta", "partial_json": flushed_text},
                }
                synthetic.append(f"event: content_block_delta\ndata: {json.dumps(payload)}\n\n")
            elif kind == "openai_text":
                payload = {
                    "choices": [{"index": choice_idx, "delta": {"content": flushed_text}}],
                }
                synthetic.append(f"data: {json.dumps(payload)}\n\n")
            elif kind == "openai_tool":
                payload = {
                    "choices": [
                        {
                            "index": choice_idx,
                            "delta": {
                                "tool_calls": [
                                    {"index": tool_idx, "function": {"arguments": flushed_text}}
                                ]
                            },
                        }
                    ],
                }
                synthetic.append(f"data: {json.dumps(payload)}\n\n")
        return synthetic

    def _process_single_sse_event(self, raw_event: str, sep: str) -> str:
        if not raw_event.strip():
            return raw_event + sep

        lines = raw_event.splitlines()
        event_line_prefix: List[str] = []
        data_lines: List[str] = []
        other_lines: List[str] = []

        for line in lines:
            if line.startswith("data:"):
                data_lines.append(line[5:].lstrip(" "))
            elif line.startswith("event:"):
                event_line_prefix.append(line)
            else:
                other_lines.append(line)

        if not data_lines:
            return raw_event + sep

        data_str = "\n".join(data_lines)
        if data_str.strip() == "[DONE]":
            flushed = "".join(self._flush_all_slots())
            return flushed + raw_event + sep

        try:
            payload = json.loads(data_str)
        except json.JSONDecodeError:
            return raw_event + sep

        if not isinstance(payload, dict):
            return raw_event + sep

        ev_type = payload.get("type")

        # -------------------------------------------------------------------
        # Anthropic Messages SSE Format
        # -------------------------------------------------------------------
        if ev_type == "content_block_start":
            idx = int(payload.get("index", 0))
            cb = payload.get("content_block") or {}
            cb_type = cb.get("type")
            if cb_type in ("thinking", "redacted_thinking") or "signature" in cb:
                self._immune_blocks[idx] = True
            else:
                self._immune_blocks[idx] = False
                if cb_type == "text" and isinstance(cb.get("text"), str) and cb["text"]:
                    cb["text"] = self._process_fragment_in_slot(
                        (0, idx, 0, "anthropic_text"), cb["text"], is_raw_json=False
                    )
            return self._rebuild_sse(event_line_prefix, other_lines, payload, sep)

        if ev_type == "content_block_delta":
            idx = int(payload.get("index", 0))
            if self._immune_blocks.get(idx, False):
                return raw_event + sep
            delta = payload.get("delta")
            if not isinstance(delta, dict):
                return raw_event + sep
            d_type = delta.get("type")
            # Never touch thinking_delta or signature_delta (B1)
            if d_type in ("thinking_delta", "signature_delta") or "signature" in delta:
                return raw_event + sep
            if d_type == "text_delta" and isinstance(delta.get("text"), str):
                delta["text"] = self._process_fragment_in_slot(
                    (0, idx, 0, "anthropic_text"), delta["text"], is_raw_json=False
                )
                return self._rebuild_sse(event_line_prefix, other_lines, payload, sep)
            if d_type == "input_json_delta" and isinstance(delta.get("partial_json"), str):
                delta["partial_json"] = self._process_fragment_in_slot(
                    (0, idx, 0, "anthropic_json"), delta["partial_json"], is_raw_json=True
                )
                return self._rebuild_sse(event_line_prefix, other_lines, payload, sep)
            return raw_event + sep

        if ev_type == "content_block_stop":
            idx = int(payload.get("index", 0))
            prefix_flushed: List[str] = []
            for kind in ("anthropic_text", "anthropic_json"):
                key = (0, idx, 0, kind)
                slot = self._slots.get(key)
                if slot and slot.pending:
                    flushed_text = self._process_fragment_in_slot(
                        key, "", is_raw_json=slot.is_raw_json, flush=True
                    )
                    if flushed_text:
                        d_obj = (
                            {"type": "text_delta", "text": flushed_text}
                            if kind == "anthropic_text"
                            else {"type": "input_json_delta", "partial_json": flushed_text}
                        )
                        syn = {
                            "type": "content_block_delta",
                            "index": idx,
                            "delta": d_obj,
                        }
                        prefix_flushed.append(
                            f"event: content_block_delta\ndata: {json.dumps(syn)}\n\n"
                        )
            return "".join(prefix_flushed) + raw_event + sep

        if ev_type in ("message_stop", "error"):
            flushed_str = "".join(self._flush_all_slots())
            return flushed_str + raw_event + sep

        # -------------------------------------------------------------------
        # OpenAI Chat Completions SSE Format (Secondary Support)
        # -------------------------------------------------------------------
        if "choices" in payload and isinstance(payload["choices"], list):
            flushed_before: List[str] = []
            for ch in payload["choices"]:
                if not isinstance(ch, dict):
                    continue
                c_idx = int(ch.get("index", 0))
                delta = ch.get("delta")
                if isinstance(delta, dict):
                    if isinstance(delta.get("content"), str):
                        delta["content"] = self._process_fragment_in_slot(
                            (c_idx, 0, 0, "openai_text"), delta["content"], is_raw_json=False
                        )
                    if isinstance(delta.get("tool_calls"), list):
                        for tc in delta["tool_calls"]:
                            if isinstance(tc, dict):
                                t_idx = int(tc.get("index", 0))
                                fn = tc.get("function")
                                if isinstance(fn, dict) and isinstance(fn.get("arguments"), str):
                                    fn["arguments"] = self._process_fragment_in_slot(
                                        (c_idx, 0, t_idx, "openai_tool"),
                                        fn["arguments"],
                                        is_raw_json=True,
                                    )
                if ch.get("finish_reason") is not None:
                    flushed_before.extend(self._flush_all_slots())
            return "".join(flushed_before) + self._rebuild_sse(
                event_line_prefix, other_lines, payload, sep
            )

        return raw_event + sep

    @staticmethod
    def _rebuild_sse(
        event_lines: List[str],
        other_lines: List[str],
        payload: dict,
        sep: str,
    ) -> str:
        parts: List[str] = []
        parts.extend(event_lines)
        parts.extend(other_lines)
        parts.append(f"data: {json.dumps(payload, ensure_ascii=False)}")
        line_join = "\r\n" if "\r\n" in sep else "\n"
        return line_join.join(parts) + sep
