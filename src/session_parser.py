"""
Claude Code session parser — extracts real conversation content from JSONL files.

Session files contain: progress events, file snapshots, system hooks, AND
actual human/assistant messages. Only the messages matter for memory.

Format:
  {"type": "user", "message": {"role": "human", "content": "..."}, ...}
  {"type": "assistant", "message": {"role": "assistant", "content": [{"type": "text", "text": "..."}]}, ...}

Content can be:
  - A string (simple message)
  - A list of content blocks [{"type": "text", "text": "..."}, {"type": "tool_use", ...}]

This parser extracts conversation text, generates summaries, and extracts
meaningful keywords — replacing the current garbage extraction that indexes
JSONL field names instead of conversation content.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Optional
from collections import Counter


# Keywords to EXCLUDE (stop words + JSONL metadata noise)
STOP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why",
    "how", "all", "each", "every", "both", "few", "more", "most", "other",
    "some", "such", "no", "not", "only", "same", "so", "than", "too",
    "very", "just", "don", "now", "also", "but", "and", "or", "if",
    "this", "that", "these", "those", "it", "its", "they", "them",
    "their", "we", "our", "you", "your", "i", "me", "my", "he", "she",
    "his", "her", "what", "which", "who", "whom", "let", "use", "make",
    "like", "get", "got", "one", "two", "new", "first", "well", "way",
    "about", "up", "out", "much", "right", "still", "thing", "need",
    # JSONL metadata noise
    "type", "messageid", "snapshot", "issnaphotupdate", "parentuuid",
    "issidechain", "data", "tooltipuseid", "timestamp", "uuid",
    "usertype", "entrypoint", "cwd", "sessionid", "version", "gitbranch",
    "entries", "fields", "true", "false", "null", "none",
})

# Minimum keyword length
MIN_KEYWORD_LEN = 3

# Max keywords to extract
MAX_KEYWORDS = 30


def parse_session(path: Path) -> Optional[SessionContent]:
    """Parse a Claude Code session JSONL file into structured content."""
    if not path.exists():
        return None

    messages = []
    session_id = None
    cwd = None

    try:
        with open(path, errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    continue

                msg_type = obj.get("type", "")

                # Extract session metadata from first message
                if session_id is None:
                    session_id = obj.get("sessionId", "")
                    cwd = obj.get("cwd", "")

                # Parse human messages
                if msg_type == "user":
                    text = _extract_message_text(obj)
                    if text and len(text) > 5:
                        messages.append(Message(role="human", text=text, timestamp=obj.get("timestamp", "")))

                # Parse assistant messages
                elif msg_type == "assistant":
                    text = _extract_message_text(obj)
                    if text and len(text) > 5:
                        messages.append(Message(role="assistant", text=text, timestamp=obj.get("timestamp", "")))

    except (PermissionError, OSError):
        return None

    if not messages:
        return None

    return SessionContent(
        path=str(path),
        session_id=session_id or "",
        cwd=cwd or "",
        messages=messages,
    )


def _extract_message_text(obj: dict) -> str:
    """Extract text content from a session message object."""
    msg = obj.get("message", {})
    if not isinstance(msg, dict):
        return ""

    content = msg.get("content", "")

    # String content
    if isinstance(content, str):
        return content.strip()

    # List of content blocks
    if isinstance(content, list):
        texts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text" and "text" in block:
                    texts.append(block["text"])
        return " ".join(texts).strip()

    return ""


class Message:
    __slots__ = ("role", "text", "timestamp")

    def __init__(self, role: str, text: str, timestamp: str = ""):
        self.role = role
        self.text = text
        self.timestamp = timestamp


class SessionContent:
    """Parsed session with extracted content, summary, and keywords."""

    def __init__(self, path: str, session_id: str, cwd: str, messages: list[Message]):
        self.path = path
        self.session_id = session_id
        self.cwd = cwd
        self.messages = messages

    @property
    def human_messages(self) -> list[Message]:
        return [m for m in self.messages if m.role == "human"]

    @property
    def assistant_messages(self) -> list[Message]:
        return [m for m in self.messages if m.role == "assistant"]

    @property
    def full_text(self) -> str:
        """All message text concatenated."""
        return "\n\n".join(m.text for m in self.messages)

    @property
    def conversation_text(self) -> str:
        """Human + assistant messages formatted as a conversation."""
        parts = []
        for m in self.messages:
            prefix = "Human:" if m.role == "human" else "Assistant:"
            parts.append(f"{prefix} {m.text[:500]}")
        return "\n".join(parts)

    def generate_summary(self, max_length: int = 300) -> str:
        """Generate a meaningful summary from the conversation.

        Strategy:
        1. First human message = the topic/request
        2. Key assistant decisions/conclusions
        3. Truncate to max_length
        """
        parts = []

        # The first human message is usually the task/topic
        if self.human_messages:
            first_human = self.human_messages[0].text[:200]
            # Clean up: remove image references, system prompts
            first_human = re.sub(r'\[Image:.*?\]', '[image]', first_human)
            parts.append(first_human)

        # Find key decisions/conclusions from assistant
        decision_patterns = [
            r'(?:decided|decision|chose|choosing|picked|selected|went with|going with)\s+(.{20,100})',
            r'(?:built|created|added|implemented|shipped|deployed)\s+(.{20,100})',
            r'(?:the (?:fix|solution|answer|result|approach) (?:is|was))\s+(.{20,100})',
        ]

        for msg in self.assistant_messages[:10]:  # Check first 10 assistant messages
            for pattern in decision_patterns:
                match = re.search(pattern, msg.text, re.IGNORECASE)
                if match:
                    parts.append(match.group(0)[:100])
                    break

        summary = ". ".join(parts)[:max_length]
        if not summary:
            # Fallback: first 300 chars of conversation
            summary = self.full_text[:max_length]

        return summary

    def extract_keywords(self, max_keywords: int = MAX_KEYWORDS) -> list[str]:
        """Extract meaningful keywords from conversation content.

        Strategy:
        1. Count word frequency across all messages
        2. Filter stop words and noise
        3. Boost words that appear in human messages (user's actual vocabulary)
        4. Return top N by score
        """
        word_counts: Counter = Counter()
        human_words: Counter = Counter()

        for msg in self.messages:
            words = _tokenize(msg.text)
            word_counts.update(words)
            if msg.role == "human":
                human_words.update(words)

        # Score: frequency + 2x boost for human words
        scored: dict[str, float] = {}
        for word, count in word_counts.items():
            if word in STOP_WORDS:
                continue
            if len(word) < MIN_KEYWORD_LEN:
                continue
            if word.isdigit():
                continue
            # Filter hex hashes and random tokens
            if re.match(r'^[0-9a-f]{8,}$', word):
                continue

            score = count + (human_words.get(word, 0) * 2)
            scored[word] = score

        # Sort by score, return top N
        sorted_words = sorted(scored.items(), key=lambda x: -x[1])
        return [word for word, _ in sorted_words[:max_keywords]]

    def extract_section_headers(self) -> list[str]:
        """Find markdown section headers in assistant responses."""
        headers = []
        for msg in self.assistant_messages:
            for match in re.finditer(r'^#{1,3}\s+(.+)$', msg.text, re.MULTILINE):
                header = match.group(1).strip()
                if len(header) > 3 and header not in headers:
                    headers.append(header)
        return headers[:20]


def _tokenize(text: str) -> list[str]:
    """Split text into lowercase words, stripping punctuation."""
    # Remove code blocks (they add noise)
    text = re.sub(r'```[\s\S]*?```', '', text)
    # Remove URLs
    text = re.sub(r'https?://\S+', '', text)
    # Split on non-alphanumeric
    words = re.findall(r'[a-zA-Z][a-zA-Z0-9_-]{2,}', text.lower())
    return words
