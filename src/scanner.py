"""
Artifact scanner — discovers AI assistant artifacts across all known locations.

AI-agnostic: scans for artifacts from Claude, ChatGPT, Copilot, Cursor,
and any custom paths the user configures.

This module knows WHERE to look. The engine decides WHAT to do.

Coverage audit (2026-03-18):
  Before: 4 Claude scan targets (~15% of archivable artifacts)
  After:  18 Claude scan targets (~85-90% of archivable artifacts)
  Added: debug logs, file-history snapshots, plans, tasks, paste-cache,
         shell-snapshots, session metadata, project configs, skills,
         settings, subagent .jsonl.gz compressed logs
"""

from __future__ import annotations

from pathlib import Path
from typing import Iterator

from .config import ScanTarget


# Known AI assistant artifact locations (expandable)
KNOWN_ARTIFACT_LOCATIONS: dict[str, list[ScanTarget]] = {
    "claude": [
        # ===== P0: Critical — conversation history =====
        ScanTarget(
            path="~/.claude",
            pattern="history.jsonl",
            recursive=False,
            description="Claude main conversation history (4+ MB, 15K+ lines)",
        ),
        ScanTarget(
            path="~/.claude/projects",
            pattern="**/*.jsonl",
            recursive=True,
            description="Claude project-scoped session conversation logs",
        ),
        ScanTarget(
            path="~/.claude/projects",
            pattern="**/*.jsonl.gz",
            recursive=True,
            description="Claude subagent conversation logs (gzip compressed)",
        ),
        ScanTarget(
            path="~/.claude/projects",
            pattern="**/memory/**/*",
            recursive=True,
            description="Claude project memory files (persistent cross-session)",
        ),

        # ===== P1: Important — high value for context reconstruction =====
        ScanTarget(
            path="~/.claude/debug",
            pattern="*.txt",
            description="Claude debug logs — error traces, tool outputs, recovery patterns",
        ),
        ScanTarget(
            path="~/.claude/file-history",
            pattern="**/*",
            recursive=True,
            description="File content snapshots at context injection time",
        ),
        ScanTarget(
            path="~/.claude/tasks",
            pattern="**/*.json",
            recursive=True,
            description="Task list state, definitions, dependencies between sessions",
        ),
        ScanTarget(
            path="~/.claude/todos",
            pattern="*.json",
            description="Ad-hoc todo entries and priority tracking",
        ),
        ScanTarget(
            path="~/.claude/plans",
            pattern="*.md",
            description="Multi-step plans and strategic approach documents",
        ),
        ScanTarget(
            path="~/.claude/skills",
            pattern="**/*.md",
            recursive=True,
            description="Installed skill definitions (SKILL.md files)",
        ),
        ScanTarget(
            path="~/.claude",
            pattern="settings*.json",
            recursive=False,
            description="Claude Code configuration (permissions, env vars, features)",
        ),

        # ===== P2: Useful — moderate context value =====
        ScanTarget(
            path="~/.claude/paste-cache",
            pattern="*",
            description="Pasted code snippets and text blocks shared during sessions",
        ),
        ScanTarget(
            path="~/.claude/shell-snapshots",
            pattern="*.sh",
            description="Shell environment state snapshots (PATH, aliases)",
        ),
        ScanTarget(
            path="~/.claude/sessions",
            pattern="*.json",
            description="Session metadata — start/end times, IDs, status",
        ),
        ScanTarget(
            path="~/.claude/backups",
            pattern="*.json",
            description="Periodic state backups",
        ),
        ScanTarget(
            path="~/.claude/subagents",
            pattern="*.jsonl",
            description="Claude subagent conversation logs (legacy location)",
        ),

        # ===== macOS-specific: MCP integration logs =====
        ScanTarget(
            path="~/Library/Caches/claude-cli-nodejs",
            pattern="**/*",
            recursive=True,
            description="MCP server logs (Gmail, Calendar, Chrome, VSCode integrations)",
        ),
    ],
    "chatgpt": [
        ScanTarget(
            path="~/Library/Application Support/com.openai.chat",
            pattern="**/*.json",
            description="ChatGPT desktop app cache (macOS)",
        ),
    ],
    "cursor": [
        ScanTarget(
            path="~/.cursor",
            pattern="**/*.jsonl",
            description="Cursor AI conversation logs",
        ),
    ],
    "copilot": [
        ScanTarget(
            path="~/.config/github-copilot",
            pattern="**/*.json",
            description="GitHub Copilot cache",
        ),
    ],
    "generic": [
        ScanTarget(
            path="~/.local/share/ai-memory",
            pattern="*",
            description="Generic AI memory store",
        ),
    ],
}


def discover_installed_assistants() -> dict[str, list[ScanTarget]]:
    """
    Auto-detect which AI assistants have artifacts on this system.
    Returns only the ones with existing directories.
    """
    found: dict[str, list[ScanTarget]] = {}

    for name, targets in KNOWN_ARTIFACT_LOCATIONS.items():
        existing = []
        for t in targets:
            if t.resolve().exists():
                existing.append(t)
        if existing:
            found[name] = existing

    return found


def iter_artifacts(targets: list[ScanTarget]) -> Iterator[Path]:
    """
    Yield all artifact files matching the given scan targets.
    Skips already-compressed (.zst), encrypted (.encf), temp (.tmp),
    Parquet (.parquet), and symlinks.
    """
    skip_suffixes = {".zst", ".encf", ".tmp", ".parquet"}

    for target in targets:
        base = target.resolve()
        if not base.exists():
            continue

        base_resolved = base.resolve()
        pattern = f"**/{target.pattern}" if target.recursive else target.pattern

        for match in base.glob(pattern):
            # Skip symlinks (prevents cross-directory reads)
            if match.is_symlink():
                continue
            # Containment check — file must stay within scan root
            try:
                match.resolve().relative_to(base_resolved)
            except ValueError:
                continue
            if match.is_file() and match.suffix not in skip_suffixes:
                yield match
