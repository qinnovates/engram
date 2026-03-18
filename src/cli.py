#!/usr/bin/env python3
"""
CLI for engram-engine.

Usage:
  engram run [--config PATH] [--dry-run] [--verbose]
  engram status [--config PATH]
  engram recall <file> [--config PATH]
  engram init [--config PATH]
  engram scan [--config PATH]
  engram encrypt-setup
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from .config import EngineConfig
from .engine import TieringEngine
from .encryption import check_age_installed, AgeNotFoundError
from .setup import run_guided_setup, run_interactive_setup


DEFAULT_CONFIG = "~/.engram/config.json"


def cmd_init(args: argparse.Namespace) -> None:
    """Initialize configuration — guided or interactive setup."""
    config_path = Path(args.config).expanduser()
    if config_path.exists() and not args.force:
        print(f"Config already exists: {config_path}")
        print("Use --force to overwrite.")
        return

    mode = getattr(args, "mode", "guided")

    if mode == "interactive":
        run_interactive_setup(config_path)
    elif mode == "auto":
        # Silent mode — no prompts, use all defaults
        config = EngineConfig()
        config.scan_targets = EngineConfig.default_claude_targets()
        config.save(config_path)
        print(f"Config initialized: {config_path}")
        print(f"Scan targets: {len(config.scan_targets)}")
    else:
        run_guided_setup(config_path)


def cmd_scan(args: argparse.Namespace) -> None:
    """Scan for artifacts without tiering."""
    config = EngineConfig.load(args.config)
    config.verbose = args.verbose
    engine = TieringEngine(config)

    discovered = engine.scan()
    engine.register_all(discovered)

    print(f"Discovered {len(discovered)} artifacts:")
    for p in discovered:
        s = p.stat()
        age_h = (time.time() - s.st_ctime) / 3600
        print(f"  {p}  ({s.st_size:,} bytes, {age_h:.1f}h old)")


def cmd_run(args: argparse.Namespace) -> None:
    """Run the tiering engine."""
    config = EngineConfig.load(args.config)
    config.dry_run = args.dry_run
    config.verbose = args.verbose
    engine = TieringEngine(config)

    actions = engine.run()

    if not actions:
        print("No tier transitions needed.")
        return

    prefix = "[DRY RUN] " if config.dry_run else ""
    print(f"{prefix}Tier transitions: {len(actions)}")
    total_saved = 0
    for a in actions:
        print(f"  {a}")
        if not a.dry_run:
            total_saved += a.original_size - a.new_size

    if not config.dry_run and total_saved > 0:
        print(f"\nTotal space saved: {total_saved:,} bytes ({total_saved / 1024:.1f} KB)")


def cmd_status(args: argparse.Namespace) -> None:
    """Show current tier distribution."""
    config = EngineConfig.load(args.config)
    engine = TieringEngine(config)
    stats = engine.status()

    print("Tiered Memory Status")
    print("=" * 40)
    print(f"Total artifacts:   {stats['total_artifacts']}")
    print(f"  Hot:             {stats['hot_count']}")
    print(f"  Warm:            {stats['warm_count']}")
    print(f"  Cold:            {stats['cold_count']}")
    print(f"Total original:    {stats['total_original_bytes']:,} bytes")
    if stats['total_compressed_bytes'] > 0:
        print(f"Total compressed:  {stats['total_compressed_bytes']:,} bytes")
        print(f"Overall ratio:     {stats['overall_ratio']}x")
        print(f"Space saved:       {stats['space_saved_bytes']:,} bytes")
    print(f"Indexed artifacts: {stats.get('indexed_artifacts', 0)}")
    print(f"Total keywords:    {stats.get('total_keywords', 0)}")


def cmd_recall(args: argparse.Namespace) -> None:
    """Recall a compressed artifact back to hot tier."""
    config = EngineConfig.load(args.config)
    engine = TieringEngine(config)

    target = Path(args.file).resolve()
    result = engine.recall(target)

    if result:
        print(f"Recalled: {result}")
    else:
        print(f"Not found or already hot: {target}")


def cmd_context(args: argparse.Namespace) -> None:
    """Get context-enhanced memory for AI assistant injection."""
    config = EngineConfig.load(args.config)
    engine = TieringEngine(config)

    # Ensure artifacts are indexed
    discovered = engine.scan()
    engine.register_all(discovered)

    query = getattr(args, "query", "") or ""
    budget = getattr(args, "budget", None)
    if budget is None or budget < 0:
        budget = 128000

    context = engine.get_context(query=query, budget_chars=budget)
    print(context)


def cmd_search(args: argparse.Namespace) -> None:
    """Search indexed memories by relevance."""
    config = EngineConfig.load(args.config)
    engine = TieringEngine(config)

    # Ensure artifacts are indexed
    discovered = engine.scan()
    engine.register_all(discovered)

    results = engine.search_memory(args.query, max_results=args.limit)

    if not results:
        print(f"No results for: {args.query}")
        return

    print(f"Results for: \"{args.query}\" ({len(results)} matches)\n")
    for i, entry in enumerate(results, 1):
        score = f"{entry.relevance_score:.2f}"
        print(f"  {i}. [{score}] {entry.to_context_line()}")
        if entry.keywords:
            print(f"     Keywords: {', '.join(entry.keywords[:8])}")


def cmd_encrypt_setup(_args: argparse.Namespace) -> None:
    """Guide user through encryption setup."""
    print("=" * 60)
    print("  PQKC Encryption Setup (Post-Quantum Key Encapsulation)")
    print("=" * 60)
    print()

    # Check age
    try:
        version = check_age_installed()
        print(f"[OK] age found: {version}")
        if "1.3" in version or any(f"1.{x}" in version for x in range(3, 20)):
            print("[OK] PQ hybrid support (ML-KEM-768) available")
        else:
            print("[WARN] age < 1.3.0 — no PQ support. Update: brew upgrade age")
    except AgeNotFoundError as e:
        print(f"[MISSING] {e}")
        return

    print()
    print("Step 1: Generate an age keypair")
    print("-" * 40)
    print("  age-keygen -o ~/.engram/key.txt")
    print()
    print("  This creates a private key (AGE-SECRET-KEY-...) and prints")
    print("  the public key (age1...). The public key goes in your config.")
    print("  The private key is what you MUST protect.")
    print()
    print("Step 2: Store the private key securely")
    print("-" * 40)
    print("  See: docs/KEY-STORAGE-GUIDE.md for vault options and risks.")
    print()
    print("Step 3: Update your config")
    print("-" * 40)
    print('  In ~/.engram/config.json, set:')
    print('  "encryption": {')
    print('    "enabled": true,')
    print('    "recipient_pubkey": "age1your-public-key-here",')
    print('    "identity_path": "~/.engram/key.txt"')
    print('  }')
    print()
    print("IMPORTANT: The identity_path should point to your key or to a")
    print("process that retrieves it from your vault. Never commit the")
    print("private key to version control.")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="engram",
        description="AI-agnostic tiered memory compression with optional PQKC encryption",
    )
    parser.add_argument(
        "--config", default=DEFAULT_CONFIG,
        help=f"Config file path (default: {DEFAULT_CONFIG})"
    )
    parser.add_argument("--verbose", "-v", action="store_true")

    sub = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = sub.add_parser("init", help="Initialize config (guided, interactive, or auto)")
    p_init.add_argument("--force", action="store_true",
                        help="Overwrite existing config")
    p_init.add_argument("--mode", choices=["guided", "interactive", "auto"],
                        default="guided",
                        help="Setup mode: guided (recommended), interactive (pick locations), auto (no prompts)")

    # scan
    sub.add_parser("scan", help="Scan for artifacts without tiering")

    # run
    p_run = sub.add_parser("run", help="Run tiering engine")
    p_run.add_argument("--dry-run", action="store_true",
                       help="Report what would happen without changes")

    # status
    sub.add_parser("status", help="Show tier distribution")

    # recall
    p_recall = sub.add_parser("recall", help="Recall artifact to hot tier")
    p_recall.add_argument("file", help="Original file path to recall")

    # context
    p_context = sub.add_parser("context", help="Get context-enhanced memory for AI injection")
    p_context.add_argument("--query", "-q", default="",
                           help="Task or query to bias relevance scoring")
    p_context.add_argument("--budget", "-b", type=int, default=128000,
                           help="Context budget in characters (default: 128000 ≈ 32K tokens)")

    # search
    p_search = sub.add_parser("search", help="Search indexed memories")
    p_search.add_argument("query", help="Search query")
    p_search.add_argument("--limit", "-l", type=int, default=10,
                          help="Max results (default: 10)")

    # encrypt-setup
    sub.add_parser("encrypt-setup", help="Guide through encryption setup")

    args = parser.parse_args()

    commands = {
        "init": cmd_init,
        "scan": cmd_scan,
        "run": cmd_run,
        "status": cmd_status,
        "recall": cmd_recall,
        "context": cmd_context,
        "search": cmd_search,
        "encrypt-setup": cmd_encrypt_setup,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
