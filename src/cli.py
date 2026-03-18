#!/usr/bin/env python3
"""
CLI for engram-engine.

Usage:
  engram run [--config PATH] [--dry-run] [--verbose]
  engram status [--config PATH]
  engram recall <file> [--config PATH]
  engram init [--config PATH]
  engram scan [--config PATH]
  engram reindex [--config PATH]
  engram verify [--config PATH]
  engram encrypt-setup
"""

from __future__ import annotations

import argparse
import time
from pathlib import Path

from .config import EngineConfig
from .engine import TieringEngine
from .encryption import EncryptionError
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

    # Download/update embedding model (only time network is allowed)
    try:
        from .embeddings import download_model
        print("Downloading/verifying embedding model (one-time network call)...")
        if download_model():
            print("Embedding model ready (future operations will be fully offline)")
        else:
            print("Embedding model not available (sentence-transformers not installed)")
            print("Keyword search will work. Install for semantic search: pip install sentence-transformers")
    except Exception as e:
        print(f"Embedding model setup skipped: {e}")


def cmd_update_model(args: argparse.Namespace) -> None:
    """Download or update the embedding model (network call)."""
    try:
        from .embeddings import download_model
        print("Checking for embedding model updates...")
        if download_model():
            print("Embedding model updated and verified.")
        else:
            print("sentence-transformers not installed. Install: pip install sentence-transformers")
    except Exception as e:
        print(f"Model update failed: {e}")


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


def cmd_reindex(args: argparse.Namespace) -> None:
    """Rebuild the semantic index from scratch."""
    config = EngineConfig.load(args.config)
    config.verbose = args.verbose
    engine = TieringEngine(config)

    # Delete the existing semantic index
    index_path = engine.index.index_path
    if index_path.exists():
        index_path.unlink()
        print(f"Deleted existing index: {index_path}")
    else:
        print("No existing index found.")

    # Reload the index (now empty) and rebuild
    from .context import SemanticIndex
    engine.index = SemanticIndex(config.resolve_metadata_dir())

    discovered = engine.scan()
    engine.register_all(discovered)

    entries = engine.index.all_entries()
    print(f"Reindexed {len(entries)} artifacts.")


def cmd_verify(args: argparse.Namespace) -> None:
    """Verify SHA-256 integrity of all tracked artifacts."""
    from .metadata import compute_sha256

    config = EngineConfig.load(args.config)
    engine = TieringEngine(config)

    artifacts = engine.metadata.all_artifacts()
    total = len(artifacts)
    passed = 0
    failed = 0
    skipped = 0
    failures: list[tuple[str, str, str]] = []

    for meta in artifacts:
        if not meta.sha256:
            skipped += 1
            continue

        path = Path(meta.path)
        if not path.exists():
            failed += 1
            failures.append((meta.path, meta.sha256[:16], "file missing"))
            continue

        current_hash = compute_sha256(path)
        if current_hash == meta.sha256:
            passed += 1
        else:
            failed += 1
            failures.append((meta.path, meta.sha256[:16], f"got {current_hash[:16]}"))

    print("Integrity Verification")
    print("=" * 40)
    print(f"Total checked:  {total}")
    print(f"  Passed:       {passed}")
    print(f"  Failed:       {failed}")
    print(f"  Skipped:      {skipped}  (no hash stored)")

    if failures:
        print(f"\nFailed artifacts:")
        for path, expected, actual in failures:
            print(f"  {path}")
            print(f"    expected: {expected}...  {actual}")


def cmd_lock(args: argparse.Namespace) -> None:
    """Encrypt the index bundle (lock at session end)."""
    config = EngineConfig.load(args.config)
    if not config.encryption.enabled:
        print("Encryption is not enabled. Nothing to lock.")
        return
    engine = TieringEngine(config)
    engine.lock_index()
    print("Index locked. All index files encrypted.")
    print("Run `engram unlock` or any engram command to decrypt (Touch ID).")


def cmd_unlock(args: argparse.Namespace) -> None:
    """Decrypt the index bundle (unlock at session start)."""
    config = EngineConfig.load(args.config)
    if not config.encryption.enabled:
        print("Encryption is not enabled. Nothing to unlock.")
        return
    # TieringEngine.__init__ auto-unlocks if locked
    engine = TieringEngine(config)
    print("Index unlocked. Ready for search, context, and tiering.")


def cmd_encrypt_setup(_args: argparse.Namespace) -> None:
    """Guide user through encryption setup."""
    print("=" * 60)
    print("  PQKC Encryption Setup (Post-Quantum Key Encapsulation)")
    print("=" * 60)
    print()

    # Check sidecar
    try:
        from .vault import VaultClient
        client = VaultClient()
        client.close()
        print("[OK] engram-vault sidecar found")
        print("[OK] NIST-approved: ML-KEM-768 + X25519 + AES-256-GCM")
    except EncryptionError as e:
        print(f"[MISSING] {e}")
        return

    print()
    print("Step 1: Generate keypair for each tier")
    print("-" * 40)
    print("  The sidecar generates ML-KEM-768 + X25519 hybrid keypairs")
    print("  and stores private keys directly in your OS credential vault.")
    print()

    for tier in ["warm", "cold", "frozen"]:
        try:
            client = VaultClient()
            pubkey = client.keygen(tier)
            client.close()
            print(f"  [OK] {tier}: keypair generated, private key in Keychain")
            print(f"       Public key: {pubkey[:40]}...")
        except EncryptionError as e:
            msg = str(e)
            if "already exists" in msg:
                print(f"  [OK] {tier}: keypair already exists")
            else:
                print(f"  [SKIP] {tier}: {msg}")

    print()
    print("Step 2: Update your config")
    print("-" * 40)
    print('  In ~/.engram/config.json, set:')
    print('  "encryption": {')
    print('    "enabled": true,')
    print('    "envelope_mode": true')
    print('  }')
    print()
    print("  Private keys are stored in your OS credential vault:")
    print("    macOS: Keychain (Touch ID protected)")
    print("    Windows: Credential Manager (DPAPI)")
    print("    Linux: libsecret / GNOME Keyring")
    print()
    print("  Keys NEVER exist as files on disk. Python NEVER sees them.")
    print("  See docs/KEY-STORAGE-GUIDE.md for Vault/KMS alternatives.")


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

    # reindex
    sub.add_parser("reindex", help="Rebuild semantic index from scratch")

    # verify
    sub.add_parser("verify", help="Verify SHA-256 integrity of tracked artifacts")

    # update-model
    sub.add_parser("update-model", help="Download or update embedding model (only command that uses network)")

    # encrypt-setup
    sub.add_parser("lock", help="Encrypt index bundle (session end)")
    sub.add_parser("unlock", help="Decrypt index bundle (session start)")
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
        "reindex": cmd_reindex,
        "verify": cmd_verify,
        "update-model": cmd_update_model,
        "lock": cmd_lock,
        "unlock": cmd_unlock,
        "encrypt-setup": cmd_encrypt_setup,
    }

    commands[args.command](args)


if __name__ == "__main__":
    main()
