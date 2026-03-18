"""
Interactive and guided setup for Engram.

Two modes:
  GUIDED:      Auto-detects installed AI assistants, shows what was found,
               user confirms with Y/n. Recommended defaults applied.
  INTERACTIVE: Shows every discovered location with file count + size,
               user picks which ones to include (y/n per location).

Both modes:
  1. Discover what AI assistants are installed
  2. Show what artifacts exist at each location
  3. Let user confirm or pick
  4. Configure tier thresholds (or accept defaults)
  5. Optionally set up encryption
  6. Write config to ~/.engram/config.json
"""

from __future__ import annotations

from pathlib import Path

from .config import EngineConfig, ScanTarget, TierPolicy
from .scanner import discover_installed_assistants


def _count_artifacts(target: ScanTarget) -> tuple[int, int]:
    """Count files and total bytes for a scan target. Returns (count, bytes)."""
    base = target.resolve()
    if not base.exists():
        return 0, 0

    pattern = f"**/{target.pattern}" if target.recursive else target.pattern
    count = 0
    total_bytes = 0
    skip = {".zst", ".age", ".tmp", ".parquet"}

    for match in base.glob(pattern):
        if match.is_file() and not match.is_symlink() and match.suffix not in skip:
            count += 1
            try:
                total_bytes += match.stat().st_size
            except OSError:
                pass

    return count, total_bytes


def _format_size(size_bytes: int) -> str:
    """Human-readable file size."""
    if size_bytes < 1024:
        return f"{size_bytes} B"
    elif size_bytes < 1024 * 1024:
        return f"{size_bytes / 1024:.1f} KB"
    elif size_bytes < 1024 * 1024 * 1024:
        return f"{size_bytes / (1024 * 1024):.1f} MB"
    else:
        return f"{size_bytes / (1024 * 1024 * 1024):.1f} GB"


def _input_yn(prompt: str, default: bool = True) -> bool:
    """Prompt user for yes/no, with a default."""
    suffix = " [Y/n] " if default else " [y/N] "
    try:
        response = input(prompt + suffix).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not response:
        return default
    return response in ("y", "yes")


def _input_choice(prompt: str, options: list[str], default: str = "") -> str:
    """Prompt user to pick from options."""
    try:
        response = input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    if not response:
        return default
    for opt in options:
        if opt.startswith(response):
            return opt
    return default


def run_guided_setup(config_path: Path) -> EngineConfig:
    """
    Guided setup: auto-detect, show summary, user confirms.

    Flow:
      1. Detect installed AI assistants
      2. Show summary (total files, total size)
      3. User confirms Y/n
      4. Show tier threshold defaults, user confirms
      5. Ask about encryption
      6. Save config
    """
    print()
    print("=" * 60)
    print("  Engram — Guided Setup")
    print("  Brain-inspired AI memory compression")
    print("=" * 60)
    print()

    # Step 1: Discover
    print("Scanning for AI assistant artifacts...")
    found = discover_installed_assistants()

    if not found:
        print("No AI assistant artifacts found on this system.")
        print("You can add custom scan targets manually in config.json.")
        config = EngineConfig()
        config.save(config_path)
        return config

    # Step 2: Show summary
    total_files = 0
    total_bytes = 0
    selected_targets: list[ScanTarget] = []

    for assistant, targets in found.items():
        assistant_files = 0
        assistant_bytes = 0
        for t in targets:
            count, size = _count_artifacts(t)
            assistant_files += count
            assistant_bytes += size
        if assistant_files > 0:
            print(f"  Found: {assistant.upper()}")
            print(f"    {assistant_files:,} artifacts, {_format_size(assistant_bytes)}")
            total_files += assistant_files
            total_bytes += assistant_bytes
            selected_targets.extend(targets)

    print()
    print(f"  Total: {total_files:,} artifacts, {_format_size(total_bytes)}")
    print()

    # Step 3: Confirm
    if not _input_yn("Archive all discovered locations?"):
        print("Switching to interactive mode...")
        return run_interactive_setup(config_path)

    # Step 4: Tier complexity
    print()
    print("How many storage tiers do you want?")
    print()
    print("  [2] Simple — Hot (recent) + Cold (old, compressed)")
    print("      Good for most users. Less complexity.")
    print()
    print("  [4] Full — Hot + Warm + Cold + Frozen")
    print("      Maximum compression. Each tier gets progressively")
    print("      more aggressive. Best disk savings. Recommended.")
    print()

    tier_choice = _input_choice("  Choose [2/4]: ", ["2", "4"], default="4")

    if tier_choice == "2":
        # Simple: skip warm, go straight to cold at 48h
        policy = TierPolicy(
            hot_to_warm_age_hours=0,
            hot_to_warm_idle_hours=0,
            warm_to_cold_age_hours=48,
            warm_to_cold_idle_hours=24,
            cold_to_frozen_age_hours=99999,  # effectively disabled
            cold_to_frozen_idle_hours=99999,
        )
        print("  Using 2-tier mode: Hot → Cold (48h old + 24h idle)")
    else:
        print()
        print("Tier thresholds (when memories move to deeper storage):")
        print("  Hot → Warm:    48 hours old + 24 hours idle")
        print("  Warm → Cold:   14 days old + 7 days idle")
        print("  Cold → Frozen: 90 days old + 30 days idle")
        print()

        if _input_yn("Use recommended thresholds?"):
            policy = TierPolicy()
        else:
            policy = _configure_thresholds()

    # Step 4b: Smart first-run analysis
    print()
    print("Analyzing file ages for initial tier placement...")
    age_analysis = _analyze_file_ages(selected_targets, policy)
    print(f"  Would stay hot (recent):  {age_analysis['hot']:,}")
    print(f"  → Warm (days old):        {age_analysis['warm']:,}")
    print(f"  → Cold (weeks old):       {age_analysis['cold']:,}")
    print(f"  → Frozen (months old):    {age_analysis['frozen']:,}")
    print()
    if age_analysis['warm'] + age_analysis['cold'] + age_analysis['frozen'] > 0:
        if _input_yn("Run initial tiering after setup to sort old files?"):
            run_initial_tier = True
        else:
            run_initial_tier = False
    else:
        run_initial_tier = False
        print("  All files are recent — nothing to tier yet.")

    # Step 5: Encryption
    print()
    encryption_enabled = _input_yn(
        "Enable post-quantum encryption (ML-KEM-768)? Requires `brew install age`",
        default=False,
    )

    encrypt_hot = False
    use_envelope = False
    if encryption_enabled:
        print()
        print("  Encryption enabled. Run `engram encrypt-setup` after init")
        print("  to generate keypairs and store in Keychain.")
        print()
        print("  By default, only warm/cold/frozen tiers are encrypted.")
        print("  Hot tier (active session files) stays plaintext for fast access.")
        print()
        print("  For the most secure setup, you can also encrypt hot storage.")
        print("  This encrypts everything, including your most recent sessions")
        print("  that haven't been compressed yet. Requires Touch ID on every read.")
        print()
        encrypt_hot = _input_yn(
            "  Enable most secure mode (encrypt all tiers including hot)?",
            default=False,
        )
        if encrypt_hot:
            print("    Most secure: all data encrypted at rest, all tiers.")
        else:
            print("    Standard: hot stays plaintext. Old sessions encrypted when tiered.")

        # Envelope mode
        print()
        print("  Encryption architecture:")
        print("    [simple]   One key for all tiers (easier setup)")
        print("    [envelope] Per-tier keypairs with per-artifact keys")
        print("               (most secure — compromise one tier, others safe)")
        print()
        envelope_choice = _input_choice(
            "  Choose [simple/envelope]: ", ["simple", "envelope"], default="simple"
        )
        use_envelope = envelope_choice == "envelope"
        if use_envelope:
            print("    Envelope mode: each tier gets its own keypair.")
            print("    Run `engram encrypt-setup` to generate per-tier keys.")

    # Step 6: Save
    from .config import EncryptionConfig
    enc_config = EncryptionConfig(
        enabled=encryption_enabled,
        encrypt_hot=encrypt_hot,
        envelope_mode=use_envelope if encryption_enabled else False,
    )
    config = EngineConfig(
        scan_targets=selected_targets,
        tier_policy=policy,
        encryption=enc_config,
    )
    config.save(config_path)

    print()
    print(f"Config saved: {config_path}")
    print(f"  {len(selected_targets)} scan targets")
    print(f"  {total_files:,} artifacts ready for tiering")

    # Step 7: Run initial tiering if user opted in
    if run_initial_tier:
        print()
        print("Running initial tiering...")
        from .engine import TieringEngine
        engine = TieringEngine(config)
        discovered = engine.scan()
        engine.register_all(discovered)
        actions = engine.evaluate_and_tier()
        if actions:
            warm_count = sum(1 for a in actions if a.to_tier == "warm")
            cold_count = sum(1 for a in actions if a.to_tier == "cold")
            total_saved = sum(a.original_size - a.new_size for a in actions if not a.dry_run)
            print(f"  Tiered {len(actions)} artifacts:")
            if warm_count:
                print(f"    → Warm: {warm_count}")
            if cold_count:
                print(f"    → Cold: {cold_count}")
            print(f"  Space saved: {_format_size(total_saved)}")
        else:
            print("  No transitions needed.")

    print()
    print("Next steps:")
    if not run_initial_tier:
        print(f"  engram run --dry-run   # Preview tier transitions")
        print(f"  engram run             # Execute tiering")
    print(f"  engram status          # Check tier distribution")

    return config


def run_interactive_setup(config_path: Path) -> EngineConfig:
    """
    Interactive setup: user picks which locations to archive.

    Shows each discovered location with file count and size,
    user selects y/n for each.
    """
    print()
    print("=" * 60)
    print("  Engram — Interactive Setup")
    print("  Pick which AI memory locations to archive")
    print("=" * 60)
    print()

    found = discover_installed_assistants()
    selected_targets: list[ScanTarget] = []
    total_files = 0
    total_bytes = 0

    for assistant, targets in found.items():
        print(f"\n── {assistant.upper()} ──")
        for t in targets:
            count, size = _count_artifacts(t)
            if count == 0:
                continue

            # Show details
            print(f"\n  {t.description}")
            print(f"  Path: {t.path}/{t.pattern}")
            print(f"  Files: {count:,}  |  Size: {_format_size(size)}")

            if _input_yn("  Include?"):
                selected_targets.append(t)
                total_files += count
                total_bytes += size
                print("    ✓ Added")
            else:
                print("    ✗ Skipped")

    if not selected_targets:
        print("\nNo locations selected. You can add targets manually in config.json.")
        config = EngineConfig()
        config.save(config_path)
        return config

    print(f"\n{'─' * 40}")
    print(f"Selected: {len(selected_targets)} locations")
    print(f"Total: {total_files:,} artifacts, {_format_size(total_bytes)}")

    # Thresholds
    print()
    if _input_yn("Use recommended tier thresholds?"):
        policy = TierPolicy()
    else:
        policy = _configure_thresholds()

    # Save
    config = EngineConfig(
        scan_targets=selected_targets,
        tier_policy=policy,
    )
    config.save(config_path)

    print(f"\nConfig saved: {config_path}")
    print(f"  engram run --dry-run   # Preview")
    print(f"  engram run             # Execute")

    return config


def _analyze_file_ages(targets: list[ScanTarget], policy: TierPolicy) -> dict:
    """Analyze file ages to predict tier distribution before running."""
    import time
    counts = {"hot": 0, "warm": 0, "cold": 0, "frozen": 0}
    skip = {".zst", ".age", ".tmp", ".parquet"}

    for t in targets:
        base = t.resolve()
        if not base.exists():
            continue
        pattern = f"**/{t.pattern}" if t.recursive else t.pattern
        for match in base.glob(pattern):
            if match.is_file() and not match.is_symlink() and match.suffix not in skip:
                try:
                    stat = match.stat()
                    age_h = (time.time() - stat.st_ctime) / 3600
                    idle_h = (time.time() - stat.st_atime) / 3600

                    if age_h >= policy.cold_to_frozen_age_hours and idle_h >= policy.cold_to_frozen_idle_hours:
                        counts["frozen"] += 1
                    elif age_h >= policy.warm_to_cold_age_hours and idle_h >= policy.warm_to_cold_idle_hours:
                        counts["cold"] += 1
                    elif age_h >= policy.hot_to_warm_age_hours and idle_h >= policy.hot_to_warm_idle_hours:
                        counts["warm"] += 1
                    else:
                        counts["hot"] += 1
                except OSError:
                    counts["hot"] += 1

    return counts


def _configure_thresholds() -> TierPolicy:
    """Let user configure tier transition thresholds."""
    print()
    print("Configure tier thresholds (press Enter for default):")

    def _get_int(prompt: str, default: int, max_val: int = 87600) -> int:
        """Get integer input with bounds (max default: 87600 hours = 10 years)."""
        try:
            val = input(f"  {prompt} [{default}]: ").strip()
            if not val:
                return default
            parsed = int(val)
            if parsed < 0:
                print(f"    Must be >= 0. Using default: {default}")
                return default
            if parsed > max_val:
                print(f"    Max is {max_val}. Using default: {default}")
                return default
            return parsed
        except (ValueError, EOFError, KeyboardInterrupt):
            return default

    hot_warm_age = _get_int("Hot → Warm: hours old", 48)
    hot_warm_idle = _get_int("Hot → Warm: hours idle", 24)
    warm_cold_age = _get_int("Warm → Cold: hours old", 336)
    warm_cold_idle = _get_int("Warm → Cold: hours idle", 168)
    cold_frozen_age = _get_int("Cold → Frozen: hours old", 2160)
    cold_frozen_idle = _get_int("Cold → Frozen: hours idle", 720)

    return TierPolicy(
        hot_to_warm_age_hours=hot_warm_age,
        hot_to_warm_idle_hours=hot_warm_idle,
        warm_to_cold_age_hours=warm_cold_age,
        warm_to_cold_idle_hours=warm_cold_idle,
        cold_to_frozen_age_hours=cold_frozen_age,
        cold_to_frozen_idle_hours=cold_frozen_idle,
    )
