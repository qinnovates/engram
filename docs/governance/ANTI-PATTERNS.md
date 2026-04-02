# Anti-Patterns: What Not to Do and Why

> Every pattern here was a production mistake. Most are also mistakes you've seen in SIEM deployments — the same underlying failure mode, different tooling.

---

## Anti-Pattern 1: The God Memory File

**What it looks like:**
```
memory.md (2,847 lines)
├── User preferences (lines 1-50)
├── Project notes (lines 51-400)
├── Code snippets to remember (lines 401-800)
├── Past conversation summaries (lines 801-1600)
├── Architecture decisions (lines 1601-2000)
├── Security rules (lines 2001-2200)
└── Random accumulated context (lines 2201-2847)
```

**Why it fails:**
- Lines 1-50 get near-zero attention by turn 30 of a complex session
- Security rules on line 2100 are not security controls — they're suggestions buried in noise
- No TTLs: everything accumulates forever
- No provenance: you can't tell what was explicitly stated vs. inferred
- Retrieval is impossible — everything gets injected every time

**SIEM equivalent:** Keeping all your `transforms.conf`, `props.conf`, and `inputs.conf` stanzas in a single file called `everything.conf`. Works until it doesn't. Fails silently when something conflicts.

**The fix:** Separate stores (semantic, episodic, working, procedural). Structured schemas with provenance and TTLs. Retrieval-based injection, not full-dump injection.

---

## Anti-Pattern 2: Model Freely Rewriting Durable Memory

**What it looks like:**
```
User: "Actually, I prefer verbose responses"
Model: [updates semantic_memory.json: output_length = "verbose"]
     → Next session: model is verbose
     → User: "Why are you being so verbose? I said concise last month"
```

**Why it fails:**
- The model over-indexing on one session's preference overwrites a stable preference from 50 sessions
- The user has no visibility into what changed
- No audit trail: you can't tell what overwrote what or when
- Confidence from a single statement is not enough to overwrite a pattern

**SIEM equivalent:** A search-time automatic rule that silently modifies your lookup table based on a single event match. Even with `outputlookup`, you'd want a confirmation gate for destructive writes.

**The fix:** Memory write policy with explicit confirmation gates. Every durable write goes to the audit log. Confidence scoring prevents single-session observations from overriding stable patterns. User can review and approve proposed memory updates.

```yaml
# memory-write-policy.yaml
durable_write_rules:
  explicit_statement:
    auto_write: true
    confidence: 1.0
    audit_required: true
  inferred_single_session:
    auto_write: false          # Require confirmation
    pending_review: true
  inferred_repeated_pattern:
    sessions_required: 3
    auto_write: true
    confidence: 0.75
    audit_required: true
```

---

## Anti-Pattern 3: Storing Unverified Inferences as Facts

**What it looks like:**
```json
{"key": "user_expertise_level", "value": "expert", "source": "inferred", "confidence": 0.95}
```

The model inferred this from a few technical questions in one session and wrote it with high confidence.

**Why it fails:**
- Confidence 0.95 from a few data points is overfit
- The "fact" now shapes every future response, even in domains where the user is not an expert
- The user never confirmed this — it was a model inference, not a stated preference
- "Expert" is not a well-defined domain anyway

**SIEM equivalent:** Auto-populating a lookup table with categorizations derived from pattern matching on raw events, then using that lookup as ground truth without manual review. The lookup becomes the fact; the inference quality is forgotten.

**The fix:**
- Inferred facts get a confidence ceiling of 0.8
- Inferred facts without domain scope are prohibited (`expert_at_what` is required)
- Inferred facts older than 90 days without explicit confirmation decay
- Explicit statements from users override inferences for the same key

---

## Anti-Pattern 4: No TTL on Ephemeral State

**What it looks like:**
```json
{
  "current_task": "refactoring auth module",
  "active_branch": "feature/auth-refactor",
  "working_notes": "JWT validation needs aud check",
  "created_at": "2026-01-15T10:00:00Z"
  // No expires_at field
}
```

Six months later, the model is still injecting stale "working notes" about a branch that was merged and deleted.

**Why it fails:**
- Session state is not session-scoped in practice — it persists indefinitely
- Stale context actively misleads the model ("you're working on the auth refactor" — no, that shipped months ago)
- Storage bloat: working state accumulates across sessions

**SIEM equivalent:** A `kvstore` collection for session data that never gets purged. Every search job that ran in the last two years is still in the collection, and your correlation searches are matching against stale entries.

**The fix:** All working memory fields have mandatory `expires_at`. Default TTL: end of session. Maximum TTL: 72 hours for anything crossing session boundaries. Cleanup job runs hourly.

---

## Anti-Pattern 5: Mixing Instructions and User Facts in One Store

**What it looks like:**
```json
{"key": "use_async_await", "value": "always", "type": "fact"}
{"key": "never_use_shell_true", "value": "true", "type": "fact"}
{"key": "user_preferred_tone", "value": "direct", "type": "fact"}
{"key": "jwt_aud_must_be_verified", "value": "true", "type": "fact"}
```

Security constraints and user preferences in the same store, with the same data type, the same retrieval path.

**Why it fails:**
- Security constraints retrieved by relevance might not be retrieved when they're most critical
- A user who updates their "facts" might inadvertently modify a security constraint if the interface doesn't distinguish between them
- No separation means no different governance: facts about user preferences need different TTL, audit, and write policies than security rules

**SIEM equivalent:** Mixing your alert definitions with your lookup table data. Both live in the Splunk KV store, but they have completely different governance requirements — one is operational config, the other is enrichment data.

**The fix:** Strict type separation.
- `type: instruction` → comes from CLAUDE.md, hooks, or system config. Never from user store. Read-only at inference time.
- `type: preference` → comes from explicit user statements. Writable with audit.
- `type: domain_fact` → stable facts about the world. Writable with provenance.
- `type: constraint` → security/safety. System layer only. Immutable.

---

## Anti-Pattern 6: Hidden Prompt Fragments with Unclear Precedence

**What it looks like:**
- System prompt (set by platform)
- CLAUDE.md (set by repo)
- User memory file (auto-loaded by Claude Code)
- Tool description strings (set by MCP server developer)
- Retrieved documents (set by whoever wrote those docs)

All of these inject text into the context window. None of them are aware of each other. When they conflict, there's no defined winner.

**Why it fails:**
- An MCP server's tool description might say "when in doubt, always call this tool" — overriding your "only call tools when necessary" rule
- Retrieved documents might contain instructions directed at the model — prompt injection
- No audit trail of what's in the context window at inference time

**SIEM equivalent:** Multiple `inputs.conf` files from different apps all defining the same sourcetype with different settings. The merge is implicit, the winner is non-obvious, and debugging requires reading all configs simultaneously.

**The fix:** Context assembly logging. At inference time, log the full assembled context (or a hash of it) to the audit trail. For production systems, implement a context policy engine that validates the assembled context before inference.

---

## Anti-Pattern 7: Injecting All Past Chats Every Turn

**What it looks like:**
```python
# "Smart" context injection
def build_prompt(user_message, conversation_history, all_past_sessions):
    return system_prompt + all_past_sessions + conversation_history + user_message
```

**Why it fails:**
- Context window fills immediately
- 99% of past session content is irrelevant to the current task
- Recent context gets compressed by the model to make room
- Latency spikes, costs spike, quality degrades

**SIEM equivalent:** `index=* earliest=-365d@d` on every single search. Technically correct (all the data is there), practically ruinous (you've just loaded a year of events to answer a question that only needs today's data).

**The fix:** Retrieval-augmented injection. Embed the current turn, retrieve the top-K relevant episodes and facts, inject only those. Window the conversation history to the last N turns. See [`docs/memory-architecture.md`](memory-architecture.md) for retrieval budgets.

---

## Anti-Pattern 8: CLAUDE.md as the Security Boundary

This deserves its own section because it's the most consequential mistake.

**What it looks like:**
```markdown
# CLAUDE.md
...
NEVER hardcode secrets.
NEVER use shell=True.
NEVER skip input validation.
```

The team considers these "enforced" because they're in CLAUDE.md.

**Why it fails:**
- CLAUDE.md is text in the context window. It cannot enforce anything.
- A complex enough task can cause attention to drift from early-context instructions
- An attacker with access to the prompt (directly or via injected content) can construct inputs that effectively override the rule
- There is no enforcement mechanism

**The fix:** PostToolUse hooks. When the model writes code:
1. The hook runs before the code is accepted
2. Semgrep scans for `shell=True`, hardcoded credential patterns, missing input validation
3. If violation found: hook returns non-zero exit code, tool call fails, model sees the violation and must fix it
4. This runs outside the model's context window and cannot be "forgotten" or "overridden" by a prompt

The model still reads CLAUDE.md and it still helps. But CLAUDE.md is the first line of defense (advisory), and the hook is the actual enforcement. Defense in depth. The SIEM analogy: your detection rules catch what they catch, but network-layer controls catch what they catch regardless of whether the detection fired.
