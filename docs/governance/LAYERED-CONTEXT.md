# Architecture: Layered Context Orchestration

> This document is the canonical reference for the five-layer AI configuration architecture. Read this before touching any templates or schemas.

---

## The SIEM Analogy

If you've operated Splunk at scale, you know the configuration hierarchy:

```
$SPLUNK_HOME/system/default/     ← Splunk ships these, read-only
$SPLUNK_HOME/system/local/       ← Global overrides, highest non-app precedence
$SPLUNK_HOME/etc/apps/<app>/default/   ← App ships these
$SPLUNK_HOME/etc/apps/<app>/local/     ← App local overrides
$SPLUNK_HOME/etc/users/<user>/         ← User-level overrides
```

Precedence is deterministic. `system/local` beats `app/default`. `app/local` beats `app/default`. Every `.conf` merge is documented. You can trace why a setting has a particular value by following the precedence chain.

**Production AI systems need this exact architecture.** The current state of the industry is equivalent to every Splunk deployment keeping all configuration in one giant `inputs.conf` and calling it done.

---

## The Five Layers

### Layer 1: Base System (global cluster defaults)

**Splunk equivalent:** `$SPLUNK_HOME/system/default/`

This layer defines:
- Core assistant identity and persona
- Safety boundaries (immutable — no downstream layer can override)
- Tool policies (what tools are available, under what constraints)
- Organization-wide constraints
- Response style defaults

```yaml
# templates/system/defaults.yaml
system:
  persona: "security_research_assistant"
  verbosity: "medium"
  citation_policy: "required_for_external_facts"
  tool_policy:
    web_search: "allowed"
    code_exec: "sandbox_only"
    file_write: "requires_confirmation"
  safety:
    pii_redaction: true
    high_risk_actions_require_confirmation: true
    safety_overridable_by_downstream: false   # ← This is the hard constraint
```

**Critical design rule:** Safety fields marked `overridable: false` are immutable. A user preference of `"skip all confirmations"` cannot suppress `high_risk_actions_require_confirmation`. Just as a Splunk app cannot grant itself `admin` capabilities it wasn't shipped with, a user tenant cannot override Layer 1 safety boundaries.

### Layer 2: Domain / App (use-case defaults)

**Splunk equivalent:** `$SPLUNK_HOME/etc/apps/<app>/default/`

This layer customizes behavior for a specific use case: a legal research assistant, a SOC copilot, a code review agent. Different apps ship with different defaults.

```yaml
# templates/apps/research/default.yaml
app:
  name: "research_copilot"
  defaults:
    summarize_style: "analytical"
    ask_clarifying_questions: "minimal"
    output_format: "markdown"
    citation_style: "inline"
    reasoning_depth: "thorough"
    hedge_uncertain_claims: true
```

A SOC copilot app would override different fields:

```yaml
# templates/apps/soc/default.yaml
app:
  name: "soc_copilot"
  defaults:
    response_urgency: "high"
    output_format: "structured_triage"
    ask_clarifying_questions: "never"   # Alert triage needs fast answers
    confidence_thresholds:
      escalate_above: 0.8
      dismiss_below: 0.2
```

### Layer 3: Environment (dev/stage/prod)

**Splunk equivalent:** Deployment server app with environment-specific `server.conf`.

This layer controls:
- Model selection
- Retrieval source configuration
- Latency budgets and timeout policies
- Logging verbosity
- Feature flags and experiment enrollment

```yaml
# templates/environments/prod.yaml
environment:
  name: "prod"
  model: "claude-opus-4-6"
  retrieval:
    vector_index: "research-prod-index"
    reranker: true
    max_retrieved_facts: 5
    max_retrieved_episodes: 3
  limits:
    max_context_tokens: 100000
    response_timeout_ms: 12000
  observability:
    prompt_logging: "metadata_only"   # PII concern in prod
    trace_id_injection: true
```

```yaml
# templates/environments/dev.yaml
environment:
  name: "dev"
  model: "claude-haiku-4-5-20251001"  # Cheaper for iteration
  retrieval:
    vector_index: "research-dev-index"
    reranker: false
    max_retrieved_facts: 10           # More liberal for debugging
  limits:
    max_context_tokens: 50000
    response_timeout_ms: 30000        # Longer timeout for debugging
  observability:
    prompt_logging: "full"            # Full logging in dev
    trace_id_injection: true
```

The same codebase deploys identically to all environments — the environment layer is the only diff.

### Layer 4: User / Tenant (durable preferences)

**Splunk equivalent:** `$SPLUNK_HOME/etc/users/<user>/` and multi-tenant `system/local` overrides.

This layer stores **durable, explicitly established preferences** — not transient conversational history.

The distinction is critical and mirrors the Splunk problem of operators accidentally making `local` changes that they didn't intend to be permanent.

**What goes in user/tenant layer:**
- Tone and communication preferences
- Output format preferences
- Recurring interests and domains
- Background context the agent should always carry
- Exclusions ("never suggest framework X")

**What does NOT go here:**
- Transient moods or temporary preferences expressed in one session
- Unverified inferences about the user's preferences
- Sensitive data
- Session-specific working state

```yaml
# templates/users/example-user/preferences.yaml
user:
  id: "user_123"
  preferences:
    tone: "direct"
    output_length: "concise"
    tables: "avoid"
    code_comments: "minimal"
  long_term_memory:
    interests:
      - "neuroethics"
      - "cybersecurity"
      - "systems architecture"
    recurring_goals:
      - "build BCI security framework"
    exclusions:
      - "avoid suggesting PHP"
      - "never recommend jQuery for new projects"
```

### Layer 5: Session / Runtime (ephemeral working state)

**Splunk equivalent:** KV Store lookups and search-time field extractions — they exist for the duration of the search and are not persisted.

This layer is destroyed aggressively. It contains:
- Current task objective
- Active file handles and context references
- Tool outputs from earlier in the session
- Working scratchpad state
- Temporary constraints ("for this task only, don't summarize")

```json
{
  "session_id": "sess_abc123",
  "objective": "Audit auth middleware for IDOR vulnerabilities",
  "active_files": ["src/middleware/auth.ts", "src/routes/user.ts"],
  "scratchpad_refs": ["scratchpad_0", "scratchpad_1"],
  "created_at": "2026-04-01T10:00:00Z",
  "expires_at": "2026-04-01T18:00:00Z"
}
```

**Hard rule:** Session state never writes back to Layers 1-4 without explicit user confirmation and an audit log entry. The model cannot unilaterally promote ephemeral state to durable memory.

---

## Context Assembly at Inference Time

When a request arrives, the context pipeline assembles the prompt by merging layers in order:

```
1. Load Layer 1 (base system) — always present, immutable fields locked
2. Load Layer 2 (app/domain) — override Layer 1 safe fields
3. Load Layer 3 (environment) — override Layers 1-2 safe fields
4. Load Layer 4 (user/tenant) — override Layers 1-3 safe fields
5. Load Layer 5 (session state) — append working context
6. Retrieve semantic memory — top-N relevant facts (NOT full injection)
7. Retrieve episodic memory — top-M recent relevant episodes
8. Inject turn history — windowed, not unlimited
9. Inject current turn
```

**Retrieval over prompt stuffing.** You do not inject the full semantic memory store into every prompt. You retrieve the top 5 relevant facts and the top 3 recent episodes. This is the difference between a well-tuned Splunk search with `index=` and `sourcetype=` constraints versus `index=*`.

See [`docs/precedence-resolution.md`](precedence-resolution.md) for the merge algorithm.

---

## Where the Splunk Analogy Breaks

The SIEM analogy is useful but not perfect. Here's where it diverges:

### AI memory is probabilistic, not deterministic

A Splunk `[stanza]` either has a value or it doesn't. AI semantic memory has **confidence scores**. A fact with confidence 0.3 should be weighted differently than one at 0.95, and probably shouldn't be injected at all.

Implication: every fact in the semantic memory store needs a `confidence` field. Retrieval must filter or weight by confidence. You cannot treat a model's inferred belief about a user the same as an explicitly stated preference.

### AI memory needs contradiction detection

`inputs.conf` doesn't contradict itself — if two stanzas set the same key, the higher-precedence layer wins and the value is single. AI memory can contain `fact_A: "user prefers concise responses"` and `fact_B: "user wants thorough analysis"` at the same time, with no automatic resolution.

Implication: the memory write pipeline needs contradiction detection. Before writing a new fact, check for conflicts with existing facts in the same namespace. Flag conflicts for review rather than silently overwriting.

### Compaction and summarization have no SIEM equivalent

Splunk indexes don't compress themselves intelligently — you configure retention and rollover. AI episodic memory requires active **compaction**: older episodes get summarized, detail is lost, importance scores decay. This is closer to a knowledge management system with LRU eviction than a SIEM index.

### The correct extended analogy

> Splunk config management (for layered precedence and audit trails)
> \+ Splunk KV Store (for structured lookup data with TTLs)
> \+ Splunk knowledge objects (for governance of who can create/modify shared config)
> \+ A retrieval-augmented search index (for relevance-ranked fact retrieval)
> \+ Active garbage collection (for episodic memory compaction)

That's the full system. Build each component separately. **Never merge them into one blob.**

---

## Security Architecture

This is the most important section.

### CLAUDE.md is advisory, not enforced

CLAUDE.md (and its equivalent in any AI system) is text in the context window. The model reads it. The model tries to follow it. But:

- At turn 50 of a complex session, attention to early-context instructions degrades
- A sufficiently complex user request can inadvertently crowd out constraint text
- Prompt injection in retrieved content can conflict with instructions
- There is no enforcement mechanism — it's a strong suggestion

**PostToolUse hooks are the actual security boundary.**

When a model writes code, a PostToolUse hook can run semgrep, bandit, or a custom linter against the output *before* it's accepted. This runs outside the model's context window. It cannot be "forgotten." It cannot be overridden by a clever prompt. It is not advisory — it is a hard gate.

Architecture implication: design your security constraints in two places:

1. **CLAUDE.md (advisory):** Imperative framing, recency-positioned (put prohibitions at the bottom of the file for transformer recency attention weighting). Example: `NEVER use shell=True in subprocess calls.`

2. **PostToolUse hooks (enforced):** Semgrep rule that catches `shell=True` and blocks the tool call response until fixed. The model sees the hook output and must fix the violation before the session continues.

See [`claude-code/hooks/post-tool-use.sh`](../claude-code/hooks/post-tool-use.sh) for the reference implementation.

---

## Audit Architecture

Every config change and every memory write must produce an audit log entry. This is non-negotiable.

```jsonl
{"ts":"2026-04-01T10:00:00Z","event":"memory_write","layer":"user","user_id":"user_123","key":"preferences.tone","old_value":"balanced","new_value":"direct","source":"explicit_user_statement","session_id":"sess_abc123"}
{"ts":"2026-04-01T10:05:00Z","event":"config_override","layer":"environment","env":"prod","key":"retrieval.max_retrieved_facts","old_value":10,"new_value":5,"changed_by":"deploy_pipeline","commit":"a1b2c3d"}
```

See [`audit/`](../audit/) for the full format specification and example logs.
