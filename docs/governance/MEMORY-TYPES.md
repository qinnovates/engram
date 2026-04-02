# Memory Architecture

> AI memory is not a flat file. It's a KV store with confidence scores, TTLs, relevance ranking, and contradiction detection — crossed with a knowledge object governance system. Build it that way.

---

## The Four Memory Types

### 1. Semantic Memory

**What it stores:** Long-lived facts about the world, about the user, about the project — things that remain true across sessions.

**Analogy:** Splunk KV Store lookups. Structured, indexed, retrievable by key or by similarity search.

**Key properties:**
- Confidence scores on every fact (0.0–1.0)
- Explicit provenance: was this stated explicitly or inferred?
- TTL: semantic facts can expire (a user's current project focus changes)
- Sensitivity classification: some facts are high-sensitivity and get restricted retrieval

**Schema:** See [`../schemas/fact.schema.yaml`](../schemas/fact.schema.yaml)

**Retrieval pattern:** Don't inject all semantic memory. Retrieve **top-N relevant facts** using similarity search against the current turn embedding. In production, N=5 is a reasonable starting point. More than 10 rarely improves responses and always costs context budget.

**Write policy:**
- Explicit user statement → confidence 1.0, source: explicit
- Inferred from strong repeated pattern → confidence 0.6-0.8, source: inferred
- Single-session observation → usually don't write at all (use episodic memory instead)

```jsonl
{"id":"fact_001","namespace":"user","type":"preference","key":"output_format","value":"markdown","confidence":1.0,"source":"explicit","created_at":"2026-01-15T09:00:00Z","updated_at":"2026-03-20T14:00:00Z","expires_at":null,"sensitivity":"low"}
{"id":"fact_002","namespace":"user","type":"goal","key":"current_focus","value":"BCI security framework","confidence":0.9,"source":"explicit","created_at":"2026-02-01T10:00:00Z","updated_at":"2026-04-01T08:00:00Z","expires_at":"2026-07-01T00:00:00Z","sensitivity":"low"}
{"id":"fact_003","namespace":"user","type":"preference","key":"prefers_tables","value":false,"confidence":0.85,"source":"inferred","created_at":"2026-03-10T11:00:00Z","updated_at":"2026-03-10T11:00:00Z","expires_at":null,"sensitivity":"low"}
```

---

### 2. Episodic Memory

**What it stores:** Records of past interactions — what happened, when, and what was significant about it.

**Analogy:** Splunk event index. Time-ordered, searchable, with importance scores that decay over time.

**Key properties:**
- Summary of what happened (not a verbatim transcript)
- Entity tags: what people, projects, concepts were involved
- Importance score: decays with time unless the episode is referenced again
- Source conversation ID: can trace back to the original session

**Schema:** See [`../schemas/episode.schema.yaml`](../schemas/episode.schema.yaml)

**Retrieval pattern:** Top-M recent episodes relevant to the current task. M=3 is typical. Prioritize by recency-weighted importance (recent high-importance episodes rank above old low-importance ones).

**Compaction:** Episodic memory requires active management. Episodes older than a configurable threshold get summarized into compressed weekly or monthly digests. Detail is lost; the summary is retained. This is not analogous to Splunk index retention — it's more like Splunk summary indexing where you pre-aggregate before the raw data ages out.

```jsonl
{"id":"ep_001","summary":"Debugged JWT validation bug where aud claim was not being checked. Fixed in src/middleware/auth.ts. User noted this was the second time this pattern caused a production incident.","entities":["JWT","auth middleware","production incident"],"timestamp":"2026-03-25T16:00:00Z","importance":0.85,"source_conversation_id":"conv_xyz789"}
{"id":"ep_002","summary":"Designed initial schema for QIF NISS scoring. User confirmed confidence float and sensitivity enum are correct fields. Noted DSM-5-TR mapping should be advisory, not diagnostic.","entities":["QIF","NISS","schema design","neuroethics"],"timestamp":"2026-03-28T10:00:00Z","importance":0.9,"source_conversation_id":"conv_abc456"}
```

---

### 3. Working Memory

**What it stores:** Short-lived active state for the current task. Expires aggressively.

**Analogy:** Splunk search job KV store — exists for the duration of the search, gone when the job ends.

**Key properties:**
- Session-scoped: destroyed when the session ends (or sooner)
- No persistence between sessions
- Can reference open file handles, active tool outputs, scratchpad state
- High write frequency, no audit overhead needed

**Schema:** See [`../schemas/session.schema.yaml`](../schemas/session.schema.yaml)

**Critical rule:** Working memory does not write back to semantic or episodic memory without explicit confirmation. The model noticing something during a session does not constitute a durable memory. A user explicitly saying "remember this" is the trigger.

**What belongs here:**
- Current task objective
- Files opened in this session
- Tool outputs from earlier turns
- Intermediate reasoning state

**What does NOT belong here:**
- Anything the user should expect to persist across sessions
- User preferences (those go in Layer 4)
- Security constraints (those go in hooks)

---

### 4. Procedural Memory

**What it stores:** Playbooks for repeated workflows. How to do things, not what to know.

**Analogy:** Splunk saved searches and alert actions. Reusable procedures that encode accumulated knowledge about how to accomplish recurring tasks.

**Examples:**
- "When the user asks to review a PR, run these steps in this order"
- "When a new paper is cited, verify the DOI via Crossref, then check semantic scholar, then add to the registry"
- "When scaffolding a new Swift module, follow this build order"

**Storage:** YAML or Markdown files. Not in a KV store — procedural memory is read-only at inference time and modified deliberately, not auto-updated.

**This is what CLAUDE.md commands/ are.** Custom slash commands that encode workflow procedures. See [`../claude-code/commands/`](../claude-code/commands/).

---

## Memory Write Policy

Not everything the model learns belongs in durable memory. This is the most important governance decision in the architecture.

See [`../schemas/memory-write-policy.yaml`](../schemas/memory-write-policy.yaml) for the full specification.

### Write: Yes

| Trigger | Memory Type | Example |
|---------|-------------|---------|
| User explicitly states a preference | Semantic | "I prefer concise responses" |
| User explicitly states a stable fact | Semantic | "I'm building a BCI security framework" |
| Recurring pattern confirmed over 3+ sessions | Semantic (inferred, confidence ≤ 0.8) | User always asks for markdown output |
| Significant task completion | Episodic | "Finished auth module refactor" |
| Important decision made | Episodic | "Chose PostgreSQL over MongoDB" |
| User says "remember this" | Semantic or Episodic | Direct instruction |

### Write: No

| Trigger | Why Not |
|---------|---------|
| User expressed a temporary preference ("just for this task") | Use working memory only |
| Model inferred a preference from a single interaction | Too noisy; wait for pattern confirmation |
| Sensitive PII (email, phone, location) | Privacy — store nothing identifiable |
| Temporary emotional state ("I'm frustrated with this bug") | Moods don't belong in semantic memory |
| Speculative inference ("user probably likes X") | Confidence too low; would pollute retrieval |
| Security constraints | Go in hooks, not memory |

---

## Retrieval Architecture

### The Wrong Way
```
# Don't do this
full_prompt = system_prompt + ALL_SEMANTIC_MEMORY + ALL_EPISODES + user_message
```

This is the equivalent of `index=*` in Splunk. Everything gets loaded, relevant or not. Context window fills with noise. Signal-to-noise ratio degrades.

### The Right Way
```
# Context assembly pipeline
1. Embed current turn
2. Similarity search: top 5 semantic facts with confidence > 0.5
3. Recency-importance search: top 3 episodes from last 30 days
4. Merge with layered config (Layers 1-4)
5. Append session working memory (Layer 5)
6. Append windowed turn history (last N turns, not unlimited)
7. Append current turn
```

### Retrieval Budgets (production defaults)

| Memory Type | Retrieved Count | Filter |
|-------------|----------------|--------|
| Semantic facts | 5 | confidence > 0.5, sensitivity ≤ current clearance |
| Episodic events | 3 | importance-weighted, last 30 days preferred |
| Procedural memory | 1-2 | only if current task matches a known procedure |
| Turn history | 10-20 turns | always windowed, never unlimited |

These are starting points, not absolutes. Tune based on your domain and context budget.

---

## Contradiction Detection

Before writing a new semantic fact, the write pipeline must check for conflicts:

```
1. Query existing facts in same namespace with same key
2. Query existing facts in same namespace with semantically similar keys
3. If conflict found:
   a. Flag for review (don't silently overwrite)
   b. Log conflict to audit trail
   c. Present both to user if interactive: "I have a conflicting record: [old] vs [new]. Which is correct?"
4. If no conflict: write with provenance metadata
```

Example conflict: `fact_A: output_length = concise` vs `fact_B: output_length = thorough`. Same key, conflicting values. This cannot be resolved by last-writer-wins — it needs human review.

This is the feature Splunk's conf merge doesn't need because stanzas are deterministic. AI memory has to earn determinism through explicit conflict resolution.
