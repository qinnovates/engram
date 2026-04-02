# Precedence Resolution

> How layered configuration merges into a single context at inference time. Deterministic precedence is the difference between a production system and a prototype that works until it doesn't.

---

## The Merge Algorithm

```
resolved_config = {}

for layer in [system, app, environment, user, session]:
    for key, value in layer.items():
        if key in resolved_config:
            existing = resolved_config[key]
            if existing.metadata.overridable == False:
                # Hard constraint — never overridden
                continue
            if existing.metadata.layer_precedence >= layer.precedence:
                # This shouldn't happen if layers are ordered correctly
                raise PrecedenceError(f"{key} being set by lower-precedence layer")
        resolved_config[key] = LayerValue(value=value, source_layer=layer.name)
```

Last writer wins — but only for `overridable: true` fields. Fields marked `overridable: false` at Layer 1 are immutable for the entire session.

---

## Field Mutability Classification

Every field in the configuration schema is classified as one of:

| Class | Meaning | Example |
|-------|---------|---------|
| `immutable` | Set at Layer 1, never overridden | `safety.pii_redaction` |
| `overridable` | Can be overridden by higher-precedence layers | `verbosity`, `output_format` |
| `additive` | Each layer adds to the set (no replacement) | `interests[]`, `exclusions[]` |
| `session_only` | Only set at Layer 5, cleared at session end | `active_files`, `objective` |

Example annotation in schema:

```yaml
fields:
  pii_redaction:
    type: boolean
    default: true
    mutability: immutable          # Layer 1 sets this forever
    layer: system

  verbosity:
    type: enum
    values: [low, medium, high]
    default: medium
    mutability: overridable        # User can set this in Layer 4
    layer: system

  interests:
    type: array
    items: string
    mutability: additive           # Layers 2-4 can add to this list
    layer: user
    merge_strategy: union          # All layers' lists combined

  active_files:
    type: array
    items: string
    mutability: session_only       # Layer 5 only, expires with session
    layer: session
```

---

## Worked Example

Given this layer stack:

**Layer 1 (system/defaults.yaml):**
```yaml
verbosity: medium
output_format: markdown
safety.pii_redaction: true     # immutable
tool_policy.code_exec: sandbox_only
```

**Layer 2 (apps/soc/default.yaml):**
```yaml
verbosity: low                 # Override Layer 1
output_format: structured_triage  # Override Layer 1
ask_clarifying_questions: never
```

**Layer 3 (environments/prod.yaml):**
```yaml
model: claude-opus-4-6
retrieval.max_retrieved_facts: 5
observability.prompt_logging: metadata_only
```

**Layer 4 (users/user_123/preferences.yaml):**
```yaml
verbosity: high                # Override Layers 1+2
output_length: concise
tone: direct
```

**Resolved config:**
```yaml
verbosity: high                # Layer 4 wins (highest precedence for overridable field)
output_format: structured_triage   # Layer 2 wins (Layer 4 didn't override)
ask_clarifying_questions: never    # Layer 2 wins (no override)
safety.pii_redaction: true         # Layer 1, immutable — cannot be overridden
tool_policy.code_exec: sandbox_only  # Layer 1 wins (no override)
model: claude-opus-4-6             # Layer 3 wins
retrieval.max_retrieved_facts: 5   # Layer 3 wins
observability.prompt_logging: metadata_only  # Layer 3 wins
output_length: concise             # Layer 4 wins
tone: direct                       # Layer 4 wins
```

Note: `verbosity: high` from Layer 4 overrides `verbosity: low` from Layer 2. The user's explicit preference wins over the app default. This is correct behavior — it mirrors how `users/<user>/local/` in Splunk overrides `apps/<app>/local/`.

---

## Conflict Types

### Type 1: Clean Override (expected)

```
Layer 1: verbosity = medium
Layer 4: verbosity = high
→ Result: verbosity = high (Layer 4 wins)
```

No conflict. This is the intended merge behavior.

### Type 2: Immutability Violation (block)

```
Layer 1: safety.pii_redaction = true (immutable)
Layer 4: safety.pii_redaction = false  ← User tries to disable safety
→ Result: safety.pii_redaction = true (immutable field, Layer 4 override rejected)
→ Action: Log warning to audit trail, continue with immutable value
```

Log entry:
```jsonl
{"ts":"2026-04-01T10:00:00Z","event":"immutability_violation","field":"safety.pii_redaction","attempted_value":false,"source_layer":"user","user_id":"user_123","action":"override_rejected"}
```

### Type 3: Additive Merge

```
Layer 2 (app): interests = ["cybersecurity"]
Layer 4 (user): interests = ["neuroethics", "BCI"]
→ Result: interests = ["cybersecurity", "neuroethics", "BCI"]  (union)
```

Both layers contribute. Neither overrides the other.

### Type 4: Schema Conflict (needs review)

```
Semantic memory fact_A: preferred_response_length = "concise"   (confidence 0.9)
Semantic memory fact_B: preferred_response_length = "thorough"  (confidence 0.7)
→ Result: Cannot auto-resolve — human review required
→ Action: Use higher-confidence fact (fact_A), flag conflict for review
```

Log entry:
```jsonl
{"ts":"2026-04-01T10:05:00Z","event":"memory_conflict","key":"preferred_response_length","fact_a_id":"fact_001","fact_a_confidence":0.9,"fact_b_id":"fact_002","fact_b_confidence":0.7,"resolution":"fact_a_used_pending_review","flagged":true}
```

---

## Precedence Table

| Layer | Name | Precedence | Beats |
|-------|------|-----------|-------|
| 1 | System/Base | Lowest (for overridable fields), Absolute (for immutable) | Nothing |
| 2 | App/Domain | Low | Layer 1 overridable fields |
| 3 | Environment | Medium | Layers 1-2 overridable fields |
| 4 | User/Tenant | High | Layers 1-3 overridable fields |
| 5 | Session/Runtime | Highest (for session fields) | Layers 1-4 session-only fields |

**Immutable fields are outside this table.** They are set once at Layer 1 and that's the value for the lifetime of the deployment. Not the session — the deployment. Changing an immutable field requires a system-level config change with a full audit trail.

---

## Testing Precedence Resolution

Before deploying a new config layer, test the resolution:

```python
# pseudocode
def test_precedence_resolution():
    stack = load_layer_stack(
        system="templates/system/defaults.yaml",
        app="templates/apps/soc/default.yaml",
        environment="templates/environments/prod.yaml",
        user="templates/users/example-user/preferences.yaml"
    )

    resolved = resolve(stack)

    # Safety constraints are immutable
    assert resolved["safety.pii_redaction"] == True
    assert resolved["safety.pii_redaction"].source_layer == "system"

    # User preferences win for overridable fields
    assert resolved["verbosity"] == "high"
    assert resolved["verbosity"].source_layer == "user"

    # Additive fields are unioned
    assert "cybersecurity" in resolved["interests"]
    assert "neuroethics" in resolved["interests"]
```

Run this test on every config layer change. A merge regression is the AI equivalent of a bad Splunk `transforms.conf` that silently drops events — it's hard to detect and the blast radius is wide.
