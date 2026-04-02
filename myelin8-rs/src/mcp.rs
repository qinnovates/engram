use anyhow::Result;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::io::{self, AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::config::Config;
use crate::index::SearchIndex;
use crate::ingest::Artifact;
use crate::recall;
use crate::store::ParquetStore;

/// Run the MCP stdio server. Reads JSON-RPC from stdin, writes responses to stdout.
pub async fn serve(config: Config) -> Result<()> {
    let data_dir = config.data_dir();
    let index_dir = data_dir.join("index");
    let store_dir = data_dir.join("store");
    let hot_dir = data_dir.join("hot");

    // Ensure dirs exist
    std::fs::create_dir_all(&index_dir)?;
    std::fs::create_dir_all(&store_dir)?;
    std::fs::create_dir_all(&hot_dir)?;

    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let reader = BufReader::new(stdin);
    let mut lines = reader.lines();

    while let Some(line) = lines.next_line().await? {
        let line = line.trim().to_string();
        if line.is_empty() {
            continue;
        }

        let request: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": null,
                    "error": {
                        "code": -32700,
                        "message": format!("Parse error: {}", e)
                    }
                });
                write_response(&mut stdout, &err_resp).await?;
                continue;
            }
        };

        let id = request.get("id").cloned().unwrap_or(Value::Null);
        let method = request
            .get("method")
            .and_then(|m| m.as_str())
            .unwrap_or("");

        let response = match method {
            "initialize" => handle_initialize(&id),
            "notifications/initialized" => {
                // Client acknowledgment, no response needed
                continue;
            }
            "tools/list" => handle_tools_list(&id),
            "tools/call" => {
                let params = request.get("params").cloned().unwrap_or(json!({}));
                handle_tools_call(&id, &params, &config, &index_dir, &store_dir, &hot_dir)
            }
            _ => {
                json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": {
                        "code": -32601,
                        "message": format!("Method not found: {}", method)
                    }
                })
            }
        };

        write_response(&mut stdout, &response).await?;
    }

    Ok(())
}

async fn write_response(stdout: &mut io::Stdout, response: &Value) -> Result<()> {
    let mut out = serde_json::to_string(response)?;
    out.push('\n');
    stdout.write_all(out.as_bytes()).await?;
    stdout.flush().await?;
    Ok(())
}

fn handle_initialize(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "myelin8",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    })
}

fn handle_tools_list(id: &Value) -> Value {
    json!({
        "jsonrpc": "2.0",
        "id": id,
        "result": {
            "tools": [
                {
                    "name": "memory_search",
                    "description": "Search indexed memories by query. Returns ranked summaries with metadata.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "query": {
                                "type": "string",
                                "description": "Search query (full-text search across memory content and summaries)"
                            },
                            "after": {
                                "type": "string",
                                "description": "Only return results after this date (YYYY-MM-DD)"
                            },
                            "before": {
                                "type": "string",
                                "description": "Only return results before this date (YYYY-MM-DD)"
                            },
                            "limit": {
                                "type": "integer",
                                "description": "Maximum number of results to return (default: 10)"
                            }
                        },
                        "required": ["query"]
                    }
                },
                {
                    "name": "memory_recall",
                    "description": "Get full content of a specific artifact by ID. Returns content with integrity verification status.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "artifact_id": {
                                "type": "string",
                                "description": "The artifact ID or content hash prefix to recall"
                            }
                        },
                        "required": ["artifact_id"]
                    }
                },
                {
                    "name": "memory_status",
                    "description": "Get system status: artifact counts, index stats, registered sources.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {}
                    }
                },
                {
                    "name": "memory_ingest",
                    "description": "[DEPRECATED: use memory_ingest_governed] Ingest a note directly into memory without governance.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "The content to store"
                            },
                            "label": {
                                "type": "string",
                                "description": "Label/category for this memory"
                            }
                        },
                        "required": ["content", "label"]
                    }
                },
                {
                    "name": "memory_ingest_governed",
                    "description": "Write a fact or episode through the SIEMPLE-AI governance pipeline. Validates schema, applies write policy, checks for PII/conflicts, and logs to audit trail.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "content": {
                                "type": "string",
                                "description": "The content to store"
                            },
                            "label": {
                                "type": "string",
                                "description": "Type: preference, identity, goal, constraint, domain_fact, exclusion, episode, decision"
                            },
                            "key": {
                                "type": "string",
                                "description": "Machine-readable key for dedup (e.g., preferred_tone, current_project.focus)"
                            },
                            "confidence": {
                                "type": "number",
                                "description": "Confidence 0.0-1.0. Explicit=1.0, inferred ceiling=0.8"
                            },
                            "source": {
                                "type": "string",
                                "description": "Provenance: explicit, inferred, imported"
                            },
                            "namespace": {
                                "type": "string",
                                "description": "Scope: user, project, system (default: user)"
                            },
                            "sensitivity": {
                                "type": "string",
                                "description": "Access control: low, moderate, high (default: low)"
                            },
                            "tags": {
                                "type": "string",
                                "description": "JSON array of semantic tags"
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Current session ID for provenance"
                            },
                            "ttl_days": {
                                "type": "integer",
                                "description": "Days until expiry. Null=permanent. Inferred facts default to 180"
                            }
                        },
                        "required": ["content", "label", "confidence", "source"]
                    }
                },
                {
                    "name": "memory_context",
                    "description": "Get assembled context block for current session. Merges system defaults, user preferences, and relevant memories within token budget.",
                    "inputSchema": {
                        "type": "object",
                        "properties": {
                            "objective": {
                                "type": "string",
                                "description": "Current session objective for relevance scoring"
                            },
                            "budget_tokens": {
                                "type": "integer",
                                "description": "Max tokens for context block (default: 32000)"
                            },
                            "session_id": {
                                "type": "string",
                                "description": "Session ID for ephemeral state"
                            }
                        },
                        "required": ["objective"]
                    }
                }
            ]
        }
    })
}

fn handle_tools_call(
    id: &Value,
    params: &Value,
    config: &Config,
    index_dir: &std::path::Path,
    store_dir: &std::path::Path,
    hot_dir: &std::path::Path,
) -> Value {
    let tool_name = params
        .get("name")
        .and_then(|n| n.as_str())
        .unwrap_or("");
    let arguments = params.get("arguments").cloned().unwrap_or(json!({}));

    let result = match tool_name {
        "memory_search" => tool_memory_search(&arguments, index_dir),
        "memory_recall" => tool_memory_recall(&arguments, store_dir, hot_dir),
        "memory_status" => tool_memory_status(config, index_dir, store_dir, hot_dir),
        "memory_ingest" => tool_memory_ingest(&arguments, index_dir, hot_dir),
        "memory_ingest_governed" => tool_memory_ingest_governed(&arguments, index_dir, hot_dir),
        "memory_context" => tool_memory_context(&arguments),
        _ => Err(anyhow::anyhow!("Unknown tool: {}", tool_name)),
    };

    match result {
        Ok(content) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": content
                    }
                ]
            }
        }),
        Err(e) => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "content": [
                    {
                        "type": "text",
                        "text": format!("Error: {}", e)
                    }
                ],
                "isError": true
            }
        }),
    }
}

fn tool_memory_search(args: &Value, index_dir: &std::path::Path) -> Result<String> {
    let query = args
        .get("query")
        .and_then(|q| q.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: query"))?;

    let after = args.get("after").and_then(|a| a.as_str());
    let before = args.get("before").and_then(|b| b.as_str());
    let limit = args
        .get("limit")
        .and_then(|l| l.as_u64())
        .unwrap_or(10) as usize;

    let index = SearchIndex::open_or_create(index_dir)?;
    let results = index.search(query, after, before, limit)?;

    if results.is_empty() {
        return Ok("No results found.".to_string());
    }

    let output: Vec<Value> = results
        .iter()
        .map(|r| {
            json!({
                "artifact_id": r.artifact_id,
                "summary": r.summary,
                "significance": r.significance,
                "created_date": r.created_date,
                "source_label": r.source_label,
                "content_hash": &r.content_hash[..16.min(r.content_hash.len())],
                "score": r.score
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&output)?)
}

fn tool_memory_recall(
    args: &Value,
    store_dir: &std::path::Path,
    hot_dir: &std::path::Path,
) -> Result<String> {
    let artifact_id = args
        .get("artifact_id")
        .and_then(|a| a.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: artifact_id"))?;

    // Check hot/ first (plaintext JSON)
    let hot_path = hot_dir.join(format!("{}.json", artifact_id));
    if hot_path.exists() {
        let content = std::fs::read_to_string(&hot_path)?;
        let artifact: Value = serde_json::from_str(&content)?;
        return Ok(serde_json::to_string_pretty(&json!({
            "artifact_id": artifact_id,
            "content": artifact.get("content").and_then(|c| c.as_str()).unwrap_or(""),
            "integrity": "HOT — plaintext, not yet compacted",
            "source": "hot"
        }))?);
    }

    // Check Parquet store
    let store = ParquetStore::new(store_dir);
    let result = recall::recall_from_store(&store, artifact_id)?;

    match result {
        Some(recalled) => Ok(serde_json::to_string_pretty(&json!({
            "artifact_id": artifact_id,
            "content": recalled.content,
            "integrity": recalled.integrity_status,
            "content_hash": recalled.content_hash,
            "source": "parquet"
        }))?),
        None => Ok(format!("Artifact '{}' not found.", artifact_id)),
    }
}

fn tool_memory_status(
    config: &Config,
    index_dir: &std::path::Path,
    store_dir: &std::path::Path,
    hot_dir: &std::path::Path,
) -> Result<String> {
    // Hot count
    let hot_count = std::fs::read_dir(hot_dir)
        .map(|d| {
            d.filter_map(|e| e.ok())
                .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
                .count()
        })
        .unwrap_or(0);

    // Parquet stats
    let mut parquet_count = 0;
    let mut parquet_bytes = 0u64;
    if let Ok(entries) = std::fs::read_dir(store_dir) {
        for entry in entries.filter_map(|e| e.ok()) {
            if entry
                .path()
                .extension()
                .map_or(false, |ext| ext == "parquet")
            {
                parquet_count += 1;
                parquet_bytes += entry.metadata().map(|m| m.len()).unwrap_or(0);
            }
        }
    }

    // Index stats
    let index = SearchIndex::open_or_create(index_dir)?;
    let index_stats = index.stats()?;

    // Sources
    let sources: Vec<Value> = config
        .sources
        .iter()
        .map(|s| {
            json!({
                "label": s.label,
                "path": s.path,
                "pattern": s.pattern
            })
        })
        .collect();

    Ok(serde_json::to_string_pretty(&json!({
        "hot_artifacts": hot_count,
        "parquet_files": parquet_count,
        "parquet_bytes": parquet_bytes,
        "index_docs": index_stats.num_docs,
        "index_terms": index_stats.num_terms,
        "sources": sources
    }))?)
}

fn tool_memory_ingest(
    args: &Value,
    index_dir: &std::path::Path,
    hot_dir: &std::path::Path,
) -> Result<String> {
    let content = args
        .get("content")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: content"))?;

    let label = args
        .get("label")
        .and_then(|l| l.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: label"))?;

    let content_hash = hex::encode(Sha256::digest(content.as_bytes()));
    let artifact_id = format!(
        "{}-{}",
        chrono::Utc::now().format("%Y%m%d-%H%M%S"),
        &content_hash[..8]
    );

    // Build a summary: first 200 chars, single line
    let summary = content
        .chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_string();

    let semantic_fields = crate::semantic::extract(content);

    let artifact = Artifact {
        artifact_id: artifact_id.clone(),
        content: content.to_string(),
        content_hash: content_hash.clone(),
        summary: summary.clone(),
        keywords: vec![label.to_string()],
        significance: 0.5,
        source_label: label.to_string(),
        source_path: "mcp-ingest".to_string(),
        created_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        original_size: content.len() as u64,
        supersedes: None,
        semantic: semantic_fields,
        // SIEMPLE-AI governance defaults (ungoverned path)
        namespace: "user".to_string(),
        memory_type: label.to_string(),
        confidence: 0.5,
        source_provenance: "explicit".to_string(),
        sensitivity: "low".to_string(),
        tags: None,
        expires_at: None,
        session_id: None,
    };

    // Index in tantivy
    let mut index = SearchIndex::open_or_create(index_dir)?;
    index.add_artifact(&artifact)?;
    index.commit()?;

    // Write to hot/ as JSON
    let hot_path = hot_dir.join(format!("{}.json", artifact_id));
    let hot_json = serde_json::to_string_pretty(&artifact)?;
    std::fs::write(&hot_path, &hot_json)?;

    Ok(serde_json::to_string_pretty(&json!({
        "artifact_id": artifact_id,
        "content_hash": &content_hash[..16],
        "summary": summary,
        "status": "ingested"
    }))?)
}

/// Governed ingest: calls Python governance bridge via subprocess, then indexes if approved.
fn tool_memory_ingest_governed(
    args: &Value,
    index_dir: &std::path::Path,
    hot_dir: &std::path::Path,
) -> Result<String> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    use std::time::Duration;

    let content = args
        .get("content")
        .and_then(|c| c.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: content"))?;
    let label = args
        .get("label")
        .and_then(|l| l.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: label"))?;
    let confidence = args
        .get("confidence")
        .and_then(|c| c.as_f64())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: confidence"))?;
    let source = args
        .get("source")
        .and_then(|s| s.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: source"))?;

    let key = args.get("key").and_then(|k| k.as_str()).unwrap_or("");
    let namespace = args.get("namespace").and_then(|n| n.as_str()).unwrap_or("user");
    let sensitivity = args.get("sensitivity").and_then(|s| s.as_str()).unwrap_or("low");
    let tags = args.get("tags").and_then(|t| t.as_str());
    let session_id = args.get("session_id").and_then(|s| s.as_str());
    let ttl_days = args.get("ttl_days").and_then(|t| t.as_i64());

    // Build artifact JSON for governance
    let artifact_json = json!({
        "content": content,
        "label": label,
        "key": key,
        "confidence": confidence,
        "source": source,
        "namespace": namespace,
        "sensitivity": sensitivity,
        "tags": tags,
        "session_id": session_id,
        "ttl_days": ttl_days
    });

    // Call Python governance gate via subprocess (5s timeout)
    let mut child = Command::new("python3")
        .args(["-m", "src.governance", "validate-write"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("Failed to spawn governance process: {}", e))?;

    if let Some(stdin) = child.stdin.as_mut() {
        stdin.write_all(artifact_json.to_string().as_bytes())?;
    }

    let output = child
        .wait_with_output()
        .map_err(|e| anyhow::anyhow!("Governance process failed: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(serde_json::to_string_pretty(&json!({
            "status": "error",
            "reason": format!("Governance process failed: {}", stderr)
        }))?);
    }

    let governance_result: Value = serde_json::from_slice(&output.stdout)
        .map_err(|e| anyhow::anyhow!("Failed to parse governance result: {}", e))?;

    let status = governance_result
        .get("status")
        .and_then(|s| s.as_str())
        .unwrap_or("error");

    // If not approved, return the governance result directly
    if status != "ingested" {
        return Ok(serde_json::to_string_pretty(&governance_result)?);
    }

    // Governance approved — proceed with indexing
    let content_hash = hex::encode(Sha256::digest(content.as_bytes()));
    let artifact_id = governance_result
        .get("artifact_id")
        .and_then(|a| a.as_str())
        .unwrap_or(&format!(
            "{}-{}",
            chrono::Utc::now().format("%Y%m%d-%H%M%S"),
            &content_hash[..8]
        ))
        .to_string();

    let summary = content
        .chars()
        .take(200)
        .collect::<String>()
        .replace('\n', " ")
        .trim()
        .to_string();

    let semantic_fields = crate::semantic::extract(content);

    let expires_at = ttl_days.map(|days| {
        (chrono::Utc::now() + chrono::Duration::days(days))
            .format("%Y-%m-%dT%H:%M:%SZ")
            .to_string()
    });

    let artifact = Artifact {
        artifact_id: artifact_id.clone(),
        content: content.to_string(),
        content_hash: content_hash.clone(),
        summary: summary.clone(),
        keywords: vec![label.to_string()],
        significance: confidence as f32,
        source_label: if key.is_empty() { label.to_string() } else { key.to_string() },
        source_path: "mcp-governed".to_string(),
        created_date: chrono::Utc::now().format("%Y-%m-%d").to_string(),
        original_size: content.len() as u64,
        supersedes: None,
        semantic: semantic_fields,
        namespace: namespace.to_string(),
        memory_type: label.to_string(),
        confidence: confidence as f32,
        source_provenance: source.to_string(),
        sensitivity: sensitivity.to_string(),
        tags: tags.map(|t| t.to_string()),
        expires_at,
        session_id: session_id.map(|s| s.to_string()),
    };

    // Index in tantivy
    let mut index = SearchIndex::open_or_create(index_dir)?;
    index.add_artifact(&artifact)?;
    index.commit()?;

    // Write to hot/ as JSON
    let hot_path = hot_dir.join(format!("{}.json", artifact_id));
    let hot_json = serde_json::to_string_pretty(&artifact)?;
    std::fs::write(&hot_path, &hot_json)?;

    Ok(serde_json::to_string_pretty(&json!({
        "artifact_id": artifact_id,
        "content_hash": &content_hash[..16],
        "summary": summary,
        "status": "ingested",
        "governance": "approved",
        "confidence": confidence,
        "namespace": namespace,
        "memory_type": label
    }))?)
}

/// Context assembly: calls Python context_assembler via subprocess.
fn tool_memory_context(args: &Value) -> Result<String> {
    use std::process::{Command, Stdio};

    let objective = args
        .get("objective")
        .and_then(|o| o.as_str())
        .ok_or_else(|| anyhow::anyhow!("Missing required parameter: objective"))?;

    let budget = args
        .get("budget_tokens")
        .and_then(|b| b.as_i64())
        .unwrap_or(32000);

    let session_id = args
        .get("session_id")
        .and_then(|s| s.as_str())
        .unwrap_or("");

    let output = Command::new("python3")
        .args([
            "-m", "src.context_assembler",
            "--objective", objective,
            "--budget", &budget.to_string(),
            "--session-id", session_id,
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .map_err(|e| anyhow::anyhow!("Failed to spawn context assembler: {}", e))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Ok(serde_json::to_string_pretty(&json!({
            "status": "error",
            "reason": format!("Context assembly failed: {}", stderr)
        }))?);
    }

    // Return the assembled context directly
    let result = String::from_utf8_lossy(&output.stdout);
    Ok(result.to_string())
}
