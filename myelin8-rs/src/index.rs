use anyhow::Result;
use std::path::Path;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, QueryParser, RangeQuery};
use tantivy::schema::*;
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy};

use crate::ingest::Artifact;
use crate::semantic;

pub struct SearchResult {
    pub artifact_id: String,
    pub content_hash: String,
    pub summary: String,
    pub significance: f64,
    pub created_date: String,
    pub source_label: String,
    pub score: f32,
    /// True if this artifact has been superseded by a newer one.
    pub superseded: bool,
    /// The artifact_id that supersedes this one, if any.
    pub superseded_by: Option<String>,
}

pub struct IndexStats {
    pub num_docs: u64,
    pub num_terms: u64,
}

pub struct SearchIndex {
    index: Index,
    reader: IndexReader,
    writer: Option<IndexWriter>,
    schema: Schema,
    // Field handles
    f_artifact_id: Field,
    f_content_hash: Field,
    f_body: Field,
    f_summary: Field,
    f_significance: Field,
    f_created_date: Field,
    f_source_label: Field,
    f_supersedes: Field,
    // Semantic KV fields
    f_technology: Field,
    f_category: Field,
    f_action: Field,
    f_domain: Field,
    f_polarity: Field,
    f_entities: Field,
    // SIEMPLE-AI governance fields (v2.0.0)
    f_namespace: Field,
    f_memory_type: Field,
    f_confidence: Field,
    f_source_provenance: Field,
    f_sensitivity: Field,
    f_tags: Field,
    f_expires_at: Field,
}

impl SearchIndex {
    pub fn open_or_create(index_dir: &Path) -> Result<Self> {
        std::fs::create_dir_all(index_dir)?;

        let mut schema_builder = Schema::builder();

        // Stored + indexed fields
        let f_artifact_id = schema_builder.add_text_field("artifact_id", STRING | STORED);
        let f_content_hash = schema_builder.add_text_field("content_hash", STRING | STORED);
        let f_body = schema_builder.add_text_field("body", TEXT); // ALL tokens, not stored (saves space)
        let f_summary = schema_builder.add_text_field("summary", TEXT | STORED);
        let f_significance = schema_builder.add_f64_field("significance", INDEXED | STORED | FAST);
        let f_created_date = schema_builder.add_text_field("created_date", STRING | STORED | FAST);
        let f_source_label = schema_builder.add_text_field("source_label", STRING | STORED);
        let f_supersedes = schema_builder.add_text_field("supersedes", STRING | STORED);

        // Semantic KV fields: TEXT for full-text search, STORED for retrieval
        let f_technology = schema_builder.add_text_field("technology", TEXT | STORED);
        let f_category = schema_builder.add_text_field("category", TEXT | STORED);
        let f_action = schema_builder.add_text_field("action", TEXT | STORED);
        let f_domain = schema_builder.add_text_field("domain", TEXT | STORED);
        let f_polarity = schema_builder.add_text_field("polarity", STRING | STORED);
        let f_entities = schema_builder.add_text_field("entities", TEXT | STORED);

        // SIEMPLE-AI governance fields (v2.0.0)
        let f_namespace = schema_builder.add_text_field("namespace", STRING | STORED);
        let f_memory_type = schema_builder.add_text_field("memory_type", STRING | STORED);
        let f_confidence = schema_builder.add_f64_field("confidence", STORED | FAST);
        let f_source_provenance = schema_builder.add_text_field("source_provenance", STRING | STORED);
        let f_sensitivity = schema_builder.add_text_field("sensitivity", STRING | STORED);
        let f_tags = schema_builder.add_text_field("tags", TEXT | STORED);
        let f_expires_at = schema_builder.add_text_field("expires_at", STRING | STORED);

        let schema = schema_builder.build();

        let index = if index_dir.join("meta.json").exists() {
            Index::open_in_dir(index_dir)?
        } else {
            Index::create_in_dir(index_dir, schema.clone())?
        };

        let reader = index
            .reader_builder()
            .reload_policy(ReloadPolicy::OnCommitWithDelay)
            .try_into()?;

        Ok(Self {
            index,
            reader,
            writer: None,
            schema,
            f_artifact_id,
            f_content_hash,
            f_body,
            f_summary,
            f_significance,
            f_created_date,
            f_source_label,
            f_supersedes,
            f_technology,
            f_category,
            f_action,
            f_domain,
            f_polarity,
            f_entities,
            f_namespace,
            f_memory_type,
            f_confidence,
            f_source_provenance,
            f_sensitivity,
            f_tags,
            f_expires_at,
        })
    }

    fn ensure_writer(&mut self) -> Result<&mut IndexWriter> {
        if self.writer.is_none() {
            // 50MB heap for writer
            self.writer = Some(self.index.writer(50_000_000)?);
        }
        Ok(self.writer.as_mut().unwrap())
    }

    pub fn add_artifact(&mut self, artifact: &Artifact) -> Result<()> {
        // Copy field handles before mutable borrow
        let f_aid = self.f_artifact_id;
        let f_hash = self.f_content_hash;
        let f_body = self.f_body;
        let f_summary = self.f_summary;
        let f_sig = self.f_significance;
        let f_date = self.f_created_date;
        let f_label = self.f_source_label;
        let f_sup = self.f_supersedes;
        let f_tech = self.f_technology;
        let f_cat = self.f_category;
        let f_act = self.f_action;
        let f_dom = self.f_domain;
        let f_pol = self.f_polarity;
        let f_ent = self.f_entities;
        // SIEMPLE-AI governance fields
        let f_ns = self.f_namespace;
        let f_mt = self.f_memory_type;
        let f_conf = self.f_confidence;
        let f_sp = self.f_source_provenance;
        let f_sens = self.f_sensitivity;
        let f_tags = self.f_tags;
        let f_exp = self.f_expires_at;

        let supersedes_val = artifact.supersedes.clone().unwrap_or_default();
        let tags_val = artifact.tags.clone().unwrap_or_default();
        let expires_val = artifact.expires_at.clone().unwrap_or_default();
        let sem = &artifact.semantic;
        let writer = self.ensure_writer()?;

        writer.add_document(doc!(
            f_aid => artifact.artifact_id.clone(),
            f_hash => artifact.content_hash.clone(),
            f_body => artifact.content.clone(),
            f_summary => artifact.summary.clone(),
            f_sig => artifact.significance as f64,
            f_date => artifact.created_date.clone(),
            f_label => artifact.source_label.clone(),
            f_sup => supersedes_val,
            f_tech => semantic::join_field(&sem.technology),
            f_cat => semantic::join_field(&sem.category),
            f_act => semantic::join_field(&sem.action),
            f_dom => semantic::join_field(&sem.domain),
            f_pol => sem.polarity.clone(),
            f_ent => semantic::join_field(&sem.entities),
            // SIEMPLE-AI governance fields
            f_ns => artifact.namespace.clone(),
            f_mt => artifact.memory_type.clone(),
            f_conf => artifact.confidence as f64,
            f_sp => artifact.source_provenance.clone(),
            f_sens => artifact.sensitivity.clone(),
            f_tags => tags_val,
            f_exp => expires_val,
        ))?;

        Ok(())
    }

    pub fn commit(&mut self) -> Result<()> {
        if let Some(writer) = &mut self.writer {
            writer.commit()?;
            self.reader.reload()?;
        }
        Ok(())
    }

    pub fn search(
        &self,
        query_str: &str,
        _after: Option<&str>,
        _before: Option<&str>,
        limit: usize,
    ) -> Result<Vec<SearchResult>> {
        let searcher = self.reader.searcher();

        // Search across body, summary, and all semantic fields
        let query_parser = QueryParser::for_index(
            &self.index,
            vec![
                self.f_body,
                self.f_summary,
                self.f_technology,
                self.f_category,
                self.f_action,
                self.f_domain,
                self.f_entities,
            ],
        );

        // Expand query terms using synonym map before searching
        let expanded = semantic::expand_query(query_str);
        let query = query_parser.parse_query(&expanded)?;

        // TODO: add date range filtering with BooleanQuery when after/before provided

        let top_docs = searcher.search(&query, &TopDocs::with_limit(limit))?;

        let mut results = Vec::new();
        for (score, doc_address) in top_docs {
            let doc: TantivyDocument = searcher.doc(doc_address)?;

            let artifact_id = doc.get_first(self.f_artifact_id)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let content_hash = doc.get_first(self.f_content_hash)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let summary = doc.get_first(self.f_summary)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let significance = doc.get_first(self.f_significance)
                .and_then(|v| v.as_f64())
                .unwrap_or(0.0);
            let created_date = doc.get_first(self.f_created_date)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();
            let source_label = doc.get_first(self.f_source_label)
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string();

            results.push(SearchResult {
                artifact_id,
                content_hash,
                summary,
                significance,
                created_date,
                source_label,
                score,
                superseded: false,
                superseded_by: None,
            });
        }

        Ok(results)
    }

    pub fn stats(&self) -> Result<IndexStats> {
        let searcher = self.reader.searcher();
        let num_docs = searcher.num_docs();

        // Approximate term count from segment readers
        let mut num_terms = 0u64;
        for segment_reader in searcher.segment_readers() {
            let inv_index = segment_reader.inverted_index(self.f_body)?;
            num_terms += inv_index.terms().num_terms() as u64;
        }

        Ok(IndexStats { num_docs, num_terms })
    }
}
