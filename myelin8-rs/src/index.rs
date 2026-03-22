use anyhow::Result;
use std::path::Path;
use tantivy::collector::TopDocs;
use tantivy::query::{BooleanQuery, Occur, QueryParser, RangeQuery};
use tantivy::schema::*;
use tantivy::{doc, Index, IndexReader, IndexWriter, ReloadPolicy};

use crate::ingest::Artifact;

pub struct SearchResult {
    pub artifact_id: String,
    pub content_hash: String,
    pub summary: String,
    pub significance: f64,
    pub created_date: String,
    pub source_label: String,
    pub score: f32,
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

        let writer = self.ensure_writer()?;

        writer.add_document(doc!(
            f_aid => artifact.artifact_id.clone(),
            f_hash => artifact.content_hash.clone(),
            f_body => artifact.content.clone(),
            f_summary => artifact.summary.clone(),
            f_sig => artifact.significance as f64,
            f_date => artifact.created_date.clone(),
            f_label => artifact.source_label.clone(),
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
        let query_parser = QueryParser::for_index(&self.index, vec![self.f_body, self.f_summary]);
        let query = query_parser.parse_query(query_str)?;

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
