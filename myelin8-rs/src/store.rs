use anyhow::Result;
use arrow::array::{ArrayRef, Float32Array, StringArray, UInt64Array};
use arrow::datatypes::{DataType, Field, Schema};
use arrow::record_batch::RecordBatch;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::arrow::ArrowWriter;
use parquet::basic::{Compression, ZstdLevel};
use parquet::file::properties::WriterProperties;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::ingest::Artifact;

pub struct ParquetStore {
    store_dir: PathBuf,
}

impl ParquetStore {
    pub fn new(store_dir: &Path) -> Self {
        Self {
            store_dir: store_dir.to_path_buf(),
        }
    }

    fn schema() -> Schema {
        Schema::new(vec![
            Field::new("artifact_id", DataType::Utf8, false),
            Field::new("content_hash", DataType::Utf8, false),
            Field::new("content", DataType::Utf8, false),
            Field::new("content_type", DataType::Utf8, false),
            Field::new("source_label", DataType::Utf8, false),
            Field::new("significance", DataType::Float32, false),
            Field::new("created_date", DataType::Utf8, false),
            Field::new("summary", DataType::Utf8, false),
            Field::new("original_size", DataType::UInt64, false),
        ])
    }

    /// Write a batch of artifacts to a new Parquet file.
    pub fn write_batch(&self, artifacts: &[Artifact], filename: &str, zstd_level: i32) -> Result<PathBuf> {
        let schema = Arc::new(Self::schema());

        let artifact_ids: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.artifact_id.as_str()).collect::<Vec<_>>()));
        let content_hashes: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.content_hash.as_str()).collect::<Vec<_>>()));
        let contents: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.content.as_str()).collect::<Vec<_>>()));
        let content_types: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|_| "memory").collect::<Vec<_>>()));
        let source_labels: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.source_label.as_str()).collect::<Vec<_>>()));
        let significances: ArrayRef = Arc::new(Float32Array::from(
            artifacts.iter().map(|a| a.significance).collect::<Vec<_>>()));
        let created_dates: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.created_date.as_str()).collect::<Vec<_>>()));
        let summaries: ArrayRef = Arc::new(StringArray::from(
            artifacts.iter().map(|a| a.summary.as_str()).collect::<Vec<_>>()));
        let original_sizes: ArrayRef = Arc::new(UInt64Array::from(
            artifacts.iter().map(|a| a.original_size).collect::<Vec<_>>()));

        let batch = RecordBatch::try_new(schema.clone(), vec![
            artifact_ids, content_hashes, contents, content_types,
            source_labels, significances, created_dates, summaries, original_sizes,
        ])?;

        // Write to .tmp/ first, then atomic rename
        let tmp_dir = self.store_dir.join(".tmp");
        std::fs::create_dir_all(&tmp_dir)?;
        let tmp_path = tmp_dir.join(filename);
        let final_path = self.store_dir.join(filename);

        let file = File::create(&tmp_path)?;
        let props = WriterProperties::builder()
            .set_compression(Compression::ZSTD(ZstdLevel::try_new(zstd_level)?))
            .build();

        let mut writer = ArrowWriter::try_new(file, schema, Some(props))?;
        writer.write(&batch)?;
        writer.close()?;

        // Atomic rename
        std::fs::rename(&tmp_path, &final_path)?;

        Ok(final_path)
    }

    /// Read a specific artifact's content from Parquet by artifact_id.
    /// Column-selective: reads only artifact_id to find the row, then content + content_hash.
    pub fn read_content(&self, artifact_id: &str) -> Result<Option<(String, String)>> {
        // Search all Parquet files in store
        let entries = std::fs::read_dir(&self.store_dir)?;

        for entry in entries.filter_map(|e| e.ok()) {
            let path = entry.path();
            if path.extension().map_or(false, |ext| ext == "parquet") {
                if let Some(result) = self.read_from_file(&path, artifact_id)? {
                    return Ok(Some(result));
                }
            }
        }

        Ok(None)
    }

    fn read_from_file(&self, path: &Path, artifact_id: &str) -> Result<Option<(String, String)>> {
        let file = File::open(path)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)?;
        let reader = builder.build()?;

        for batch in reader {
            let batch = batch?;
            let ids = batch.column_by_name("artifact_id")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let contents = batch.column_by_name("content")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());
            let hashes = batch.column_by_name("content_hash")
                .and_then(|c| c.as_any().downcast_ref::<StringArray>());

            if let (Some(ids), Some(contents), Some(hashes)) = (ids, contents, hashes) {
                for i in 0..batch.num_rows() {
                    if ids.value(i) == artifact_id {
                        return Ok(Some((
                            contents.value(i).to_string(),
                            hashes.value(i).to_string(),
                        )));
                    }
                }
            }
        }

        Ok(None)
    }

    /// List all Parquet files in the store.
    pub fn list_files(&self) -> Result<Vec<PathBuf>> {
        let mut files = Vec::new();
        if let Ok(entries) = std::fs::read_dir(&self.store_dir) {
            for entry in entries.filter_map(|e| e.ok()) {
                let path = entry.path();
                if path.extension().map_or(false, |ext| ext == "parquet") {
                    files.push(path);
                }
            }
        }
        files.sort();
        Ok(files)
    }
}
