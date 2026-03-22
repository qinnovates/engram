// Search is handled entirely by index.rs (tantivy).
// This module exists for future enhancements:
// - Query expansion / synonym support
// - Semantic search (embedding-based, optional)
// - RRF fusion when multiple search methods are enabled
// - Time-decay boosting

// For now, all search goes through SearchIndex::search() in index.rs.
// Parquet is NEVER accessed during search — only during recall.
