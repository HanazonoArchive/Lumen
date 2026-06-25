use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How to scan a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ScanMode {
    /// Read header bytes only — for files < 16MB
    Quick,
    /// Divide file into N segments, scan parallel
    Segmented(u8),
}

/// One identified chunk inside a file
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResult {
    /// Human-readable type, e.g. "ZIP archive", "JPEG image"
    pub file_type: String,
    /// MIME type if known
    pub mime: Option<String>,
    /// Common file extension
    pub extension: Option<String>,
    /// Compression algorithm if detected
    pub compression: Option<String>,
    /// Byte offset where this signature was found
    pub offset: u64,
    /// How sure we are (0.0–1.0)
    pub confidence: f32,
    /// True if container has password protection
    pub has_password: bool,
    /// Hex bytes of leading header before magic (if any)
    pub header_hex: Option<String>,
    /// Name of inner file (from temp extract)
    pub inner_name: Option<String>,
    /// Embedded files inside a container
    pub children: Vec<ScanResult>,
}

impl ScanResult {
    pub fn unknown() -> Self {
        Self {
            file_type: "Unknown".into(),
            mime: None,
            extension: None,
            compression: None,
            offset: 0,
            confidence: 0.0,
            has_password: false,
            header_hex: None,
            inner_name: None,
            children: vec![],
        }
    }
}

/// A signature from the DB (before pattern matching)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signature {
    pub id: i64,
    pub name: String,
    pub mime: Option<String>,
    pub extension: Option<String>,
    pub patterns: Vec<MagicPattern>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MagicPattern {
    pub offset: i64,
    pub hex_bytes: String,
    pub mask: Option<String>,
    pub endianness: String,
}

/// Request payload for a scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanRequest {
    pub path: PathBuf,
    pub mode: ScanMode,
}

/// Report of one segment in a segmented scan
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SegmentReport {
    pub index: usize,
    pub offset: u64,
    pub size: u64,
    pub result: ScanResult,
}

/// Full scan response — one result or multiple segments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanResponse {
    pub total_size: u64,
    pub segments: Vec<SegmentReport>,
    pub combined: ScanResult,
}
