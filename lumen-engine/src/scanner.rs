// ponytail: single-pass buffered reader, no full load
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Minimum printable ASCII ratio to consider a file "plain text"
const TEXT_RATIO_THRESHOLD: f32 = 0.85;

use crate::db;
use crate::types::*;

/// Common offsets to check for magic bytes
const SCAN_OFFSETS: &[u64] = &[0, 4, 8, 16, 32, 64, 128, 256, 512, 1024];

/// Maximum bytes to read for quick scan
const QUICK_SCAN_SIZE: u64 = 8192;

/// Overlap between segments in bytes
const SEGMENT_OVERLAP: u64 = 4096;

/// Threshold for segmented scan
const SEGMENT_THRESHOLD: u64 = 16 * 1024 * 1024; // 16 MB

/// Default segment count for files >= threshold
fn segment_count(file_size: u64) -> u8 {
    if file_size < 512 * 1024 * 1024 {
        4
    } else if file_size < 4 * 1024 * 1024 * 1024 {
        8
    } else {
        16
    }
}

/// Read hex bytes from a file at given offset and length
pub fn read_hex_at(path: &Path, offset: u64, len: usize) -> Result<String, std::io::Error> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(hex::encode(&buf).to_uppercase())
}

/// Match magic bytes at a specific offset against the DB
pub fn match_at_offset(
    conn: &rusqlite::Connection,
    path: &Path,
    offset: u64,
    scan_len: usize,
) -> Result<Vec<Signature>, String> {
    let hex_str = read_hex_at(path, offset, scan_len).map_err(|e| e.to_string())?;

    // Try full match first (longest pattern that fits)
    let mut matched = db::match_signatures(conn, &hex_str, offset)
        .map_err(|e| e.to_string())?;

    // Try prefix matches — some sigs are shorter than our read buffer
    if matched.is_empty() {
        let max = hex_str.len();
        let mut i = max - (max % 2); // align to even
        while i >= 4 {
            let prefix = &hex_str[..i];
            matched = db::match_signatures(conn, prefix, offset)
                .map_err(|e| e.to_string())?;
            if !matched.is_empty() {
                break;
            }
            i -= 2;
        }
    }

    Ok(matched)
}

/// Quick scan — read header bytes, match at common offsets
pub fn quick_scan(
    conn: &rusqlite::Connection,
    path: &Path,
) -> Result<ScanResult, String> {
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;

    for &offset in SCAN_OFFSETS {
        if offset >= file_size {
            break;
        }
        let remaining = (file_size - offset).min(QUICK_SCAN_SIZE) as usize;
        let matched = match_at_offset(conn, path, offset, remaining)?;
        if !matched.is_empty() {
            let sig = &matched[0];
            let mut result = ScanResult {
                file_type: sig.name.clone(),
                mime: sig.mime.clone(),
                extension: sig.extension.clone(),
                compression: None,
                offset,
                confidence: 0.9,
                children: vec![],
            };

            // Check compression for known containers
            if is_known_container(&sig.name) {
                result.children = scan_container(conn, path, file_size)?;
            }

            return Ok(result);
        }
    }

    // Fallback: check if it's plain text
    detect_text_file(path)
}

/// Check if a file is plain text by sampling first 2KB
fn detect_text_file(path: &Path) -> Result<ScanResult, String> {
    if let Ok(mut f) = File::open(path) {
        let mut buf = vec![0u8; 2048];
        if let Ok(n) = f.read(&mut buf) {
            buf.truncate(n);
            if n == 0 { return Ok(ScanResult::unknown()); }

            let mut printable = 0usize;
            let mut i = 0;
            while i < buf.len() {
                let b = buf[i];
                if b == 0 { // null byte → binary
                    if i < 10 { break; }
                    i += 1;
                    continue;
                }
                if b == 0xFF || b == 0x1A { // 0xFF, EOF marker → binary
                    i += 1;
                    continue;
                }
                if b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) {
                    printable += 1;
                } else if b >= 0xC0 && b <= 0xFD {
                    // UTF-8 multibyte start — counts as printable
                    printable += 1;
                    i += 2; // skip continuation byte
                    continue;
                }
                i += 1;
            }

            let total = buf.len();
            let text_ratio = (printable as f32) / (total as f32);

            if text_ratio >= TEXT_RATIO_THRESHOLD {
                // Determine specific type by looking at first line
                let head = String::from_utf8_lossy(&buf[..buf.len().min(256)]);
                let detect = if head.trim_start().starts_with('{') || head.trim_start().starts_with('[') {
                    ("JSON data", "application/json", ".json")
                } else if head.trim_start().starts_with('<') {
                    if head.contains("<?xml") { ("XML document", "application/xml", ".xml") }
                    else if head.contains("<!DOCTYPE html") || head.contains("<html") { ("HTML document", "text/html", ".html") }
                    else { ("XML document", "application/xml", ".xml") }
                } else if head.trim_start().starts_with('#') || head.contains("#!/") {
                    ("Script file", "text/plain", ".sh")
                } else {
                    ("Plain text file", "text/plain", ".txt")
                };

                return Ok(ScanResult {
                    file_type: detect.0.to_string(),
                    mime: Some(detect.1.to_string()),
                    extension: Some(detect.2.to_string()),
                    compression: None,
                    offset: 0,
                    confidence: 0.7,
                    children: vec![],
                });
            }
        }
    }
    Ok(ScanResult::unknown())
}

/// Segmented scan — split file, scan in parallel via Rayon
pub fn segmented_scan(
    conn: &rusqlite::Connection,
    path: &Path,
    num_segments: u8,
) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;

    let segment_size = file_size / num_segments as u64;

    // Build segment descriptors
    let segments: Vec<(usize, u64, u64)> = (0..num_segments as usize)
        .map(|i| {
            let start = i as u64 * segment_size;
            let end = if i == num_segments as usize - 1 {
                file_size
            } else {
                start + segment_size + SEGMENT_OVERLAP
            };
            let size = (end - start).min(file_size - start);
            (i, start, size)
        })
        .collect();

    // Scan each segment sequentially for simplicity
    // ponytail: Rayon parallel later when DB connection sharing is sorted
    let mut results = Vec::with_capacity(segments.len());
    for (idx, start, size) in &segments {
        let mut result = ScanResult::unknown();
        if let Ok(mut matched) = match_at_offset(conn, path, *start, 128) {
            if !matched.is_empty() {
                let sig = matched.remove(0);
                result.file_type = sig.name.clone();
                result.mime = sig.mime;
                result.extension = sig.extension;
                result.offset = *start;
                result.confidence = 0.8;
            }
        }
        results.push(SegmentReport {
            index: *idx,
            offset: *start,
            size: *size,
            result,
        });
    }

    // Combine: first segment's type determines overall
    let combined = if let Some(first) = results.first() {
        if first.result.file_type != "Unknown" {
            ScanResult {
                file_type: format!("Multiple types — contains {}", first.result.file_type),
                mime: None,
                extension: None,
                compression: None,
                offset: 0,
                confidence: 0.7,
                children: vec![],
            }
        } else {
            ScanResult::unknown()
        }
    } else {
        ScanResult::unknown()
    };

    Ok(ScanResponse {
        total_size: file_size,
        segments: results,
        combined,
    })
}

/// Check if a file type is a known container format
fn is_known_container(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("zip")
        || lower.contains("rar")
        || lower.contains("tar")
        || lower.contains("7z")
        || lower.contains("gzip")
        || lower.contains("bzip")
        || lower.contains("iso")
        || lower.contains("cab")
        || lower.contains("arj")
}

/// Scan inside a container for embedded file signatures
fn scan_container(
    conn: &rusqlite::Connection,
    path: &Path,
    file_size: u64,
) -> Result<Vec<ScanResult>, String> {
    // ponytail: basic offset probing — scan at regular intervals inside container
    let mut children = Vec::new();
    let step = file_size / 16;

    // Scan inner offsets for embedded signatures
    for i in 1..16 {
        let offset = i * step;
        if offset >= file_size {
            break;
        }
        if let Ok(mut matched) = match_at_offset(conn, path, offset, 128) {
            if !matched.is_empty() && matched[0].extension.as_deref() != Some(".zip") {
                let sig = matched.remove(0);
                children.push(ScanResult {
                    file_type: sig.name,
                    mime: sig.mime,
                    extension: sig.extension,
                    compression: None,
                    offset,
                    confidence: 0.7,
                    children: vec![],
                });
            }
        }
    }

    Ok(children)
}

/// Main entry — decide mode, run scan
pub fn scan_file(
    conn: &rusqlite::Connection,
    path: &Path,
    mode: ScanMode,
) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;

    match mode {
        ScanMode::Quick => {
            let result = quick_scan(conn, path)?;
            Ok(ScanResponse {
                total_size: file_size,
                segments: vec![SegmentReport {
                    index: 0,
                    offset: 0,
                    size: file_size,
                    result: result.clone(),
                }],
                combined: result,
            })
        }
        ScanMode::Segmented(n) => {
            if file_size < SEGMENT_THRESHOLD {
                let result = quick_scan(conn, path)?;
                Ok(ScanResponse {
                    total_size: file_size,
                    segments: vec![SegmentReport {
                        index: 0,
                        offset: 0,
                        size: file_size,
                        result: result.clone(),
                    }],
                    combined: result,
                })
            } else {
                segmented_scan(conn, path, n)
            }
        }
    }
}

/// Decide mode based on file size
pub fn scan_file_auto(
    conn: &rusqlite::Connection,
    path: &Path,
) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())?;

    if file_size < SEGMENT_THRESHOLD {
        scan_file(conn, path, ScanMode::Quick)
    } else {
        let segs = segment_count(file_size);
        scan_file(conn, path, ScanMode::Segmented(segs))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ensure_schema, insert_signature, open_db};

    fn test_db() -> rusqlite::Connection {
        let conn = open_db(":memory:").unwrap();
        ensure_schema(&conn).unwrap();

        let zip_pattern = MagicPattern {
            offset: 0,
            hex_bytes: "504B0304".into(),
            mask: None,
            endianness: "little".into(),
        };
        insert_signature(
            &conn, "ZIP archive", Some("application/zip"), Some(".zip"), Some("test"), 10,
            &[zip_pattern],
        ).unwrap();

        let png_pattern = MagicPattern {
            offset: 0,
            hex_bytes: "89504E470D0A1A0A".into(),
            mask: None,
            endianness: "big".into(),
        };
        insert_signature(
            &conn, "PNG image", Some("image/png"), Some(".png"), Some("test"), 10,
            &[png_pattern],
        ).unwrap();
        conn
    }

    #[test]
    fn test_quick_scan_zip() {
        let conn = test_db();
        let dir = std::env::temp_dir();
        let path = dir.join("lumen_test_zip.bin");
        let bytes: Vec<u8> = vec![0x50, 0x4B, 0x03, 0x04, 0x14, 0x00];
        std::fs::write(&path, &bytes).unwrap();

        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "ZIP archive");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_quick_scan_png() {
        let conn = test_db();
        let dir = std::env::temp_dir();
        let path = dir.join("lumen_test_png.bin");
        let bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        std::fs::write(&path, &bytes).unwrap();

        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "PNG image");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_quick_scan_unknown() {
        let conn = test_db();
        let dir = std::env::temp_dir();
        let path = dir.join("lumen_test_unk.bin");
        let bytes: Vec<u8> = vec![0xDE, 0xAD, 0xBE, 0xEF];
        std::fs::write(&path, &bytes).unwrap();

        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "Unknown");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_read_hex_at() {
        let dir = std::env::temp_dir();
        let path = dir.join("lumen_test_hex.bin");
        let bytes: Vec<u8> = vec![0x50, 0x4B, 0x03, 0x04];
        std::fs::write(&path, &bytes).unwrap();

        let hex = read_hex_at(&path, 0, 4).unwrap();
        assert_eq!(hex, "504B0304");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_segment_count() {
        assert_eq!(segment_count(8 * 1024 * 1024), 4);        // 8 MB
        assert_eq!(segment_count(256 * 1024 * 1024), 4);      // 256 MB
        assert_eq!(segment_count(2 * 1024 * 1024 * 1024), 8); // 2 GB
        assert_eq!(segment_count(8 * 1024 * 1024 * 1024), 16); // 8 GB
    }
}
