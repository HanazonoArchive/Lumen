// ponytail: single-pass buffered reader, no full load
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

const TEXT_RATIO_THRESHOLD: f32 = 0.85;

use crate::db;
use crate::types::*;

const SCAN_OFFSETS: &[u64] = &[0, 4, 8, 16, 32, 64, 128, 256, 512, 1024];
const QUICK_SCAN_SIZE: u64 = 8192;
const SEGMENT_OVERLAP: u64 = 4096;
const SEGMENT_THRESHOLD: u64 = 16 * 1024 * 1024;

fn segment_count(file_size: u64) -> u8 {
    if file_size < 512 * 1024 * 1024 { 4 }
    else if file_size < 4 * 1024 * 1024 * 1024 { 8 }
    else { 16 }
}

pub fn read_hex_at(path: &Path, offset: u64, len: usize) -> Result<String, std::io::Error> {
    let mut f = File::open(path)?;
    f.seek(SeekFrom::Start(offset))?;
    let mut buf = vec![0u8; len];
    let n = f.read(&mut buf)?;
    buf.truncate(n);
    Ok(hex::encode(&buf).to_uppercase())
}

/// Short hex patterns (≤4 bytes) that commonly appear at variable offsets
/// due to custom wrapper headers (zlib, game formats, etc.). When exact +
/// truncation matching fails, we scan the full hex buffer for these.
const SHORT_PATTERNS: &[&str] = &[
    "789C", "7801", "78DA", // zlib (no compression, default, best)
];

/// Known longer patterns that tolerate leading header bytes (checked via contains)
const FLEXIBLE_PATTERNS: &[(u64, &str)] = &[
    (0, "1F8B08"), // gzip — often has 2-10 byte headers
];

pub fn match_at_offset(
    conn: &rusqlite::Connection,
    path: &Path,
    offset: u64,
    scan_len: usize,
) -> Result<Vec<Signature>, String> {
    let hex_str = read_hex_at(path, offset, scan_len).map_err(|e| e.to_string())?;
    let mut matched = db::match_signatures(conn, &hex_str, offset).map_err(|e| e.to_string())?;
    if matched.is_empty() {
        let max = hex_str.len();
        let mut i = max - (max % 2);
        while i >= 4 {
            let prefix = &hex_str[..i];
            matched = db::match_signatures(conn, prefix, offset).map_err(|e| e.to_string())?;
            if !matched.is_empty() { break; }
            i -= 2;
        }
    }
    // Fallback: scan for short patterns at any position within the buffer.
    // This catches zlib and similar signatures that have custom wrapper headers.
    if matched.is_empty() {
        for pat in SHORT_PATTERNS {
            if let Some(pos) = hex_str.find(pat) {
                let pat_offset = offset + (pos / 2) as u64;
                matched = db::match_signatures(conn, pat, pat_offset).map_err(|e| e.to_string())?;
                if !matched.is_empty() { break; }
                // Also try with offset 0 in case DB stores it there
                matched = db::match_signatures(conn, pat, 0).map_err(|e| e.to_string())?;
                if !matched.is_empty() { break; }
            }
        }
    }
    // Fallback: try flexible patterns (tolerate leading bytes before magic)
    if matched.is_empty() {
        for &(db_offset, pat) in FLEXIBLE_PATTERNS {
            if hex_str.contains(pat) {
                matched = db::match_signatures(conn, pat, db_offset).map_err(|e| e.to_string())?;
                if !matched.is_empty() { break; }
            }
        }
    }
    Ok(matched)
}

/// Detect hex bytes before a matched offset (header bytes)
fn detect_header_hex(path: &Path, matched_offset: u64) -> Option<String> {
    if matched_offset == 0 { return None; }
    let len = matched_offset.min(256) as usize;
    if len < 4 { return None; }
    if let Ok(hex) = read_hex_at(path, 0, len) {
        // Only return if there are actual non-null bytes
        let bytes = hex::decode(&hex).ok()?;
        if bytes.iter().any(|&b| b != 0) {
            Some(hex.to_uppercase())
        } else {
            None
        }
    } else {
        None
    }
}

/// Check if a ZIP file has password protection
fn check_zip_encrypted(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut buf = [0u8; 8];
        if f.read_exact(&mut buf).is_ok() {
            // ZIP local file header: sig(4) + version(2) = 6 bytes, then general purpose bit flag(2)
            // buf[6..8] is the bit flag, LE
            let flag = u16::from_le_bytes([buf[6], buf[7]]);
            if flag & 0x0001 != 0 {
                return true;
            }
        }
    }
    false
}

/// Read file into memory and parse as ZIP (handles leading headers)
fn read_file_as_zip(path: &Path) -> Result<zip::ZipArchive<std::io::Cursor<Vec<u8>>>, String> {
    let mut f = File::open(path).map_err(|e| format!("Open: {}", e))?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).map_err(|e| format!("Read: {}", e))?;
    if buf.len() < 4 {
        return Err("File too small".to_string());
    }
    zip::ZipArchive::new(std::io::Cursor::new(buf))
        .map_err(|e| format!("ZIP parse: {}", e))
}

/// Extract ZIP to temp dir and scan inner files
fn extract_and_scan_zip(conn: &rusqlite::Connection, path: &Path) -> Result<Vec<ScanResult>, String> {
    let mut archive = read_file_as_zip(path)?;

    let temp_dir = std::env::temp_dir().join(format!("lumen_extract_{}", std::process::id()));
    let _ = std::fs::create_dir_all(&temp_dir);

    let mut children = Vec::new();

    for i in 0..archive.len() {
        let mut entry = match archive.by_index(i) {
            Ok(e) => e,
            Err(_) => continue,
        };
        let entry_name = entry.name().to_string();
        if entry.is_dir() { continue; }

        // Sanitize: prevent zip slip (path traversal)
        let safe_name = std::path::Path::new(&entry_name);
        if safe_name.is_absolute() || safe_name.has_root() || safe_name.components().any(|c| c == std::path::Component::ParentDir) {
            eprintln!("lumen: zip slip attempt skipped: {}", entry_name);
            continue;
        }

        // Extract to temp
        let out_path = temp_dir.join(&entry_name);
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(mut out) = File::create(&out_path) {
            let mut data = Vec::new();
            if entry.read_to_end(&mut data).is_ok() {
                let _ = out.write_all(&data);
            }
        }

        // Scan extracted file
        let scan = quick_scan(conn, &out_path).unwrap_or_else(|_| ScanResult::unknown());
        let _ = std::fs::remove_file(&out_path);

        children.push(ScanResult {
            file_type: scan.file_type,
            mime: scan.mime,
            extension: scan.extension,
            compression: None,
            offset: 0,
            confidence: scan.confidence,
            has_password: false,
            header_hex: None,
            inner_name: Some(entry_name),
            children: scan.children,
        });
    }

    // Cleanup temp dir
    let _ = std::fs::remove_dir_all(&temp_dir);

    Ok(build_file_tree(children))
}

// ============================================================
// Shared temp directory helpers
// ============================================================

/// Remove stale lumen_extract_* temp dirs from previous runs
pub fn cleanup_temp_dirs() {
    let temp = std::env::temp_dir();
    if let Ok(entries) = std::fs::read_dir(&temp) {
        for entry in entries.flatten() {
            let path = entry.path();
            if path.is_dir() {
                if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                    if name.starts_with("lumen_extract_") {
                        let _ = std::fs::remove_dir_all(&path);
                    }
                }
            }
        }
    }
}

/// Create a fresh PID-based temp dir for extraction (removes stale one first)
fn prepare_extract_dir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("lumen_extract_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::create_dir_all(&dir);
    dir
}

// ============================================================
// TAR extraction
// ============================================================

/// Extract a TAR archive to temp and scan inner files
fn extract_and_scan_tar(conn: &rusqlite::Connection, path: &Path) -> Result<Vec<ScanResult>, String> {
    let file = File::open(path).map_err(|e| format!("Open: {}", e))?;
    let mut archive = tar::Archive::new(file);

    let temp_dir = prepare_extract_dir();
    let mut children = Vec::new();

    if let Ok(mut entries) = archive.entries() {
        while let Some(Ok(mut entry)) = entries.next() {
            let entry_name = entry.path()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_default();

            if entry_name.is_empty() || entry.header().entry_type().is_dir() {
                continue;
            }

            // Prevent tar slip
            let safe_path = std::path::Path::new(&entry_name);
            if safe_path.is_absolute() || safe_path.has_root() || safe_path.components().any(|c| c == std::path::Component::ParentDir) {
                eprintln!("lumen: tar slip attempt skipped: {}", entry_name);
                continue;
            }

            let out_path = temp_dir.join(&entry_name);
            if let Some(parent) = out_path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }

            let mut data = Vec::new();
            if entry.read_to_end(&mut data).is_ok() {
                let _ = std::fs::write(&out_path, &data);
            }

            let scan = quick_scan(conn, &out_path).unwrap_or_else(|_| ScanResult::unknown());
            let _ = std::fs::remove_file(&out_path);

            children.push(ScanResult {
                file_type: scan.file_type,
                mime: scan.mime,
                extension: scan.extension,
                compression: None,
                offset: 0,
                confidence: scan.confidence,
                has_password: false,
                header_hex: None,
                inner_name: Some(entry_name),
                children: scan.children,
            });
        }
    }

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(build_file_tree(children))
}

// ============================================================
// RAR extraction
// ============================================================

/// Read a RAR 5 variable-length integer (VINT). Returns None on overflow or EOF.
fn read_vint(buf: &[u8], pos: &mut usize) -> Option<u64> {
    let mut result: u64 = 0;
    let mut shift = 0;
    while *pos < buf.len() {
        let byte = buf[*pos];
        *pos += 1;
        result |= ((byte & 0x7F) as u64) << shift;
        shift += 7;
        if shift > 63 { return None; }
        if byte & 0x80 == 0 { return Some(result); }
    }
    None
}

/// Check RAR encryption via header flags. Supports both v1.5 and v5.
fn check_rar_encrypted(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut buf = [0u8; 32];
        let n = f.read(&mut buf).unwrap_or(0);
        if n < 8 { return false; }

        // RAR v1.5: marker(7) + HEAD_CRC(2) + HEAD_TYPE(1) + HEAD_FLAGS(2)
        if buf[..7] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00] {
            if n < 12 { return false; }
            let flags = u16::from_le_bytes([buf[10], buf[11]]);
            // Bit 5 (0x0020) = password. NOT bit 3 (recovery record).
            return flags & 0x0020 != 0;
        }

        // RAR v5: marker(8) + VINT CRC_SIZE + VINT HEADER_SIZE + TYPE(1) + VINT FLAGS
        if n >= 8 && buf[..8] == [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x01, 0x00] {
            let mut pos = 8;
            let _crc_size = match read_vint(&buf, &mut pos) { Some(v) => v, None => return false };
            if pos >= n { return false; }
            // Skip remaining bytes of CRC + header size VINTs
            let _header_size = match read_vint(&buf, &mut pos) { Some(v) => v, None => return false };
            if pos >= n { return false; }
            let header_type = buf[pos]; pos += 1;
            if pos >= n { return false; }
            if header_type == 1 {
                if let Some(flags) = read_vint(&buf, &mut pos) {
                    // RAR 5: bit 1 (0x02) in main archive header flags = encryption
                    return flags & 0x02 != 0;
                }
            }
        }
    }
    false
}

// ============================================================
// 7z extraction
// ============================================================

/// Extract 7z archive to temp and scan inner files
fn extract_and_scan_7z(conn: &rusqlite::Connection, path: &Path) -> Result<Vec<ScanResult>, String> {
    use sevenz_rust::{SevenZReader, Password};

    let temp_dir = prepare_extract_dir();
    let mut children = Vec::new();

    let mut reader = SevenZReader::open(path, Password::empty())
        .map_err(|e| format!("7z open: {}", e))?;

    reader.for_each_entries(|entry, data| {
        let entry_name = entry.name().to_string();
        if entry_name.is_empty() || entry.is_directory() {
            return Ok(true);
        }

        // Sanitize path
        let safe_path = std::path::Path::new(&entry_name);
        if safe_path.is_absolute() || safe_path.has_root() || safe_path.components().any(|c| c == std::path::Component::ParentDir) {
            eprintln!("lumen: 7z slip attempt skipped: {}", entry_name);
            return Ok(true);
        }

        let mut buf = Vec::new();
        let _ = data.read_to_end(&mut buf);

        let out_path = temp_dir.join(&entry_name);
        if let Some(parent) = out_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(&out_path, &buf);

        let scan = quick_scan(conn, &out_path).unwrap_or_else(|_| ScanResult::unknown());
        let _ = std::fs::remove_file(&out_path);

        children.push(ScanResult {
            file_type: scan.file_type,
            mime: scan.mime,
            extension: scan.extension,
            compression: None,
            offset: 0,
            confidence: scan.confidence,
            has_password: false,
            header_hex: None,
            inner_name: Some(entry_name),
            children: scan.children,
        });

        Ok(true)
    }).map_err(|e| format!("7z extract: {}", e))?;

    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(build_file_tree(children))
}

// ============================================================
// External extractor — uses 7z.exe as backend for formats without
// a native Rust extractor (RAR, CAB, ISO, ARJ, etc.)
// ============================================================

/// Locate 7z.exe on the system (exe dir, exe's resources/, PATH, common install dirs)
fn find_7z() -> Option<std::path::PathBuf> {
    // Check lumen.exe's own directory first (bundled deployment)
    if let Ok(exe) = std::env::current_exe() {
        if let Some(dir) = exe.parent() {
            let bundled = dir.join("7z.exe");
            if bundled.is_file() { return Some(bundled); }
            // Tauri MSI bundles resources in a subfolder
            let res = dir.join("resources").join("7z.exe");
            if res.is_file() { return Some(res); }
            // Walk up from debug/target dirs for dev mode (project's lumen-gui/resources/)
            for ancestor in dir.ancestors().skip(1).take(4) {
                let dev_res = ancestor.join("lumen-gui").join("resources").join("7z.exe");
                if dev_res.is_file() { return Some(dev_res); }
            }
        }
    }
    // Check PATH
    if let Some(path) = std::env::var_os("PATH") {
        for dir in std::env::split_paths(&path) {
            let candidate = dir.join("7z.exe");
            if candidate.is_file() { return Some(candidate); }
            let candidate = dir.join("7z");
            if candidate.is_file() { return Some(candidate); }
        }
    }
    // Common Windows install locations
    for base in &[
        r"C:\Program Files\7-Zip",
        r"C:\Program Files (x86)\7-Zip",
    ] {
        let candidate = std::path::Path::new(base).join("7z.exe");
        if candidate.is_file() { return Some(candidate); }
    }
    None
}

/// Extract archive using a known 7z.exe path. Handles any format 7-Zip supports.
fn extract_via_7z(exe: &std::path::Path, path: &Path, dest: &std::path::Path) -> Result<(), String> {
    let tst = std::process::Command::new(&exe)
        .arg("t").arg(path.as_os_str())
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .output().map_err(|e| format!("7z test: {}", e))?;
    if !tst.status.success() {
        return Err(format!("7z test failed (code {:?})", tst.status.code()));
    }
    let exe_dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
    let extract = std::process::Command::new(&exe)
        .current_dir(exe_dir)
        .arg("x").arg(path.as_os_str())
        .arg(format!("-o{}", dest.to_string_lossy())).arg("-y")
        .stdout(std::process::Stdio::null()).stderr(std::process::Stdio::null())
        .output().map_err(|e| format!("7z extract: {}", e))?;
    if extract.status.success() { Ok(()) }
    else { Err(format!("7z exited with code {:?}", extract.status.code())) }
}

/// Extract any container using 7z.exe backend, scan inner files.
/// Falls back to probe if 7z not available.
fn extract_and_scan_external(conn: &rusqlite::Connection, path: &Path) -> Result<Vec<ScanResult>, String> {
    let exe = match find_7z() {
        Some(p) => p,
        None => return Err("7z.exe not available".to_string()),
    };
    let temp_dir = prepare_extract_dir();
    if let Err(e) = extract_via_7z(&exe, path, &temp_dir) {
        let _ = std::fs::remove_dir_all(&temp_dir);
        return Err(e);
    }
    let mut children = Vec::new();
    scan_dir_for_results(conn, &temp_dir, "", &mut children);
    let _ = std::fs::remove_dir_all(&temp_dir);
    Ok(build_file_tree(children))
}

/// Strip Windows `\\?\` prefix for reliable path comparison
fn normalize_path(p: &std::path::Path) -> std::path::PathBuf {
    let s = p.to_string_lossy();
    if cfg!(windows) && s.starts_with(r"\\?\") {
        std::path::PathBuf::from(&s[4..])
    } else {
        p.to_path_buf()
    }
}

/// Convert flat extracted-file list (paths like `dir/sub/file.ext`) into a nested tree
/// with intermediate folder entries. Applied by extraction functions before returning.
fn build_file_tree(flat: Vec<ScanResult>) -> Vec<ScanResult> {
    use std::collections::BTreeMap;
    // Collect all items keyed by their full dir path
    let mut by_dir: BTreeMap<String, Vec<ScanResult>> = BTreeMap::new();
    let mut root: Vec<ScanResult> = Vec::new();

    for entry in flat {
        let name = match &entry.inner_name {
            Some(n) => n.clone(),
            None => { root.push(entry); continue; }
        };
        if let Some(slash) = name.rfind('/') {
            let dir = name[..slash].to_string();
            let mut child = entry;
            child.inner_name = Some(name[slash + 1..].to_string());
            by_dir.entry(dir).or_default().push(child);
        } else {
            root.push(entry);
        }
    }

    // Process dirs from longest path to shortest (deepest first)
    let dirs: Vec<String> = by_dir.keys().cloned().collect();
    for dp in dirs.iter().rev() {
        let contents = by_dir.remove(dp).unwrap();
        let folder_name = dp.rsplit('/').next().unwrap_or(dp);
        let children = build_file_tree(contents);
        let folder = ScanResult {
            file_type: "Folder".into(),
            mime: Some("inode/directory".into()),
            extension: None, compression: None, offset: 0, confidence: 1.0,
            has_password: false, header_hex: None,
            inner_name: Some(folder_name.to_string()),
            children,
        };

        // Place into parent dir or root
        if let Some(ps) = dp.rfind('/') {
            let parent = dp[..ps].to_string();
            // Folders within the same parent dir accumulate
            let siblings = by_dir.entry(parent).or_default();
            // Un-flatten: this folder is a child of parent, not a flat ScanResult
            // Insert it into parent's children list via a synthetic entry
            siblings.push(folder);
        } else {
            root.push(folder);
        }
    }

    root
}

/// Recursively scan a directory and collect ScanResults with relative names
/// Guards against symlink-based traversal by canonicalizing and checking boundaries.
fn scan_dir_for_results(conn: &rusqlite::Connection, dir: &std::path::Path, prefix: &str, results: &mut Vec<ScanResult>) {
    let canonical_base = normalize_path(&std::fs::canonicalize(dir).unwrap_or_else(|_| dir.to_path_buf()));
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let real = match std::fs::canonicalize(&path) {
                Ok(p) if normalize_path(&p).starts_with(&canonical_base) => p,
                _ => continue,
            };
            let name = entry.file_name().to_string_lossy().to_string();
            let rel = if prefix.is_empty() { name.clone() } else { format!("{}/{}", prefix, name) };
            if real.is_file() {
                let scan = quick_scan(conn, &real).unwrap_or_else(|_| ScanResult::unknown());
                let _ = std::fs::remove_file(&path); // remove entry path (safe symlink removal)
                results.push(ScanResult {
                    file_type: scan.file_type,
                    mime: scan.mime,
                    extension: scan.extension,
                    compression: None,
                    offset: 0,
                    confidence: scan.confidence,
                    has_password: false,
                    header_hex: None,
                    inner_name: Some(rel),
                    children: scan.children,
                });
            } else if real.is_dir() {
                scan_dir_for_results(conn, &path, &rel, results); // keep using &path for dir iteration, real handles boundary
            }
        }
    }
}

// ============================================================
// Hex-driven disambiguation — when multiple signatures share the
// same magic bytes, peek inside the file to determine the real format.
// ============================================================

/// Hex patterns known to be ambiguous. Add new ones here.
fn is_ambiguous_hex(hex: &str) -> bool {
    matches!(hex, "504B0304") // ZIP-based: ZIP, EPUB, APK, DOCX, JAR, iWork, etc.
}

/// Dispatch to the right disambiguator based on hex pattern.
/// `candidates` are all signatures matching this hex+offset.
fn disambiguate_by_hex<'a>(hex: &str, path: &Path, candidates: &'a [Signature]) -> Option<&'a Signature> {
    match hex {
        "504B0304" => disambiguate_zip(path, candidates),
        _ => None,
    }
}

/// Disambiguate ZIP-based formats by checking entry names inside the archive.
fn disambiguate_zip<'a>(path: &Path, candidates: &'a [Signature]) -> Option<&'a Signature> {
    // ponytail: skip large files — not worth loading 50+ MB just for display
    let meta = std::fs::metadata(path).ok()?;
    if meta.len() > 50 * 1024 * 1024 {
        return candidates.iter().find(|s| s.name == "ZIP archive");
    }

    let mut archive = read_file_as_zip(path).ok()?;

    // Build lookup from candidate names
    let find_candidate = |name: &str| candidates.iter().find(|s| s.name == name);

    // Collect entry names
    let mut names = Vec::new();
    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            names.push(entry.name().replace('\\', "/").to_lowercase());
        }
    }

    // Check most specific first — order matters
    if names.iter().any(|n| n == "androidmanifest.xml") {
        return find_candidate("Android APK");
    }
    if names.iter().any(|n| n.starts_with("word/")) {
        return find_candidate("Word DOCX");
    }
    if names.iter().any(|n| n.starts_with("xl/")) {
        return find_candidate("Excel XLSX");
    }
    if names.iter().any(|n| n.starts_with("ppt/")) {
        return find_candidate("PowerPoint PPTX");
    }
    if names.iter().any(|n| n == "meta-inf/manifest.mf") {
        return find_candidate("Java JAR");
    }
    // Check EPUB via mimetype content
    if let Some(idx) = names.iter().position(|n| n == "mimetype") {
        if let Ok(mut entry) = archive.by_index(idx) {
            let mut content = Vec::new();
            let _ = std::io::Read::read_to_end(&mut entry, &mut content);
            if content.starts_with(b"application/epub+zip") {
                return find_candidate("EPUB ebook");
            }
        }
    }

    // Default: return generic ZIP archive
    find_candidate("ZIP archive")
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
        if offset >= file_size { break; }
        let remaining = (file_size - offset).min(QUICK_SCAN_SIZE) as usize;
        let matched = match_at_offset(conn, path, offset, remaining)?;
        if !matched.is_empty() {
            let sig = &matched[0];
            let header_hex = detect_header_hex(path, offset);
            let hex = &sig.patterns[0].hex_bytes;

            // If multiple signatures share this hex pattern, disambiguate by content.
            // The candidate pool is all sigs sharing the same hex+offset, not just the
            // highest-priority one — so this works regardless of seed order.
            let display_sig = if matched.len() > 1 && is_ambiguous_hex(hex) {
                disambiguate_by_hex(hex, path, &matched).unwrap_or(sig)
            } else {
                sig
            };

            // Container check: by name OR by hex pattern (handles cases where matched[0]
            // is "EPUB ebook" — name isn't a container but hex 504B0304 definitely is).
            let is_container = is_known_container(&sig.name) || hex == "504B0304";

            let has_password = {
                let lower = sig.name.to_lowercase();
                if is_container && lower.contains("zip") {
                    check_zip_encrypted(path)
                } else if is_container && lower.contains("rar") {
                    check_rar_encrypted(path)
                } else {
                    false
                }
            };

            let mut result = ScanResult {
                file_type: display_sig.name.clone(),
                mime: display_sig.mime.clone(),
                extension: display_sig.extension.clone(),
                compression: None,
                offset,
                confidence: 0.9,
                has_password,
                header_hex,
                inner_name: None,
                children: vec![],
            };

            if is_container && !has_password {
                let lower = sig.name.to_lowercase();
                let hex = &sig.patterns[0].hex_bytes;
                let extract_result = if hex == "504B0304" || lower.contains("zip") {
                    extract_and_scan_zip(conn, path)
                } else if lower.contains("tar") {
                    extract_and_scan_tar(conn, path)
                } else if lower.contains("7z") {
                    extract_and_scan_7z(conn, path)
                } else {
                    // Try external 7z.exe backend for RAR, CAB, ISO, ARJ, etc.
                    extract_and_scan_external(conn, path)
                };
                match extract_result {
                    Ok(inner) => result.children = inner,
                    Err(e) => {
                        eprintln!("lumen: extract failed (falling back to probe): {}", e);
                        result.children = scan_container(conn, path, file_size)?;
                    }
                }
            } else if is_container {
                result.children = scan_container(conn, path, file_size)?;
            }

            return Ok(result);
        }
    }

    detect_text_file(path)
}

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
                if b == 0 { if i < 10 { break; } i += 1; continue; }
                if b == 0xFF || b == 0x1A { i += 1; continue; }
                if b == 9 || b == 10 || b == 13 || (b >= 32 && b < 127) { printable += 1; }
                else if b >= 0xC0 && b <= 0xFD { printable += 1; i += 2; continue; }
                i += 1;
            }

            let total = buf.len();
            let text_ratio = (printable as f32) / (total as f32);

            if text_ratio >= TEXT_RATIO_THRESHOLD {
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
                    file_type: detect.0.to_string(), mime: Some(detect.1.to_string()),
                    extension: Some(detect.2.to_string()), compression: None,
                    offset: 0, confidence: 0.7, has_password: false,
                    header_hex: None, inner_name: None, children: vec![],
                });
            }
        }
    }
    Ok(ScanResult::unknown())
}

pub fn segmented_scan(
    conn: &rusqlite::Connection, path: &Path, num_segments: u8,
) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path).map(|m| m.len()).map_err(|e| e.to_string())?;
    let segment_size = file_size / num_segments as u64;
    let segments: Vec<(usize, u64, u64)> = (0..num_segments as usize).map(|i| {
        let start = i as u64 * segment_size;
        let end = if i == num_segments as usize - 1 { file_size } else { start + segment_size + SEGMENT_OVERLAP };
        let size = (end - start).min(file_size - start);
        (i, start, size)
    }).collect();

    let mut results = Vec::with_capacity(segments.len());
    for (idx, start, size) in &segments {
        let mut result = ScanResult::unknown();
        if let Ok(mut matched) = match_at_offset(conn, path, *start, 128) {
            if !matched.is_empty() {
                let sig = matched.remove(0);
                result.file_type = sig.name; result.offset = *start; result.confidence = 0.8;
            }
        }
        results.push(SegmentReport { index: *idx, offset: *start, size: *size, result });
    }

    let combined = results.first().map(|f| {
        if f.result.file_type != "Unknown" {
            ScanResult { file_type: format!("Multiple types — contains {}", f.result.file_type),
                mime: None, extension: None, compression: None, offset: 0, confidence: 0.7,
                has_password: false, header_hex: None, inner_name: None, children: vec![] }
        } else { ScanResult::unknown() }
    }).unwrap_or_else(ScanResult::unknown);

    Ok(ScanResponse { total_size: file_size, segments: results, combined })
}

fn is_known_container(name: &str) -> bool {
    let lower = name.to_lowercase();
    lower.contains("zip") || lower.contains("rar") || lower.contains("tar")
        || lower.contains("7z") || lower.contains("gzip") || lower.contains("bzip")
        || lower.contains("iso") || lower.contains("cab") || lower.contains("arj")
}

fn scan_container(conn: &rusqlite::Connection, path: &Path, file_size: u64) -> Result<Vec<ScanResult>, String> {
    let mut children = Vec::new();
    let step = file_size / 16;
    for i in 1..16 {
        let offset = i * step;
        if offset >= file_size { break; }
        if let Ok(mut matched) = match_at_offset(conn, path, offset, 128) {
            if !matched.is_empty() && matched[0].extension.as_deref() != Some(".zip") {
                let sig = matched.remove(0);
                children.push(ScanResult {
                    file_type: sig.name, mime: sig.mime, extension: sig.extension,
                    compression: None, offset, confidence: 0.7,
                    has_password: false, header_hex: None, inner_name: None, children: vec![],
                });
            }
        }
    }
    Ok(children)
}

pub fn scan_file(conn: &rusqlite::Connection, path: &Path, mode: ScanMode) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path).map(|m| m.len()).map_err(|e| e.to_string())?;
    match mode {
        ScanMode::Quick => {
            let result = quick_scan(conn, path)?;
            Ok(ScanResponse { total_size: file_size, segments: vec![SegmentReport { index: 0, offset: 0, size: file_size, result: result.clone() }], combined: result })
        }
        ScanMode::Segmented(n) => {
            if file_size < SEGMENT_THRESHOLD {
                let result = quick_scan(conn, path)?;
                Ok(ScanResponse { total_size: file_size, segments: vec![SegmentReport { index: 0, offset: 0, size: file_size, result: result.clone() }], combined: result })
            } else { segmented_scan(conn, path, n) }
        }
    }
}

pub fn scan_file_auto(conn: &rusqlite::Connection, path: &Path) -> Result<ScanResponse, String> {
    let file_size = std::fs::metadata(path).map(|m| m.len()).map_err(|e| e.to_string())?;
    if file_size < SEGMENT_THRESHOLD { scan_file(conn, path, ScanMode::Quick) }
    else { let segs = segment_count(file_size); scan_file(conn, path, ScanMode::Segmented(segs)) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::db::{ensure_schema, insert_signature, open_db};

    fn test_db() -> rusqlite::Connection {
        let conn = open_db(":memory:").unwrap();
        ensure_schema(&conn).unwrap();
        insert_signature(&conn, "ZIP archive", Some("application/zip"), Some(".zip"), Some("test"), 10,
            &[MagicPattern { offset: 0, hex_bytes: "504B0304".into(), mask: None, endianness: "little".into() }],
        ).unwrap();
        insert_signature(&conn, "PNG image", Some("image/png"), Some(".png"), Some("test"), 10,
            &[MagicPattern { offset: 0, hex_bytes: "89504E470D0A1A0A".into(), mask: None, endianness: "big".into() }],
        ).unwrap();
        conn
    }

    #[test]
    fn test_quick_scan_zip() {
        let conn = test_db();
        let path = std::env::temp_dir().join("lumen_test_zip.bin");
        std::fs::write(&path, &[0x50, 0x4B, 0x03, 0x04, 0x14, 0x00]).unwrap();
        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "ZIP archive");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_quick_scan_png() {
        let conn = test_db();
        let path = std::env::temp_dir().join("lumen_test_png.bin");
        let bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        std::fs::write(&path, &bytes).unwrap();
        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "PNG image");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_quick_scan_unknown() {
        let conn = test_db();
        let path = std::env::temp_dir().join("lumen_test_unk.bin");
        std::fs::write(&path, &[0xDE, 0xAD, 0xBE, 0xEF]).unwrap();
        let result = quick_scan(&conn, &path).unwrap();
        assert_eq!(result.file_type, "Unknown");
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_detect_header_hex() {
        let path = std::env::temp_dir().join("lumen_test_hdr.bin");
        let mut bytes = vec![0x41u8; 16]; // 16 'A' bytes as header
        bytes.extend_from_slice(&[0x50, 0x4B, 0x03, 0x04]); // ZIP magic
        std::fs::write(&path, &bytes).unwrap();

        let header = detect_header_hex(&path, 16);
        assert!(header.is_some());
        let h = header.unwrap();
        // Should be 16 bytes of 0x41 = "41414141...41" (32 hex chars)
        assert!(h.len() >= 16);
        assert!(h.chars().all(|c| c == '4' || c == '1'));
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_no_header_at_offset_zero() {
        let path = std::env::temp_dir().join("lumen_test_nohdr.bin");
        std::fs::write(&path, &[0x50, 0x4B, 0x03, 0x04]).unwrap();
        let header = detect_header_hex(&path, 0);
        assert!(header.is_none());
        std::fs::remove_file(&path).unwrap();
    }

    #[test]
    fn test_segment_count() {
        assert_eq!(segment_count(8 * 1024 * 1024), 4);
        assert_eq!(segment_count(256 * 1024 * 1024), 4);
        assert_eq!(segment_count(2 * 1024 * 1024 * 1024), 8);
        assert_eq!(segment_count(8 * 1024 * 1024 * 1024), 16);
    }

    #[test]
    fn test_real_zip_extraction() {
        let conn = test_db();
        // Add PNG sig for inner file detection
        insert_signature(&conn, "PNG image", Some("image/png"), Some(".png"), Some("test"), 10,
            &[MagicPattern { offset: 0, hex_bytes: "89504E470D0A1A0A".into(), mask: None, endianness: "big".into() }],
        ).ok();

        let zip_path = std::env::temp_dir().join("lumen_test_real.zip");
        let inner_path = std::env::temp_dir().join("lumen_test_inner.png");

        // Create inner PNG file
        let png_bytes: Vec<u8> = vec![0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A];
        std::fs::write(&inner_path, &png_bytes).unwrap();

        // Create ZIP from inner file
        let f = File::create(&zip_path).unwrap();
        let mut zipw = zip::ZipWriter::new(f);
        zipw.start_file("test.png", zip::write::FileOptions::<()>::default()).unwrap();
        zipw.write_all(&png_bytes).unwrap();
        zipw.finish().unwrap();

        std::fs::remove_file(&inner_path).unwrap();

        // Test extract_and_scan_zip
        let children = extract_and_scan_zip(&conn, &zip_path).unwrap();
        assert!(!children.is_empty(), "Should find inner files");
        assert_eq!(children[0].inner_name.as_deref(), Some("test.png"));
        assert_eq!(children[0].file_type, "PNG image");

        std::fs::remove_file(&zip_path).unwrap();
    }

    #[test]
    fn test_scan_real_zip_extraction_via_quick() {
        let conn = test_db();
        let zip_path = std::env::temp_dir().join("lumen_real_extract_test.zip");
        let inner = std::env::temp_dir().join("lumen_inner_extract.png");

        // Create inner PNG
        std::fs::write(&inner, &[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();

        // ZIP it
        let f = std::fs::File::create(&zip_path).unwrap();
        let mut z = zip::ZipWriter::new(f);
        z.start_file("test_inner.png", zip::write::FileOptions::<()>::default()).unwrap();
        z.write_all(&[0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]).unwrap();
        z.finish().unwrap();
        std::fs::remove_file(&inner).unwrap();

        // Now scan via quick_scan which should trigger extract_and_scan_zip
        let result = quick_scan(&conn, &zip_path).unwrap();
        assert_eq!(result.file_type, "ZIP archive");
        assert!(!result.has_password);
        assert!(!result.children.is_empty(), "ZIP extraction should find inner files");
        eprintln!("  Inner file: {:?} = {}", result.children[0].inner_name, result.children[0].file_type);
        assert_eq!(result.children[0].inner_name.as_deref(), Some("test_inner.png"));
        assert_eq!(result.children[0].file_type, "PNG image");

        std::fs::remove_file(&zip_path).unwrap();
    }

    #[test]
    fn test_zip_encrypted_detection() {
        // Normal ZIP without password should not be detected as encrypted
        let path = std::env::temp_dir().join("lumen_test_noenc.zip");
        let f = File::create(&path).unwrap();
        let mut zipw = zip::ZipWriter::new(f);
        zipw.start_file("test.txt", zip::write::FileOptions::<()>::default()).unwrap();
        zipw.write_all(b"hello").unwrap();
        zipw.finish().unwrap();

        assert!(!check_zip_encrypted(&path));
        std::fs::remove_file(&path).unwrap();
    }
}
