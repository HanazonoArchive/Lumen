use rusqlite::{Connection, params};
use crate::types::{Signature, MagicPattern};

/// Open (or create) the signature database
pub fn open_db(path: &str) -> Result<Connection, rusqlite::Error> {
    let conn = Connection::open(path)?;
    conn.execute_batch("PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;")?;
    Ok(conn)
}

/// Create tables if they don't exist
pub fn ensure_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS signatures (
            id          INTEGER PRIMARY KEY,
            name        TEXT    NOT NULL,
            mime        TEXT,
            extension   TEXT,
            source      TEXT,
            priority    INTEGER DEFAULT 0
        );

        CREATE TABLE IF NOT EXISTS magic_patterns (
            id              INTEGER PRIMARY KEY,
            signature_id    INTEGER REFERENCES signatures(id) ON DELETE CASCADE,
            offset          INTEGER DEFAULT 0,
            hex_bytes       TEXT    NOT NULL,
            mask            TEXT,
            endianness      TEXT    DEFAULT 'little'
        );

        CREATE TABLE IF NOT EXISTS compression_map (
            id                  INTEGER PRIMARY KEY,
            container_sig_id    INTEGER REFERENCES signatures(id) ON DELETE CASCADE,
            inner_magic         TEXT,
            compression_type    TEXT NOT NULL
        );"
    )?;
    Ok(())
}

/// Drop all tables and recreate — for rebuild / reseed
pub fn drop_schema(conn: &Connection) -> Result<(), rusqlite::Error> {
    conn.execute_batch(
        "DROP TABLE IF EXISTS compression_map;
         DROP TABLE IF EXISTS magic_patterns;
         DROP TABLE IF EXISTS signatures;"
    )?;
    Ok(())
}

pub type SigDef = (&'static str, Option<&'static str>, Option<&'static str>, i64, &'static str);

/// Map GCK file class to a MIME type
fn class_to_mime(class: &str) -> Option<&'static str> {
    match class.to_lowercase().as_str() {
        "audio" => Some("audio/octet-stream"),
        "video" => Some("video/octet-stream"),
        "picture" => Some("image/octet-stream"),
        "multimedia" | "media" => Some("application/octet-stream"),
        "compressed archive" | "backup" => Some("application/octet-stream"),
        "database" => Some("application/octet-stream"),
        "e-mail" | "email" => Some("message/rfc822"),
        "presentation" => Some("application/octet-stream"),
        "spreadsheet" => Some("application/octet-stream"),
        "word processing" | "word processing suite" => Some("application/octet-stream"),
        "programming" => Some("text/plain"),
        "finance" | "financial" | "e-money" => Some("application/octet-stream"),
        "encryption" => Some("application/octet-stream"),
        "windows" | "system" | "utility" => Some("application/octet-stream"),
        "linux-unix" | "macos" => Some("application/octet-stream"),
        "games" => Some("application/octet-stream"),
        "navigation" | "mobile" => Some("application/octet-stream"),
        "network" => Some("application/octet-stream"),
        "open font" => Some("font/otf"),
        "application" | "statistics" => Some("application/octet-stream"),
        "miscellaneous" | "" => None,
        _ => None,
    }
}

/// Leak a String into a &'static str. Used in seed_sigs() since CSV data is dynamic
/// but SigDef requires static lifetimes. Memory is allocated once at seed time.
fn leak_str(s: String) -> &'static str {
    Box::leak(s.into_boxed_str())
}

/// Supplementary signatures the scanner depends on by name (disambiguation,
/// password checks, container detection). The CSV has broader coverage but
/// uses different naming — these fill the gap.
fn supplementary_sigs() -> Vec<SigDef> {
    vec![
        // ZIP variants (disambiguation + container detection)
        ("ZIP archive", Some("application/zip"), Some(".zip"), 0, "504B0304"),
        ("ZIP empty archive", Some("application/zip"), Some(".zip"), 0, "504B0506"),
        ("ZIP spanned archive", Some("application/zip"), Some(".zip"), 0, "504B0708"),
        // RAR variants (password check)
        ("RAR archive v1.5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A0700"),
        ("RAR archive v5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A070100"),
        // Disambiguation targets
        ("Android APK", Some("application/vnd.android.package-archive"), Some(".apk"), 0, "504B0304"),
        ("EPUB ebook", Some("application/epub+zip"), Some(".epub"), 0, "504B0304"),
        ("Word DOCX", Some("application/vnd.openxmlformats-officedocument.wordprocessingml.document"), Some(".docx"), 0, "504B0304"),
        ("Excel XLSX", Some("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"), Some(".xlsx"), 0, "504B0304"),
        ("PowerPoint PPTX", Some("application/vnd.openxmlformats-officedocument.presentationml.presentation"), Some(".pptx"), 0, "504B0304"),
        ("Java JAR", Some("application/java-archive"), Some(".jar"), 0, "504B0304"),
        ("Apple Pages", Some("application/x-iwork-pages"), Some(".pages"), 0, "504B0304"),
        ("Apple Numbers", Some("application/x-iwork-numbers"), Some(".numbers"), 0, "504B0304"),
        ("Apple Keynote", Some("application/x-iwork-keynote"), Some(".key"), 0, "504B0304"),
        // Others with accurate MIME types
        ("PDF document", Some("application/pdf"), Some(".pdf"), 0, "255044462D"),
        ("OLE2 Compound (DOC/XLS)", Some("application/x-ole-storage"), Some(".doc"), 0, "D0CF11E0A1B11AE1"),
        // Zlib compressed data (common in game files and embedded streams)
        ("Zlib compressed (no compression)", Some("application/zlib"), Some(".zlib"), 0, "7801"),
        ("Zlib compressed (default)", Some("application/zlib"), Some(".zlib"), 0, "789C"),
        ("Zlib compressed (best)", Some("application/zlib"), Some(".zlib"), 0, "78DA"),
        // LithTech / Monolith resource files
        ("LithTech RezMgr resource", Some("application/x-rezmg"), Some(".rez"), 0, "0D0A52657A4D6772"),
    ]
}

/// Seed signature list: GCK CSV (~615 entries) + supplementary sigs for scanner logic.
/// Deduplicates by (hex, offset) — CSV wins, supplementary fills gaps.
pub fn seed_sigs() -> Vec<SigDef> {
    let csv = include_str!("sigs.csv");
    let mut sigs = Vec::new();

    // 1. Parse CSV entries
    for line in csv.lines().skip(1) {
        let parts: Vec<&str> = line.splitn(6, ',').collect();
        if parts.len() < 5 { continue; }

        let name = parts[0].trim();
        let hex_raw = parts[1].trim();
        let ext_raw = parts[2].trim();
        let class = parts[3].trim();
        let offset_str = parts[4].trim();

        if name.is_empty() || hex_raw.is_empty() || hex_raw == "(null)" { continue; }

        let hex: String = hex_raw.chars().filter(|c| !c.is_whitespace()).map(|c| c.to_ascii_uppercase()).collect();
        if hex.len() < 2 || hex.len() % 2 != 0 { continue; }
        if !hex.chars().all(|c| c.is_ascii_hexdigit()) { continue; }
        let hex_static = leak_str(hex);

        let offset: i64 = offset_str.parse().unwrap_or(0);
        let mime = class_to_mime(class);

        for ext in ext_raw.split('|') {
            let e = ext.trim();
            let ext_static = if e.is_empty() || e == "(null)" || e == "(none)" {
                None
            } else {
                Some(leak_str(if e.starts_with('.') { e.to_string() } else { format!(".{}", e) }))
            };
            sigs.push((name, mime, ext_static, offset, hex_static));
        }
    }

    // 2. Append supplementary entries. No dedup by hex — we want BOTH "PKZIP archive_1"
    // (from CSV) and "ZIP archive" (from suppl) so the scanner can find them by name.
    for (name, mime, ext, offset, hex) in supplementary_sigs() {
        sigs.push((name, mime, ext, offset, hex));
    }

    sigs
}

/// Seed the database with all built-in signatures.
/// Drops existing data first, then inserts the full set.
pub fn seed_database(conn: &Connection) -> Result<u32, rusqlite::Error> {
    drop_schema(conn)?;
    ensure_schema(conn)?;

    let sigs = seed_sigs();

    let mut count = 0u32;
    for (name, mime, ext, offset, hex) in &sigs {
        // ponytail: bump generic ZIP above formats that share the same magic (EPUB, APK, iWork)
        let priority = if *name == "ZIP archive" { 20 } else { 10 };
        conn.execute(
            "INSERT INTO signatures (name, mime, extension, source, priority) VALUES (?1, ?2, ?3, 'seed', ?4)",
            params![name, mime, ext, priority],
        )?;
        let sig_id = conn.last_insert_rowid();
        conn.execute(
            "INSERT INTO magic_patterns (signature_id, offset, hex_bytes, endianness) VALUES (?1, ?2, ?3, 'big')",
            params![sig_id, offset, hex],
        )?;
        count += 1;
    }

    Ok(count)
}

/// Look up signatures matching the given hex bytes at a given offset.
pub fn match_signatures(
    conn: &Connection,
    hex_bytes: &str,
    offset: u64,
) -> Result<Vec<Signature>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.name, s.mime, s.extension,
                mp.offset, mp.hex_bytes, mp.mask, mp.endianness
         FROM signatures s
         JOIN magic_patterns mp ON mp.signature_id = s.id
         WHERE mp.hex_bytes = ?1 AND mp.offset = ?2
         ORDER BY s.priority DESC"
    )?;

    let rows = stmt.query_map(params![hex_bytes, offset as i64], |row| {
        let sig_id: i64 = row.get(0)?;
        Ok((
            sig_id,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;

    let mut sig_map: std::collections::HashMap<i64, Signature> = std::collections::HashMap::new();
    for row in rows {
        let (id, name, mime, ext, pat_off, hex_b, mask, endi) = row?;
        let pat = MagicPattern { offset: pat_off, hex_bytes: hex_b, mask, endianness: endi };
        sig_map.entry(id)
            .and_modify(|s: &mut Signature| s.patterns.push(pat.clone()))
            .or_insert(Signature { id, name, mime, extension: ext, patterns: vec![pat] });
    }
    Ok(sig_map.into_values().collect())
}

/// Get all signatures — used for building the sidebar in hex view
pub fn list_signatures(conn: &Connection) -> Result<Vec<Signature>, rusqlite::Error> {
    let mut stmt = conn.prepare(
        "SELECT s.id, s.name, s.mime, s.extension,
                mp.offset, mp.hex_bytes, mp.mask, mp.endianness
         FROM signatures s
         JOIN magic_patterns mp ON mp.signature_id = s.id
         ORDER BY s.name"
    )?;

    let rows = stmt.query_map([], |row| {
        Ok((
            row.get::<_, i64>(0)?,
            row.get::<_, String>(1)?,
            row.get::<_, Option<String>>(2)?,
            row.get::<_, Option<String>>(3)?,
            row.get::<_, i64>(4)?,
            row.get::<_, String>(5)?,
            row.get::<_, Option<String>>(6)?,
            row.get::<_, String>(7)?,
        ))
    })?;

    let mut sig_map: std::collections::HashMap<i64, Signature> = std::collections::HashMap::new();
    for row in rows {
        let (id, name, mime, ext, pat_off, hex_b, mask, endi) = row?;
        let pat = MagicPattern { offset: pat_off, hex_bytes: hex_b, mask, endianness: endi };
        sig_map.entry(id)
            .and_modify(|s: &mut Signature| s.patterns.push(pat.clone()))
            .or_insert(Signature { id, name, mime, extension: ext, patterns: vec![pat] });
    }
    Ok(sig_map.into_values().collect())
}

/// Insert a signature + its patterns in a transaction
pub fn insert_signature(
    conn: &Connection,
    name: &str,
    mime: Option<&str>,
    extension: Option<&str>,
    source: Option<&str>,
    priority: i32,
    patterns: &[MagicPattern],
) -> Result<i64, rusqlite::Error> {
    conn.execute(
        "INSERT INTO signatures (name, mime, extension, source, priority) VALUES (?1, ?2, ?3, ?4, ?5)",
        params![name, mime, extension, source, priority],
    )?;
    let sig_id = conn.last_insert_rowid();
    for p in patterns {
        conn.execute(
            "INSERT INTO magic_patterns (signature_id, offset, hex_bytes, mask, endianness) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![sig_id, p.offset, p.hex_bytes, p.mask, p.endianness],
        )?;
    }
    Ok(sig_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_schema_creation_and_insert() {
        let conn = Connection::open_in_memory().unwrap();
        ensure_schema(&conn).unwrap();
        let patterns = vec![MagicPattern { offset: 0, hex_bytes: "504B0304".into(), mask: None, endianness: "little".into() }];
        let id = insert_signature(&conn, "ZIP archive", Some("application/zip"), Some(".zip"), Some("test"), 10, &patterns).unwrap();
        assert!(id > 0);
        let sigs = match_signatures(&conn, "504B0304", 0).unwrap();
        assert_eq!(sigs.len(), 1);
        assert_eq!(sigs[0].name, "ZIP archive");
    }

    #[test]
    fn test_seed_database() {
        let conn = Connection::open_in_memory().unwrap();
        let count = seed_database(&conn).unwrap();
        assert!(count > 400, "Should have at least 400 seed sigs from CSV, got {}", count);
        let sigs = list_signatures(&conn).unwrap();
        assert_eq!(sigs.len() as u32, count);
        let names: Vec<String> = sigs.iter().map(|s| s.name.clone()).collect();
        assert!(names.contains(&"PKZIP archive_1".to_string()));
        assert!(names.contains(&"PNG image".to_string()));
        assert!(names.contains(&"PDF file".to_string()));
    }
}
