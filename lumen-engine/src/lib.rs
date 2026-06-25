pub mod db;
pub mod scanner;
pub mod types;

use std::path::Path;

use rusqlite::Connection;

use crate::types::*;

/// Initialize the engine with a database path
pub struct Engine {
    conn: Connection,
}

impl Engine {
    /// Open (or create) the signature DB at the given path
    pub fn new(db_path: &str) -> Result<Self, String> {
        let conn = db::open_db(db_path).map_err(|e| e.to_string())?;
        db::ensure_schema(&conn).map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    /// Scan a file — auto-detects quick vs segmented mode
    pub fn scan_file(&self, path: &Path) -> Result<ScanResponse, String> {
        scanner::scan_file_auto(&self.conn, path)
    }

    /// Scan with explicit mode
    pub fn scan_with_mode(&self, path: &Path, mode: ScanMode) -> Result<ScanResponse, String> {
        scanner::scan_file(&self.conn, path, mode)
    }

    /// Quick header-only scan
    pub fn quick_scan(&self, path: &Path) -> Result<ScanResult, String> {
        scanner::quick_scan(&self.conn, path)
    }

    /// Read hex bytes at offset
    pub fn read_hex_at(&self, path: &Path, offset: u64, len: usize) -> Result<String, String> {
        scanner::read_hex_at(path, offset, len).map_err(|e| e.to_string())
    }

    /// List all signatures in DB (for hex sidebar)
    pub fn list_signatures(&self) -> Result<Vec<Signature>, String> {
        db::list_signatures(&self.conn).map_err(|e| e.to_string())
    }

    /// Get raw DB connection (for advanced operations)
    pub fn connection(&self) -> &Connection {
        &self.conn
    }
}
