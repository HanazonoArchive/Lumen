#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use std::sync::Mutex;
use tauri::State;
use lumen_engine::Engine;

struct AppState {
    engine: Mutex<Engine>,
}

#[tauri::command]
fn pick_file() -> Result<String, String> {
    let file = rfd::FileDialog::new()
        .set_title("Select a file to scan")
        .pick_file();
    match file {
        Some(path) => Ok(path.to_string_lossy().to_string()),
        None => Err("cancelled".to_string()),
    }
}

#[tauri::command]
fn pick_folder() -> Result<String, String> {
    let dir = rfd::FileDialog::new()
        .set_title("Select a folder to scan")
        .pick_folder();
    match dir {
        Some(path) => Ok(path.to_string_lossy().to_string()),
        None => Err("cancelled".to_string()),
    }
}

#[tauri::command]
fn scan_file(path: String, mode: String, segments: Option<u8>, deep_scan: Option<bool>, state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let n_segments = segments.unwrap_or(8).clamp(2, 64);
    let scan_mode = match mode.as_str() {
        "segmented" => lumen_engine::types::ScanMode::Segmented(n_segments),
        _ => lumen_engine::types::ScanMode::Quick,
    };
    let mut result = engine.scan_with_mode(std::path::Path::new(&path), scan_mode)?;
    // ponytail: strip children when deep_scan=false instead of threading flag through entire scanner
    if !deep_scan.unwrap_or(true) {
        for seg in &mut result.segments {
            seg.result.children.clear();
        }
        result.combined.children.clear();
    }
    serde_json::to_string_pretty(&result).map_err(|e| e.to_string())
}

#[tauri::command]
fn read_hex(path: String, offset: u64, len: usize, state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    engine.read_hex_at(std::path::Path::new(&path), offset, len)
}

#[tauri::command]
fn list_signatures(state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let sigs = engine.list_signatures()?;
    serde_json::to_string_pretty(&sigs).map_err(|e| e.to_string())
}

/// Rebuild the seed DB — drops all data and reseeds
#[tauri::command]
fn rebuild_seed_db(state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let count = lumen_engine::db::seed_database(engine.connection())
        .map_err(|e| e.to_string())?;
    Ok(format!("Rebuilt DB with {} signatures", count))
}

/// Fetch signatures from a remote source URL and insert into DB
#[tauri::command]
fn fetch_signatures(url: String, state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    // ponytail: fetch URL, parse JSON in format [{name, mime, ext, offset, hex}]
    let resp = ureq::get(&url)
        .set("User-Agent", "Lumen/0.1")
        .call()
        .map_err(|e| format!("HTTP error: {}", e))?;
    let text = resp.into_string().map_err(|e| format!("Read error: {}", e))?;
    let sigs: Vec<serde_json::Value> = serde_json::from_str(&text)
        .map_err(|e| format!("JSON parse error: {}", e))?;

    let mut count = 0u32;
    for sig in &sigs {
        let name = sig["name"].as_str().unwrap_or("Unknown");
        let mime = sig["mime"].as_str();
        let ext = sig["ext"].as_str();
        let offset = sig["offset"].as_i64().unwrap_or(0);
        let hex = sig["hex"].as_str().unwrap_or("");
        if hex.is_empty() { continue; }

        lumen_engine::db::insert_signature(
            engine.connection(),
            name, mime, ext, Some("remote"), 5,
            &[lumen_engine::types::MagicPattern {
                offset,
                hex_bytes: hex.to_uppercase(),
                mask: None,
                endianness: "big".to_string(),
            }],
        ).map_err(|e| format!("DB insert error: {}", e))?;
        count += 1;
    }
    Ok(format!("Imported {} signatures", count))
}

fn collect_files_recursive(dir: &std::path::Path, prefix: &str, files: &mut Vec<String>) {
    if let Ok(entries) = std::fs::read_dir(dir) {
        for entry in entries.flatten() {
            let path = entry.path();
            let rel_name = if prefix.is_empty() {
                entry.file_name().to_string_lossy().to_string()
            } else {
                format!("{}/{}", prefix, entry.file_name().to_string_lossy())
            };
            if path.is_file() {
                files.push(rel_name);
            } else if path.is_dir() {
                collect_files_recursive(&path, &rel_name, files);
            }
        }
    }
}

#[tauri::command]
fn list_folder_files(path: String, recursive: Option<bool>) -> Result<String, String> {
    let mut files = Vec::new();
    if recursive.unwrap_or(false) {
        collect_files_recursive(std::path::Path::new(&path), "", &mut files);
    } else if let Ok(entries) = std::fs::read_dir(&path) {
        for entry in entries.flatten() {
            if entry.path().is_file() {
                if let Some(name) = entry.file_name().to_str() {
                    files.push(name.to_string());
                }
            }
        }
    }
    serde_json::to_string(&files).map_err(|e| e.to_string())
}

#[tauri::command]
fn scan_folder(path: String, state: State<AppState>) -> Result<String, String> {
    let engine = state.engine.lock().map_err(|e| e.to_string())?;
    let mut results = Vec::new();

    if let Ok(entries) = std::fs::read_dir(&path) {
        for entry in entries.flatten() {
            let file_path = entry.path();
            if file_path.is_file() {
                match engine.scan_file(&file_path) {
                    Ok(res) => results.push(res),
                    Err(_) => {}
                }
            }
        }
    }

    serde_json::to_string_pretty(&results).map_err(|e| e.to_string())
}

fn resolve_db_path() -> std::path::PathBuf {
    // Primary: write to %LOCALAPPDATA%/Lumen/signatures.db (writable after MSI install)
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let app_dir = std::path::Path::new(&local).join("Lumen");
        let _ = std::fs::create_dir_all(&app_dir);
        let db = app_dir.join("signatures.db");
        // If it exists or we can't find another one, use this
        if db.exists() {
            return db;
        }
    }

    // Fallback: look for existing DB near the binary (dev mode)
    if let Ok(exe) = std::env::current_exe() {
        let exe_dir = exe.parent().unwrap_or_else(|| std::path::Path::new("."));
        for depth in &[0u32, 2u32] {
            let base = exe_dir.ancestors().nth(*depth as usize).unwrap_or(exe_dir);
            let db = base.join("signatures.db");
            if db.exists() { return db; }
        }
    }

    // Fallback: CWD
    let cwd = std::env::current_dir().unwrap_or_default();
    for depth in &[0u32, 1u32, 2u32] {
        let base = cwd.ancestors().nth(*depth as usize).unwrap_or(&cwd);
        let db = base.join("signatures.db");
        if db.exists() { return db; }
    }

    // Last resort: write to LOCALAPPDATA/Lumen/ (create if we didn't above)
    if let Ok(local) = std::env::var("LOCALAPPDATA") {
        let app_dir = std::path::Path::new(&local).join("Lumen");
        let _ = std::fs::create_dir_all(&app_dir);
        return app_dir.join("signatures.db");
    }

    std::path::PathBuf::from("signatures.db")
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    let db_path = resolve_db_path();
    let db_str = db_path.to_string_lossy().to_string();
    eprintln!("Lumen: using DB at {}", db_str);

    let engine = Engine::new(&db_str).expect("Failed to initialize engine");

    tauri::Builder::default()
        .manage(AppState {
            engine: Mutex::new(engine),
        })
        .invoke_handler(tauri::generate_handler![
            scan_file,
            read_hex,
            list_signatures,
            scan_folder,
            list_folder_files,
            fetch_signatures,
            rebuild_seed_db,
            pick_file,
            pick_folder,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

fn main() {
    run();
}
