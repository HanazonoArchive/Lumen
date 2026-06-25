// Quick smoke test — scans test files using the engine
fn main() {
    let db_path = std::env::args().nth(1).unwrap_or_else(|| "signatures.db".to_string());
    let engine = lumen_engine::Engine::new(&db_path).expect("Failed to init engine");

    let dir = std::env::current_dir().unwrap_or_default();

    let tests = vec![
        ("test_sample.zip", "ZIP archive"),
        ("test_sample.png", "PNG image"),
        ("test_sample.unk", "Unknown"),
    ];

    println!("Lumen Engine — Smoke Test");
    println!("DB: {} ({} sigs loaded)", db_path, engine.list_signatures().unwrap_or_default().len());
    println!("---");

    for (filename, expected) in &tests {
        let path = dir.join(filename);
        if !path.exists() {
            println!("SKIP {} — file not found at {:?}", filename, path);
            continue;
        }
        match engine.scan_file(&path) {
            Ok(response) => {
                let result = &response.combined;
                let status = if result.file_type.contains(expected) { "✓" } else { "✗" };
                println!("{} {} ({} bytes)", status, filename, response.total_size);
                println!("  Type: {} | MIME: {:?} | Ext: {:?}",
                    result.file_type, result.mime, result.extension);
                if result.children.len() > 0 {
                    println!("  Children: {}", result.children.len());
                    for child in &result.children {
                        println!("    - {} @ 0x{:X}", child.file_type, child.offset);
                    }
                }
                if !result.file_type.contains(expected) {
                    println!("  EXPECTED: {} | GOT: {}", expected, result.file_type);
                }
            }
            Err(e) => println!("✗ {} — ERROR: {}", filename, e),
        }
    }
}
