// Binary: fetch file signatures from DIE-engine GitHub + output bundled sigs as JSON
// Usage: cargo run -p lumen-engine --bin lumen-fetch [output.json]

const DIE_SIG_URL: &str = "https://api.github.com/repos/horsicq/DIE-engine/contents/source/signatures";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("Lumen Signature Fetcher");
        eprintln!("Usage: {} [output.json]", args[0]);
        eprintln!("  Fetches signatures from DIE-engine GitHub + embedded sigs.");
        return;
    }

    let out_file = if args.len() > 1 { Some(&args[1]) } else { None };

    let mut all_sigs: Vec<serde_json::Value> = Vec::new();

    // Source 1: DIE-engine JSON signatures
    match fetch_die_signatures() {
        Ok(sigs) => {
            eprintln!("DIE-engine: {} signatures", sigs.len());
            all_sigs.extend(sigs);
        }
        Err(e) => eprintln!("DIE-engine: {} — skipping", e),
    }

    // Source 2: embedded seed signatures (single source of truth in db.rs)
    let embedded = lumen_engine::db::seed_sigs();
    eprintln!("Embedded: {} signatures", embedded.len());
    for (name, mime, ext, offset, hex) in &embedded {
        all_sigs.push(serde_json::json!({
            "name": name,
            "mime": mime,
            "ext": ext,
            "offset": offset,
            "hex": hex,
        }));
    }

    // Deduplicate by hex+offset
    let mut seen = std::collections::HashSet::new();
    all_sigs.retain(|s| {
        let key = format!("{}@{}", s["hex"].as_str().unwrap_or(""), s["offset"].as_i64().unwrap_or(0));
        seen.insert(key)
    });

    let json = serde_json::to_string_pretty(&all_sigs).unwrap_or_default();

    if let Some(path) = out_file {
        std::fs::write(path, &json).expect("Failed to write output file");
        eprintln!("Wrote {} signatures to {}", all_sigs.len(), path);
    } else {
        println!("{}", json);
        eprintln!("Total: {} unique signatures", all_sigs.len());
    }
}

fn fetch_die_signatures() -> Result<Vec<serde_json::Value>, String> {
    let mut result = Vec::new();

    let resp = ureq::get(DIE_SIG_URL)
        .set("User-Agent", "lumen/0.1")
        .set("Accept", "application/vnd.github.v3+json")
        .call()
        .map_err(|e| format!("HTTP: {}", e))?;

    let body = resp.into_string().map_err(|e| format!("Read: {}", e))?;
    let files: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| format!("JSON: {}", e))?;

    for file in &files {
        let name = file["name"].as_str().unwrap_or("");
        let download_url = file["download_url"].as_str().unwrap_or("");

        if !name.ends_with(".sig") || download_url.is_empty() {
            continue;
        }

        eprintln!("  Fetching {}...", name);
        match download_sig_file(download_url) {
            Ok(sigs) => result.extend(sigs),
            Err(e) => eprintln!("  {}: {}", name, e),
        }
    }

    Ok(result)
}

fn download_sig_file(url: &str) -> Result<Vec<serde_json::Value>, String> {
    let resp = ureq::get(url)
        .set("User-Agent", "lumen/0.1")
        .call()
        .map_err(|e| format!("HTTP: {}", e))?;

    let body = resp.into_string().map_err(|e| format!("Read: {}", e))?;
    let sigs: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| format!("JSON parse: {}", e))?;

    let mut result = Vec::new();
    for sig in &sigs {
        let name = sig["name"].as_str().unwrap_or("Unknown");
        let hex = sig["hex"].as_str().unwrap_or("");
        let offset = sig["offset"].as_i64().unwrap_or(0);

        if hex.is_empty() { continue; }
        let hex_clean = hex.replace(" ", "").replace("-", "").to_uppercase();
        if hex_clean.chars().any(|c| !"0123456789ABCDEF".contains(c)) {
            continue;
        }

        result.push(serde_json::json!({
            "name": name,
            "mime": serde_json::Value::Null,
            "ext": serde_json::Value::Null,
            "offset": offset,
            "hex": hex_clean,
        }));
    }

    Ok(result)
}
