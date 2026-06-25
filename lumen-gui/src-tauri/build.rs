fn main() {
    // Ensure 7z.exe (and optional 7z.dll) placeholders exist for Tauri resource validation.
    // The download-7z.ps1 script (run before `tauri build`) replaces them with real binaries.
    let res_dir = std::path::Path::new("../resources");
    std::fs::create_dir_all(res_dir).ok();
    for f in &["7z.exe", "7z.dll"] {
        let p = res_dir.join(f);
        if !p.exists() {
            std::fs::write(&p, "PLACEHOLDER").ok();
        }
    }
    tauri_build::build()
}
