# Lumen — RE File Identifier

Identify file types by scanning magic bytes. Takes any file, reads hex, matches against 700+ signatures (GCK File Signature Table), reports file type. Extracts containers and inspects hex on demand.

Built by [HanazonoArchive](https://github.com/HanazonoArchive).

---

## Quick Start

```bash
# 1. Seed signature DB
cargo run -p lumen-engine --bin lumen-seed

# 2. Launch GUI
cd lumen-gui
npm run tauri dev
```

Requirements: [Rust](https://rustup.rs/) 1.70+, [Node.js](https://nodejs.org/) 18+, WebView2 (pre-installed on Windows 10+).

---

## Commands

| What | Command |
|------|---------|
| **Run GUI (dev)** | `cd lumen-gui && npx @tauri-apps/cli dev` |
| **Build MSI installer (build)** | `cd lumen-gui && npm run tauri build` |
| **Seed signature DB** | `cargo run -p lumen-engine --bin lumen-seed` |
| **Check engine compiles** | `cargo check -p lumen-engine` |
| **Check GUI compiles** | `cargo check -p lumen-gui` |
| **Run engine tests** | `cargo test -p lumen-engine` |
| **Full rebuild (1st)** | `cd lumen gui && cargo build --workspace` |
| **Fetch sigs from web** | `cargo run -p lumen-engine --bin lumen-fetch` |

> `cargo tauri build` also works if you installed `cargo-tauri` globally.
> `npm run tauri build` uses the local project copy — no global install needed.

---

## Project Structure

```
lumen/
├── Cargo.toml                  # workspace root
├── signatures.db               # SQLite DB (created by lumen-seed)
├── lumen-engine/               # core library (no GUI deps)
│   ├── Cargo.toml
│   └── src/
│       ├── lib.rs              # Engine API
│       ├── types.rs            # ScanResult, Signature, ScanMode
│       ├── scanner.rs          # scanning, extraction, disambiguation
│       ├── db.rs               # SQLite schema, queries, CSV seed
│       ├── sigs.csv            # GCK File Signature Table (615+ entries)
│       └── bin/
│           ├── seed_db.rs      # re-seed signatures.db
│           ├── test_scan.rs    # CLI smoke test
│           └── fetch_sigs.rs   # web signature fetcher
└── lumen-gui/                  # Tauri v2 desktop GUI
    ├── download-7z.ps1         # 7z.exe download script
    ├── package.json            # node deps (@tauri-apps/cli + http-server)
    └── src/
        ├── index.html          # 5-tab UI
        ├── app.js              # UI logic
        └── styles.css          # dark editor theme
    └── src-tauri/
        └── src/main.rs         # Tauri commands (scan, read hex, etc.)
```

---

## Feature Overview

**Scan modes:**
- **Quick** — reads first 8KB, matches at standard offsets (0, 4, 8, 16, 32, 64, 128, 256, 512, 1024)
- **Segmented** — files >16MB split into overlapping chunks, scanned independently

**Container extraction** (recursive):

| Format | Backend |
|--------|---------|
| ZIP (+ APK, EPUB, DOCX, JAR, iWork) | `zip` crate (native) |
| TAR | `tar` crate (native) |
| 7z | `sevenz-rust` crate (native) |
| RAR, CAB, ISO, ARJ, etc. | `7z.exe` (external) |

ZIP-based formats (`504B0304`) are **disambiguated by content** — the scanner peeks inside entry names to tell APK from EPUB from DOCX from JAR.

**5-tab GUI:** scan single file, batch scan folder, hex inspector (offset jump + search), signature DB browser (rebuild + fetch remote), embedded CLI terminal.

---

## 7-Zip Setup (for RAR / CAB / ISO)

Lumen uses `7z.exe` for formats without a native Rust decoder. Run once:

```bash
cd lumen-gui
powershell -ExecutionPolicy Bypass -File download-7z.ps1
```

At runtime Lumen checks (in order): bundled `resources/7z.exe`, PATH, `C:\Program Files\7-Zip\`.

If 7z.exe is not available, unsupported formats fall back to a probe scan (no extraction).

---

## Signature Database

- **700+ signatures** from the [Gary Kessler File Signature Table](https://www.garykessler.net/library/file_sigs.html)
- Stored as `lumen-engine/src/sigs.csv`, embedded at compile time via `include_str!()`
- Auto-seeds on first launch if DB is empty
- Re-seed: click **Rebuild Seed DB** in the _db tab, or run `cargo run -p lumen-engine --bin lumen-seed`
- Import remote sigs: set URL in _db tab → **Update from Web** (expects JSON: `[{name, mime, ext, offset, hex}]`)

---

## Tech Stack

- **Rust** — binary parsing, SQLite (rusqlite), ZIP/tar/7z extraction
- **Tauri v2** — native window, file dialogs (rfd), HTTP (ureq)
- **Vanilla HTML/CSS/JS** — no framework, dark editor theme
- **SQLite** — portable signature DB

## License

MIT
