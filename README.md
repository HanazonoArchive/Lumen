# Lumen — RE File Identifier

Reverse engineering tool that identifies file types by scanning magic bytes/signatures. Takes any file (unknown/weird extensions), reads hex bytes, matches against a signature database (SQLite), and reports file type, compression, and container contents.

Built by [HanazonoArchive](https://github.com/HanazonoArchive).

---

## Features

- **Single file scan** — drop or select any file, get instant type identification
- **Segmented scan** — large files divided into adaptive segments (4/8/16), scanned with overlap to catch multi-type files
- **Batch scan** — scan entire folders with checkboxes, batch progress, identified counts
- **Hex inspector** — full hex view with signature highlighting, signature sidebar for quick navigation
- **Container detection** — detects embedded files inside ZIP, RAR, 7z, and other archives
- **Plain text detection** — identifies JSON, XML, HTML, scripts, and plain text files without magic signatures
- **Signature database** — SQLite-based, 200+ built-in signatures, rebuildable, extensible via web import
- **Tauri + Rust** — fast native GUI, safe binary parsing, cross-platform

---

## Requirements

- [Rust](https://rustup.rs/) (1.70+)
- [Node.js](https://nodejs.org/) (18+)
- npm

## Quick Start

```bash
# 1. Clone
git clone https://github.com/HanazonoArchive/lumen.git
cd lumen

# 2. Seed signature database
cargo run -p lumen-engine --bin lumen-seed -- signatures.db

# 3. Run GUI
cd lumen-gui
npm install
npx tauri dev
```

### From Git Bash / MINGW64 (cargo PATH fix)

```bash
cd "c:/path/to/lumen/lumen-gui"
export PATH="$HOME/.cargo/bin:$PATH"
npx tauri dev
```

### From PowerShell

```powershell
# First time: add cargo to PATH permanently
[Environment]::SetEnvironmentVariable("Path", [Environment]::GetEnvironmentVariable("Path", [EnvironmentVariableTarget::User]) + ";$env:USERPROFILE\.cargo\bin", [EnvironmentVariableTarget::User])
# Restart PowerShell, then:
cd C:\path\to\lumen\lumen-gui
npx tauri dev
```

### Build for production

```bash
cd lumen-gui
npx tauri build
```

---

## Signature Database

Lumen ships with **221 built-in file signatures** across these categories:

| Category | # of sigs |
|---|---|
| Archives / Compression | 28 |
| Images / Raw photos | 31 |
| Executables / Binaries | 17 |
| Documents / Markup | 18 |
| Audio | 19 |
| Video | 20 |
| Fonts | 7 |
| Disk images / Filesystems | 13 |
| Databases | 10 |
| VM / Bytecode | 6 |
| Certificates / Crypto | 9 |
| Network / Capture | 3 |
| Android / Mobile | 2 |
| CAD / 3D | 8 |
| Game ROMs / Console | 6 |
| Windows system | 4 |
| Packages / Installers | 3 |
| GIS / Geospatial | 2 |
| Science / Engineering | 3 |
| Scripts | 4 |

### Rebuild seed DB

Click **Rebuild Seed DB** in the _db tab, or run:

```bash
cargo run -p lumen-engine --bin lumen-seed -- signatures.db
```

### Import from web

Set a URL in the _db tab's **Remote URL** field pointing to a JSON array of signatures:

```json
[
  {
    "name": "My Format",
    "mime": "application/x-my-format",
    "ext": ".myf",
    "offset": 0,
    "hex": "ABCD1234"
  }
]
```

Then click **Update from Web**.

### Scrape more signatures

Lumen includes a fetcher tool to scrape public sources:

```bash
# Generate a JSON file from embedded + DIE-engine sources
cargo run -p lumen-engine --bin lumen-fetch -- sigs.json
```

**External sources for file signatures:**

| Source | URL | Format |
|---|---|---|
| DIE-engine | https://github.com/horsicq/DIE-engine | JSON (.sig) |
| Gary Kessler | https://www.garykessler.net/library/file_sigs.html | HTML table |
| Wikipedia | https://en.wikipedia.org/wiki/List_of_file_signatures | Wiki table |
| FreeDesktop | https://gitlab.freedesktop.org/xdg/shared-mime-info | XML |
| `file` command | `file -m /usr/share/misc/magic` (on Linux) | magic(5) format |

To add your own, modify `lumen-engine/src/db.rs` → `seed_sigs()` function and re-seed.

---

## Project Structure

```
lumen/
├── Cargo.toml                 # workspace root
├── signatures.db              # SQLite signature database (generated)
├── .gitignore
├── README.md
├── lumen-engine/              # core engine lib (no Tauri dependency)
│   ├── src/
│   │   ├── lib.rs             # Engine API
│   │   ├── types.rs           # ScanResult, Signature, etc.
│   │   ├── scanner.rs         # quick scan + segmented scan + text detection
│   │   └── db.rs              # SQLite schema, queries, seed data
│   └── src/bin/
│       ├── seed_db.rs         # seed DB generator
│       ├── test_scan.rs       # engine smoke test
│       └── fetch_sigs.rs      # web signature fetcher
├── lumen-gui/                 # Tauri v2 GUI
│   ├── src/
│   │   ├── index.html         # 4-tab UI (_scan/_batch/_hex/_db)
│   │   ├── styles.css         # dark editor theme
│   │   └── app.js             # UI logic
│   ├── src-tauri/
│   │   └── src/main.rs        # Tauri commands (file IO, dialogs, DB)
│   └── package.json
```

---

## Tech Stack

- **Rust engine** — binary parsing, SQLite via rusqlite, buffered IO
- **Tauri v2** — native window, file dialogs via rfd, HTTP via ureq
- **HTML/CSS/JS** — vanilla frontend (no framework), dark code editor theme
- **SQLite** — portable signature database, bundled

---

## License

MIT
