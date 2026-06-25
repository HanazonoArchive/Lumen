// Binary: fetch file signatures from DIE-engine GitHub + other public sources
// Outputs JSON array of {name, mime, ext, offset, hex}
// Pipe output into lumen-gui's fetch_signatures or use directly

const DIE_SIG_URL: &str = "https://api.github.com/repos/horsicq/DIE-engine/contents/source/signatures";

fn main() {
    let args: Vec<String> = std::env::args().collect();
    if args.len() > 1 && (args[1] == "-h" || args[1] == "--help") {
        eprintln!("Lumen Signature Fetcher");
        eprintln!("Usage: {} [output.json]", args[0]);
        eprintln!("  Fetches signatures from DIE-engine GitHub and outputs JSON.");
        eprintln!("  If output.json is given, writes to file; otherwise prints to stdout.");
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

    // Source 2: embedded comprehensive list
    let embedded = generate_embedded_sigs();
    eprintln!("Embedded: {} signatures", embedded.len());
    all_sigs.extend(embedded);

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

    // List files in the DIE signatures directory
    let resp = ureq::get(DIE_SIG_URL)
        .set("User-Agent", "lumen/0.1")
        .set("Accept", "application/vnd.github.v3+json")
        .call()
        .map_err(|e| format!("HTTP: {}", e))?;

    let body = resp.into_string().map_err(|e| format!("Read: {}", e))?;
    let files: Vec<serde_json::Value> = serde_json::from_str(&body)
        .map_err(|e| format!("JSON: {}", e))?;

    // Download each .sig file
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
        // Only hex chars
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

fn generate_embedded_sigs() -> Vec<serde_json::Value> {
    let data: Vec<(&str, Option<&str>, Option<&str>, i64, &str)> = vec![
        ("ZIP archive", Some("application/zip"), Some(".zip"), 0, "504B0304"),
        ("ZIP archive (empty)", Some("application/zip"), Some(".zip"), 0, "504B0506"),
        ("ZIP archive (spanned)", Some("application/zip"), Some(".zip"), 0, "504B0708"),
        ("RAR archive v1.5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A0700"),
        ("RAR archive v5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A070100"),
        ("7-Zip archive", Some("application/x-7z-compressed"), Some(".7z"), 0, "377ABCAF271C"),
        ("GZIP compressed", Some("application/gzip"), Some(".gz"), 0, "1F8B08"),
        ("BZIP2 compressed", Some("application/x-bzip2"), Some(".bz2"), 0, "425A68"),
        ("XZ compressed", Some("application/x-xz"), Some(".xz"), 0, "FD377A585A00"),
        ("TAR POSIX archive", Some("application/x-tar"), Some(".tar"), 257, "757374617200"),
        ("LZ4 compressed", Some("application/x-lz4"), Some(".lz4"), 0, "04224D18"),
        ("CAB archive", Some("application/vnd.ms-cab-compressed"), Some(".cab"), 0, "4D534346"),
        ("ARJ archive", Some("application/x-arj"), Some(".arj"), 0, "60EA"),
        ("Brotli compressed", Some("application/brotli"), Some(".br"), 0, "CEB2CF81"),
        ("SquashFS", Some("application/x-squashfs"), Some(".squashfs"), 0, "68737173"),
        ("Zstandard", Some("application/zstd"), Some(".zst"), 0, "28B52FFD"),
        ("PNG image", Some("image/png"), Some(".png"), 0, "89504E470D0A1A0A"),
        ("JPEG image", Some("image/jpeg"), Some(".jpg"), 0, "FFD8FF"),
        ("JPEG Exif", Some("image/jpeg"), Some(".jpg"), 0, "FFD8FFE1"),
        ("GIF89a", Some("image/gif"), Some(".gif"), 0, "474946383961"),
        ("GIF87a", Some("image/gif"), Some(".gif"), 0, "474946383761"),
        ("BMP image", Some("image/bmp"), Some(".bmp"), 0, "424D"),
        ("WebP image", Some("image/webp"), Some(".webp"), 0, "52494646"),
        ("TIFF little-endian", Some("image/tiff"), Some(".tiff"), 0, "49492A00"),
        ("TIFF big-endian", Some("image/tiff"), Some(".tiff"), 0, "4D4D002A"),
        ("ICO icon", Some("image/x-icon"), Some(".ico"), 0, "00000100"),
        ("Photoshop PSD", Some("image/vnd.adobe.photoshop"), Some(".psd"), 0, "38425053"),
        ("GIMP XCF", Some("image/x-xcf"), Some(".xcf"), 0, "67696D702078636620"),
        ("HEIC image", Some("image/heif"), Some(".heic"), 4, "6674797068656963"),
        ("AVIF image", Some("image/avif"), Some(".avif"), 4, "6674797061766966"),
        ("JPEG 2000 JP2", Some("image/jp2"), Some(".jp2"), 0, "0000000C6A502020"),
        ("OpenEXR image", Some("image/x-exr"), Some(".exr"), 0, "762F3101"),
        ("KTX2 texture", Some("image/ktx2"), Some(".ktx2"), 0, "AB4B5458203230"),
        ("DDS texture", Some("image/vnd.ms-dds"), Some(".dds"), 0, "44445320"),
        ("QOI image", Some("image/qoi"), Some(".qoi"), 0, "716F6966"),
        ("Canon CR2 raw", Some("image/x-canon-cr2"), Some(".cr2"), 0, "49492A00100000004352"),
        ("Nikon NEF raw", Some("image/x-nikon-nef"), Some(".nef"), 0, "4D4D002A"),
        ("Sony ARW raw", Some("image/x-sony-arw"), Some(".arw"), 0, "49492A00"),
        ("PE executable", Some("application/x-msdownload"), Some(".exe"), 0, "4D5A"),
        ("LE executable (OS/2)", Some("application/x-msdownload"), Some(".exe"), 0, "4C45"),
        ("ELF 32-bit LSB", Some("application/x-elf"), None, 0, "7F454C4601010100"),
        ("ELF 64-bit LSB", Some("application/x-elf"), None, 0, "7F454C4602010100"),
        ("Mach-O 32-bit LE", Some("application/x-mach-binary"), None, 0, "FEEDFACE"),
        ("Mach-O 64-bit LE", Some("application/x-mach-binary"), None, 0, "FEEDFACF"),
        ("Mach-O Universal", Some("application/x-mach-binary"), None, 0, "CAFEBABE"),
        ("COFF object (x86)", Some("application/x-coff"), Some(".o"), 0, "4C01"),
        ("PDF document", Some("application/pdf"), Some(".pdf"), 0, "255044462D"),
        ("OLE2 Compound", Some("application/x-ole-storage"), Some(".doc"), 0, "D0CF11E0A1B11AE1"),
        ("RTF document", Some("application/rtf"), Some(".rtf"), 0, "7B5C72746631"),
        ("PostScript", Some("application/postscript"), Some(".ps"), 0, "25215053"),
        ("DjVu document", Some("image/vnd.djvu"), Some(".djvu"), 0, "41542654464F524D"),
        ("CHM help", Some("application/x-chm"), Some(".chm"), 0, "49545346"),
        ("WAV audio", Some("audio/wav"), Some(".wav"), 0, "52494646"),
        ("MP3 ID3v2", Some("audio/mpeg"), Some(".mp3"), 0, "494433"),
        ("MP3 MPEG v1", Some("audio/mpeg"), Some(".mp3"), 0, "FFFB"),
        ("FLAC audio", Some("audio/flac"), Some(".flac"), 0, "664C6143"),
        ("OGG audio", Some("audio/ogg"), Some(".ogg"), 0, "4F676753"),
        ("Opus audio", Some("audio/opus"), Some(".opus"), 0, "4F676753"),
        ("MIDI audio", Some("audio/midi"), Some(".mid"), 0, "4D546864"),
        ("AIFF audio", Some("audio/aiff"), Some(".aiff"), 0, "464F524D"),
        ("AAC", Some("audio/aac"), Some(".aac"), 0, "FFF1"),
        ("AC-3 Dolby Digital", Some("audio/ac3"), Some(".ac3"), 0, "0B77"),
        ("WMA audio", Some("audio/x-ms-wma"), Some(".wma"), 0, "3026B2758E66CF11"),
        ("Monkey's Audio", Some("audio/x-ape"), Some(".ape"), 0, "4D414320"),
        ("TrueAudio TTA", Some("audio/x-tta"), Some(".tta"), 0, "54544131"),
        ("AMR audio", Some("audio/amr"), Some(".amr"), 0, "2321414D52"),
        ("MP4 video", Some("video/mp4"), Some(".mp4"), 4, "66747970"),
        ("QuickTime MOV", Some("video/quicktime"), Some(".mov"), 4, "667479706D6F6F76"),
        ("AVI video", Some("video/x-msvideo"), Some(".avi"), 0, "52494646"),
        ("Matroska MKV", Some("video/x-matroska"), Some(".mkv"), 0, "1A45DFA3"),
        ("WebM video", Some("video/webm"), Some(".webm"), 0, "1A45DFA3"),
        ("WMV video", Some("video/x-ms-wmv"), Some(".wmv"), 0, "3026B2758E66CF11"),
        ("FLV video", Some("video/x-flv"), Some(".flv"), 0, "464C5601"),
        ("Flash SWF", Some("application/x-shockwave-flash"), Some(".swf"), 0, "465753"),
        ("MPEG-1 System", Some("video/mpeg"), Some(".mpg"), 0, "000001BA"),
        ("MPEG-2 TS", Some("video/mp2t"), Some(".ts"), 0, "47"),
        ("3GPP video", Some("video/3gpp"), Some(".3gp"), 4, "66747970336770"),
        ("Bink video", Some("video/x-bink"), Some(".bik"), 0, "42494B"),
        ("DV video", Some("video/x-dv"), Some(".dv"), 0, "1F0700"),
        ("H.264 NAL", Some("video/h264"), Some(".h264"), 0, "00000001"),
        ("HEVC/H.265 NAL", Some("video/hevc"), Some(".h265"), 0, "00000001"),
        ("TrueType font", Some("font/ttf"), Some(".ttf"), 0, "0001000000"),
        ("OpenType font", Some("font/otf"), Some(".otf"), 0, "4F54544F"),
        ("WOFF font", Some("font/woff"), Some(".woff"), 0, "774F4646"),
        ("WOFF2 font", Some("font/woff2"), Some(".woff2"), 0, "774F4632"),
        ("ISO 9660 CD", Some("application/x-iso9660-image"), Some(".iso"), 32769, "4344303031"),
        ("NTFS filesystem", Some("application/x-ntfs"), None, 3, "4E54465320202020"),
        ("ext2/3/4 filesystem", Some("application/x-ext4"), None, 1080, "53EF"),
        ("VHD disk image", Some("application/x-vhd"), Some(".vhd"), 0, "636F6E6563746978"),
        ("VHDX disk image", Some("application/x-vhdx"), Some(".vhdx"), 0, "7668647866696C65"),
        ("VMDK disk", Some("application/x-vmdk"), Some(".vmdk"), 0, "4B444D"),
        ("Apple DMG", Some("application/x-apple-diskimage"), Some(".dmg"), 0, "7801730D626260"),
        ("QEMU QCOW2", Some("application/x-qcow2"), Some(".qcow2"), 0, "514649FB"),
        ("SQLite3 database", Some("application/x-sqlite3"), Some(".sqlite"), 0, "53514C69746520666F726D6174203300"),
        ("SQLite3 WAL", Some("application/x-sqlite3"), Some(".sqlite-wal"), 0, "377F0682"),
        ("Java class file", Some("application/java-vm"), Some(".class"), 0, "CAFEBABE"),
        ("Dalvik DEX", Some("application/x-dex"), Some(".dex"), 0, "6465780A"),
        ("WebAssembly WASM", Some("application/wasm"), Some(".wasm"), 0, "0061736D"),
        ("Lua bytecode", Some("application/x-lua-bytecode"), Some(".luac"), 0, "1B4C7561"),
        ("Python bytecode 3.3+", Some("application/x-python-bytecode"), Some(".pyc"), 0, "42"),
        ("X.509 DER cert", Some("application/pkix-cert"), Some(".cer"), 0, "3082"),
        ("PKCS#12 PFX", Some("application/x-pkcs12"), Some(".pfx"), 0, "3084"),
        ("OpenPGP public key", Some("application/pgp-keys"), Some(".asc"), 0, "2D2D2D2D2D424547494E2050"),
        ("PCAP (LE)", Some("application/vnd.tcpdump.pcap"), Some(".pcap"), 0, "D4C3B2A1"),
        ("PCAP (BE)", Some("application/vnd.tcpdump.pcap"), Some(".pcap"), 0, "A1B2C3D4"),
        ("PCAPNG capture", Some("application/vnd.tcpdump.pcap"), Some(".pcapng"), 0, "0A0D0D0A"),
        ("Android boot img", Some("application/x-android-boot"), Some(".img"), 0, "414E44524F494421"),
        ("Windows LNK shortcut", Some("application/x-ms-shortcut"), Some(".lnk"), 0, "4C00000001140200"),
        ("Windows registry hive", Some("application/x-ms-registry"), None, 0, "72656766"),
        ("Windows EVTX log", Some("application/x-ms-evtx"), Some(".evtx"), 0, "456C6646696C65"),
        ("Windows Minidump", Some("application/x-ms-minidump"), Some(".dmp"), 0, "4D444D5093A7"),
        ("RPM package", Some("application/x-rpm"), Some(".rpm"), 0, "EDABEEDB"),
        ("DEB package", Some("application/vnd.debian.binary-package"), Some(".deb"), 0, "213C617263683E"),
        ("MSI installer", Some("application/x-msi"), Some(".msi"), 0, "D0CF11E0A1B11AE1"),
        ("Nintendo NES ROM", Some("application/x-nintendo-nes-rom"), Some(".nes"), 0, "4E45531A"),
        ("Nintendo 64 ROM", Some("application/x-nintendo-64-rom"), Some(".z64"), 0, "80371240"),
        ("Nintendo DS ROM", Some("application/x-nintendo-ds-rom"), Some(".nds"), 0, "00010000"),
        ("Nintendo GBA ROM", Some("application/x-nintendo-gba-rom"), Some(".gba"), 0, "00008000"),
        ("Sega Genesis ROM", Some("application/x-sega-genesis-rom"), Some(".md"), 0, "00000800"),
    ];

    data.into_iter().map(|(name, mime, ext, offset, hex)| {
        serde_json::json!({
            "name": name,
            "mime": mime,
            "ext": ext,
            "offset": offset,
            "hex": hex,
        })
    }).collect()
}
