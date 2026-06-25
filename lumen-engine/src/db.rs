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

type SigDef = (&'static str, Option<&'static str>, Option<&'static str>, i64, &'static str);

fn seed_sigs() -> Vec<SigDef> {
    vec![
        ("ZIP archive", Some("application/zip"), Some(".zip"), 0, "504B0304"),
        ("ZIP empty archive", Some("application/zip"), Some(".zip"), 0, "504B0506"),
        ("ZIP spanned archive", Some("application/zip"), Some(".zip"), 0, "504B0708"),
        ("RAR archive v1.5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A0700"),
        ("RAR archive v5", Some("application/vnd.rar"), Some(".rar"), 0, "526172211A070100"),
        ("7-Zip archive", Some("application/x-7z-compressed"), Some(".7z"), 0, "377ABCAF271C"),
        ("GZIP compressed", Some("application/gzip"), Some(".gz"), 0, "1F8B08"),
        ("BZIP2 compressed", Some("application/x-bzip2"), Some(".bz2"), 0, "425A68"),
        ("XZ compressed", Some("application/x-xz"), Some(".xz"), 0, "FD377A585A00"),
        ("TAR POSIX archive", Some("application/x-tar"), Some(".tar"), 257, "757374617200"),
        ("TAR GNU archive", Some("application/x-tar"), Some(".tar"), 257, "757374617220"),
        ("Zstandard compressed", Some("application/zstd"), Some(".zst"), 0, "28B52FFD"),
        ("LZ4 compressed", Some("application/x-lz4"), Some(".lz4"), 0, "04224D18"),
        ("CAB archive", Some("application/vnd.ms-cab-compressed"), Some(".cab"), 0, "4D534346"),
        ("Unix AR archive", Some("application/x-archive"), Some(".a"), 0, "213C617263683E0A"),
        ("ARJ archive", Some("application/x-arj"), Some(".arj"), 0, "60EA"),
        ("LHA/LZH archive", Some("application/x-lzh"), Some(".lzh"), 0, "2D6C68"),
        ("StuffIt SIT archive", Some("application/x-stuffit"), Some(".sit"), 0, "5374756666497421"),
        ("InstallShield CAB", Some("application/vnd.ms-cab-compressed"), Some(".cab"), 0, "49534328"),
        ("Brotli compressed", Some("application/brotli"), Some(".br"), 0, "CEB2CF81"),
        ("WIM archive", Some("application/x-ms-wim"), Some(".wim"), 0, "4D534F52"),
        ("Snappy framed", Some("application/x-snappy"), None, 0, "FF0600736E617037"),
        ("LZ4 legacy", Some("application/x-lz4"), Some(".lz4"), 0, "02214C18"),
        ("Zstd skippable frame", Some("application/zstd"), Some(".zst"), 0, "18422A18"),
        ("SquashFS (LE)", Some("application/x-squashfs"), Some(".squashfs"), 0, "68737173"),
        ("SquashFS (BE)", Some("application/x-squashfs"), Some(".squashfs"), 0, "73717368"),
        ("ROMFS filesystem", Some("application/x-romfs"), Some(".romfs"), 0, "2D726F6D31"),
        ("CPIO archive", Some("application/x-cpio"), Some(".cpio"), 0, "3037303730"),
        ("PNG image", Some("image/png"), Some(".png"), 0, "89504E470D0A1A0A"),
        ("JPEG image", Some("image/jpeg"), Some(".jpg"), 0, "FFD8FF"),
        ("JPEG Exif", Some("image/jpeg"), Some(".jpg"), 0, "FFD8FFE1"),
        ("JPEG JFIF", Some("image/jpeg"), Some(".jpg"), 0, "FFD8FFE0"),
        ("GIF87a", Some("image/gif"), Some(".gif"), 0, "474946383761"),
        ("GIF89a", Some("image/gif"), Some(".gif"), 0, "474946383961"),
        ("BMP image", Some("image/bmp"), Some(".bmp"), 0, "424D"),
        ("WebP image (RIFF)", Some("image/webp"), Some(".webp"), 0, "52494646"),
        ("TIFF little-endian", Some("image/tiff"), Some(".tiff"), 0, "49492A00"),
        ("TIFF big-endian", Some("image/tiff"), Some(".tiff"), 0, "4D4D002A"),
        ("ICO icon", Some("image/vnd.microsoft.icon"), Some(".ico"), 0, "00000100"),
        ("CUR cursor", Some("image/x-win-bitmap"), Some(".cur"), 0, "00000200"),
        ("Photoshop PSD", Some("image/vnd.adobe.photoshop"), Some(".psd"), 0, "38425053"),
        ("GIMP XCF", Some("image/x-xcf"), Some(".xcf"), 0, "67696D702078636620"),
        ("HEIC image (heix)", Some("image/heif"), Some(".heic"), 4, "6674797068656978"),
        ("AVIF image (avif)", Some("image/avif"), Some(".avif"), 4, "6674797061766966"),
        ("DDS texture", Some("image/vnd.ms-dds"), Some(".dds"), 0, "44445320"),
        ("JPEG 2000 JP2", Some("image/jp2"), Some(".jp2"), 0, "0000000C6A502020"),
        ("JPEG 2000 J2K", Some("image/jp2"), Some(".j2k"), 0, "FF4FFF51"),
        ("OpenEXR", Some("image/x-exr"), Some(".exr"), 0, "762F3101"),
        ("TGA image", Some("image/x-tga"), Some(".tga"), 0, "000002"),
        ("PCX image", Some("image/x-pcx"), Some(".pcx"), 0, "0A"),
        ("PBM bitmap (binary)", Some("image/x-portable-bitmap"), Some(".pbm"), 0, "5034"),
        ("PGM graymap (binary)", Some("image/x-portable-graymap"), Some(".pgm"), 0, "5035"),
        ("PPM pixmap (binary)", Some("image/x-portable-pixmap"), Some(".ppm"), 0, "5036"),
        ("QOI image", Some("image/qoi"), Some(".qoi"), 0, "716F6966"),
        ("KTX2 texture", Some("image/ktx2"), Some(".ktx2"), 0, "AB4B5458203230"),
        ("Canon CR2 raw", Some("image/x-canon-cr2"), Some(".cr2"), 0, "49492A00100000004352"),
        ("Nikon NEF raw", Some("image/x-nikon-nef"), Some(".nef"), 0, "4D4D002A"),
        ("Olympus ORF raw", Some("image/x-olympus-orf"), Some(".orf"), 0, "4949524F"),
        ("Sony ARW raw", Some("image/x-sony-arw"), Some(".arw"), 0, "49492A00"),
        ("Fuji RAF raw", Some("image/x-fuji-raf"), Some(".raf"), 0, "4655"),
        ("PE executable", Some("application/x-msdownload"), Some(".exe"), 0, "4D5A"),
        ("NE executable (Win16)", Some("application/x-msdownload"), Some(".exe"), 0, "4E45"),
        ("LE executable (OS/2)", Some("application/x-msdownload"), Some(".exe"), 0, "4C45"),
        ("LX executable (OS/2)", Some("application/x-msdownload"), Some(".exe"), 0, "4C58"),
        ("ELF 32-bit LSB", Some("application/x-elf"), None, 0, "7F454C4601010100"),
        ("ELF 64-bit LSB", Some("application/x-elf"), None, 0, "7F454C4602010100"),
        ("ELF 32-bit MSB", Some("application/x-elf"), None, 0, "7F454C4601020100"),
        ("ELF 64-bit MSB", Some("application/x-elf"), None, 0, "7F454C4602020100"),
        ("Mach-O 32-bit LE", Some("application/x-mach-binary"), None, 0, "FEEDFACE"),
        ("Mach-O 64-bit LE", Some("application/x-mach-binary"), None, 0, "FEEDFACF"),
        ("Mach-O 32-bit BE", Some("application/x-mach-binary"), None, 0, "CEFAEDFE"),
        ("Mach-O 64-bit BE", Some("application/x-mach-binary"), None, 0, "CFFAEDFE"),
        ("Mach-O Universal", Some("application/x-mach-binary"), None, 0, "CAFEBABE"),
        ("COFF object (i386)", Some("application/x-coff"), Some(".o"), 0, "4C01"),
        ("COFF object (x64)", Some("application/x-coff"), Some(".o"), 0, "8664"),
        ("MS-DOS COM", Some("application/x-msdos-program"), Some(".com"), 0, "EB"),
        ("PDF document", Some("application/pdf"), Some(".pdf"), 0, "255044462D"),
        ("OLE2 Compound (DOC/XLS)", Some("application/x-ole-storage"), Some(".doc"), 0, "D0CF11E0A1B11AE1"),
        ("RTF document", Some("application/rtf"), Some(".rtf"), 0, "7B5C72746631"),
        ("PostScript", Some("application/postscript"), Some(".ps"), 0, "25215053"),
        ("DjVu document", Some("image/vnd.djvu"), Some(".djvu"), 0, "41542654464F524D"),
        ("CHM compiled help", Some("application/x-chm"), Some(".chm"), 0, "49545346"),
        ("EPUB ebook", Some("application/epub+zip"), Some(".epub"), 0, "504B0304"),
        ("MOBI ebook", Some("application/x-mobipocket-ebook"), Some(".mobi"), 0, "424F4F4B4D4F4249"),
        ("Apple Pages", Some("application/x-iwork-pages"), Some(".pages"), 0, "504B0304"),
        ("Apple Numbers", Some("application/x-iwork-numbers"), Some(".numbers"), 0, "504B0304"),
        ("Apple Keynote", Some("application/x-iwork-keynote"), Some(".key"), 0, "504B0304"),
        ("Microsoft OneNote", Some("application/onenote"), Some(".one"), 0, "E4525C7B8CD8"),
        ("HTML5 document", Some("text/html"), Some(".html"), 0, "3C21444F4354595045"),
        ("XML document", Some("application/xml"), Some(".xml"), 0, "3C3F786D6C20"),
        ("JSON data", Some("application/json"), Some(".json"), 0, "7B"),
        ("TeX DVI", Some("application/x-dvi"), Some(".dvi"), 0, "F702"),
        ("WinHelp (HLP)", Some("application/winhlp"), Some(".hlp"), 0, "3F5F03"),
        ("WAV audio", Some("audio/wav"), Some(".wav"), 0, "52494646"),
        ("MP3 ID3v2", Some("audio/mpeg"), Some(".mp3"), 0, "494433"),
        ("MP3 MPEG v1", Some("audio/mpeg"), Some(".mp3"), 0, "FFFB"),
        ("MP3 MPEG v1 no CRC", Some("audio/mpeg"), Some(".mp3"), 0, "FFF3"),
        ("FLAC audio", Some("audio/flac"), Some(".flac"), 0, "664C6143"),
        ("OGG audio", Some("audio/ogg"), Some(".ogg"), 0, "4F676753"),
        ("Opus audio", Some("audio/opus"), Some(".opus"), 0, "4F676753"),
        ("Speex audio", Some("audio/speex"), Some(".spx"), 0, "4F676753"),
        ("MIDI audio", Some("audio/midi"), Some(".mid"), 0, "4D546864"),
        ("AIFF audio", Some("audio/aiff"), Some(".aiff"), 0, "464F524D"),
        ("AAC ADTS", Some("audio/aac"), Some(".aac"), 0, "FFF1"),
        ("AAC ADIF", Some("audio/aac"), Some(".aac"), 0, "FFF9"),
        ("AC-3 Dolby Digital", Some("audio/ac3"), Some(".ac3"), 0, "0B77"),
        ("E-AC-3 Dolby+", Some("audio/eac3"), Some(".eac3"), 0, "0B78"),
        ("WMA audio (ASF)", Some("audio/x-ms-wma"), Some(".wma"), 0, "3026B2758E66CF11"),
        ("APE Monkey's Audio", Some("audio/x-ape"), Some(".ape"), 0, "4D414320"),
        ("WavPack audio", Some("audio/x-wavpack"), Some(".wv"), 0, "7776706B"),
        ("TrueAudio TTA", Some("audio/x-tta"), Some(".tta"), 0, "54544131"),
        ("AMR audio", Some("audio/amr"), Some(".amr"), 0, "2321414D52"),
        ("RealAudio", Some("audio/vnd.rn-realaudio"), Some(".ra"), 0, "2E7261FD"),
        ("CAF (Apple)", Some("audio/x-caf"), Some(".caf"), 0, "63616666"),
        ("AU/SND audio", Some("audio/basic"), Some(".au"), 0, "2E736E64"),
        ("M4A audio (MP4)", Some("audio/mp4"), Some(".m4a"), 4, "66747970"),
        ("MP4 base media", Some("video/mp4"), Some(".mp4"), 4, "66747970"),
        ("QuickTime MOV", Some("video/quicktime"), Some(".mov"), 4, "667479706D6F6F76"),
        ("AVI video", Some("video/x-msvideo"), Some(".avi"), 0, "52494646"),
        ("Matroska MKV", Some("video/x-matroska"), Some(".mkv"), 0, "1A45DFA3"),
        ("WebM video", Some("video/webm"), Some(".webm"), 0, "1A45DFA3"),
        ("WMV video (ASF)", Some("video/x-ms-wmv"), Some(".wmv"), 0, "3026B2758E66CF11"),
        ("FLV video", Some("video/x-flv"), Some(".flv"), 0, "464C5601"),
        ("Flash SWF", Some("application/x-shockwave-flash"), Some(".swf"), 0, "465753"),
        ("Flash SWF compressed", Some("application/x-shockwave-flash"), Some(".swf"), 0, "435753"),
        ("MPEG-1 PS", Some("video/mpeg"), Some(".mpg"), 0, "000001BA"),
        ("MPEG-2 TS", Some("video/mp2t"), Some(".ts"), 0, "47"),
        ("3GPP video", Some("video/3gpp"), Some(".3gp"), 4, "66747970336770"),
        ("Bink video", Some("video/x-bink"), Some(".bik"), 0, "42494B"),
        ("RealMedia", Some("video/vnd.rn-realvideo"), Some(".rm"), 0, "2E524D46"),
        ("VP8 (IVF)", Some("video/x-ivf"), Some(".ivf"), 0, "444B4946"),
        ("DV video", Some("video/x-dv"), Some(".dv"), 0, "1F0700"),
        ("MXF broadcast", Some("application/mxf"), Some(".mxf"), 0, "060E2B3402040100"),
        ("H.264 NAL unit", Some("video/h264"), Some(".h264"), 0, "00000001"),
        ("HEVC/H.265 NAL", Some("video/hevc"), Some(".h265"), 0, "00000001"),
        ("AV1 (IVF)", Some("video/av1"), Some(".ivf"), 0, "444B4946"),
        ("TrueType font", Some("font/ttf"), Some(".ttf"), 0, "0001000000"),
        ("OpenType font", Some("font/otf"), Some(".otf"), 0, "4F54544F"),
        ("WOFF font", Some("font/woff"), Some(".woff"), 0, "774F4646"),
        ("WOFF2 font", Some("font/woff2"), Some(".woff2"), 0, "774F4632"),
        ("PCF bitmap font", Some("application/x-font-pcf"), Some(".pcf"), 0, "01666370"),
        ("BDF bitmap font", Some("application/x-font-bdf"), Some(".bdf"), 0, "5354415254464F4E54"),
        ("Type1 PFB font", Some("application/x-font-type1"), Some(".pfb"), 0, "8001"),
        ("ISO 9660 CD image", Some("application/x-iso9660-image"), Some(".iso"), 32769, "4344303031"),
        ("UDF filesystem", Some("application/x-udf"), Some(".iso"), 32768, "4E535230"),
        ("NTFS filesystem", Some("application/x-ntfs"), None, 3, "4E54465320202020"),
        ("ext2/ext3/ext4 fs", Some("application/x-ext4"), None, 1080, "53EF"),
        ("XFS filesystem", Some("application/x-xfs"), None, 0, "58465342"),
        ("Btrfs filesystem", Some("application/x-btrfs"), None, 65536, "5F42485246534D5F"),
        ("VHD disk image", Some("application/x-vhd"), Some(".vhd"), 0, "636F6E6563746978"),
        ("VHDX disk image", Some("application/x-vhdx"), Some(".vhdx"), 0, "7668647866696C65"),
        ("VMDK disk", Some("application/x-vmdk"), Some(".vmdk"), 0, "4B444D"),
        ("Apple DMG", Some("application/x-apple-diskimage"), Some(".dmg"), 0, "7801730D626260"),
        ("QEMU QCOW2", Some("application/x-qcow2"), Some(".qcow2"), 0, "514649FB"),
        ("VirtualBox VDI", Some("application/x-vdi"), Some(".vdi"), 0, "3C3C3C20"),
        ("FAT filesystem", Some("application/x-fat"), None, 0, "EB"),
        ("SQLite3 database", Some("application/x-sqlite3"), Some(".sqlite"), 0, "53514C69746520666F726D6174203300"),
        ("SQLite3 WAL", Some("application/x-sqlite3"), Some(".sqlite-wal"), 0, "377F0682"),
        ("Berkeley DB (btree)", Some("application/x-bdb"), Some(".db"), 0, "00053162"),
        ("Berkeley DB (hash)", Some("application/x-bdb"), Some(".db"), 0, "00053161"),
        ("LMDB database", Some("application/x-lmdb"), Some(".mdb"), 0, "01000000"),
        ("MS Access MDB", Some("application/x-msaccess"), Some(".mdb"), 0, "000100005374616E"),
        ("MS Access ACCDB", Some("application/x-msaccess"), Some(".accdb"), 0, "00010000416363"),
        ("Parquet file", Some("application/x-parquet"), Some(".parquet"), 0, "50415231"),
        ("HDF5 data", Some("application/x-hdf5"), Some(".h5"), 0, "89484446"),
        ("Redis RDB dump", Some("application/x-redis-dump"), Some(".rdb"), 0, "5245444953"),
        ("Java class file", Some("application/java-vm"), Some(".class"), 0, "CAFEBABE"),
        ("Dalvik DEX", Some("application/x-dex"), Some(".dex"), 0, "6465780A"),
        ("WebAssembly WASM", Some("application/wasm"), Some(".wasm"), 0, "0061736D"),
        ("Lua bytecode 5.1", Some("application/x-lua-bytecode"), Some(".luac"), 0, "1B4C7561"),
        ("Python bytecode 3.3+", Some("application/x-python-bytecode"), Some(".pyc"), 0, "42"),
        ("LLVM bitcode", Some("application/x-llvm-bitcode"), Some(".bc"), 0, "4243"),
        ("X.509 DER cert", Some("application/pkix-cert"), Some(".cer"), 0, "3082"),
        ("PKCS#12 PFX", Some("application/x-pkcs12"), Some(".pfx"), 0, "3084"),
        ("OpenPGP public key", Some("application/pgp-keys"), Some(".asc"), 0, "2D2D2D2D2D424547494E2050"),
        ("OpenPGP message", Some("application/pgp-message"), Some(".pgp"), 0, "2D2D2D2D2D424547494E2050"),
        ("SSH private key", Some("text/plain"), None, 0, "2D2D2D2D2D424547494E204F5045"),
        ("SSH RSA public key", Some("text/plain"), Some(".pub"), 0, "7373682D72736100"),
        ("PEM certificate", Some("application/x-pem-file"), Some(".pem"), 0, "2D2D2D2D2D424547494E204345"),
        ("Java KeyStore JKS", Some("application/x-java-keystore"), Some(".jks"), 0, "FECAFE"),
        ("Bitcoin wallet", Some("application/x-bitcoin-wallet"), Some(".dat"), 0, "F9BEB4D9"),
        ("PCAP (LE)", Some("application/vnd.tcpdump.pcap"), Some(".pcap"), 0, "D4C3B2A1"),
        ("PCAP (BE)", Some("application/vnd.tcpdump.pcap"), Some(".pcap"), 0, "A1B2C3D4"),
        ("PCAPNG capture", Some("application/vnd.tcpdump.pcap"), Some(".pcapng"), 0, "0A0D0D0A"),
        ("Android APK", Some("application/vnd.android.package-archive"), Some(".apk"), 0, "504B0304"),
        ("Android boot img", Some("application/x-android-boot"), Some(".img"), 0, "414E44524F494421"),
        ("STL binary 3D", Some("application/sla"), Some(".stl"), 0, "434453"),
        ("OBJ 3D model", Some("model/obj"), Some(".obj"), 0, "23"),
        ("3DS Max model", Some("application/x-3ds"), Some(".3ds"), 0, "4D4D"),
        ("Collada DAE", Some("model/vnd.collada+xml"), Some(".dae"), 0, "3C3F786D6C"),
        ("FBX binary", Some("application/x-fbx"), Some(".fbx"), 0, "4B61794461726120"),
        ("GLB 3D model", Some("model/gltf-binary"), Some(".glb"), 0, "676C5446"),
        ("AutoCAD DWG", Some("image/vnd.dwg"), Some(".dwg"), 0, "41433130"),
        ("PLY point cloud", Some("application/x-ply"), Some(".ply"), 0, "706C7920"),
        ("Nintendo NES ROM", Some("application/x-nintendo-nes-rom"), Some(".nes"), 0, "4E45531A"),
        ("Nintendo 64 ROM", Some("application/x-nintendo-64-rom"), Some(".z64"), 0, "80371240"),
        ("Nintendo DS ROM", Some("application/x-nintendo-ds-rom"), Some(".nds"), 0, "00010000"),
        ("Nintendo GBA ROM", Some("application/x-nintendo-gba-rom"), Some(".gba"), 0, "00008000"),
        ("Sega Genesis ROM", Some("application/x-sega-genesis-rom"), Some(".md"), 0, "00000800"),
        ("PSX EXE", Some("application/x-playstation-exe"), Some(".exe"), 0, "00000100"),
        ("Windows LNK shortcut", Some("application/x-ms-shortcut"), Some(".lnk"), 0, "4C00000001140200"),
        ("Windows registry hive", Some("application/x-ms-registry"), None, 0, "72656766"),
        ("Windows EVTX log", Some("application/x-ms-evtx"), Some(".evtx"), 0, "456C6646696C65"),
        ("Windows Minidump", Some("application/x-ms-minidump"), Some(".dmp"), 0, "4D444D5093A7"),
        ("RPM package", Some("application/x-rpm"), Some(".rpm"), 0, "EDABEEDB"),
        ("DEB package", Some("application/vnd.debian.binary-package"), Some(".deb"), 0, "213C617263683E"),
        ("MSI installer", Some("application/x-msi"), Some(".msi"), 0, "D0CF11E0A1B11AE1"),
        ("Shapefile SHP", Some("application/x-esri-shape"), Some(".shp"), 0, "0000270A00000000"),
        ("GeoPackage", Some("application/geopackage+sqlite3"), Some(".gpkg"), 0, "53514C697465"),
        ("U-Boot FIT image", Some("application/x-fit-image"), Some(".itb"), 0, "D00DFEED"),
        ("U-Boot uImage", Some("application/x-u-boot"), Some(".img"), 0, "27051956"),
        ("FITS astronomy", Some("application/fits"), Some(".fits"), 0, "53494D50"),
        ("DICOM medical", Some("application/dicom"), Some(".dcm"), 0, "44434D"),
        ("VTK visualization", Some("application/x-vtk"), Some(".vtk"), 0, "2376746B"),
        ("Bash shell script", Some("text/x-shellscript"), Some(".sh"), 0, "23212F62696E2F"),
        ("Python script", Some("text/x-python"), Some(".py"), 0, "23212F7573722F62696E2F"),
        ("PHP script", Some("text/x-php"), Some(".php"), 0, "3C3F706870"),
        ("Perl script", Some("text/x-perl"), Some(".pl"), 0, "23212F7573722F62696E"),
        ("Ruby script", Some("text/x-ruby"), Some(".rb"), 0, "23212F7573722F62696E2F"),
        ("PostScript EPS", Some("application/postscript"), Some(".eps"), 0, "252150532D4164"),
        ("FictionBook FB2", Some("application/x-fictionbook+xml"), Some(".fb2"), 0, "3C3F786D6C"),
    ]
}

/// Seed the database with all built-in signatures.
/// Drops existing data first, then inserts the full set.
pub fn seed_database(conn: &Connection) -> Result<u32, rusqlite::Error> {
    drop_schema(conn)?;
    ensure_schema(conn)?;

    let sigs = seed_sigs();

    let mut count = 0u32;
    for (name, mime, ext, offset, hex) in &sigs {
        conn.execute(
            "INSERT INTO signatures (name, mime, extension, source, priority) VALUES (?1, ?2, ?3, 'seed', 10)",
            params![name, mime, ext],
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
        assert!(count > 100, "Should have at least 100 seed sigs, got {}", count);
        let sigs = list_signatures(&conn).unwrap();
        assert_eq!(sigs.len() as u32, count);
        let names: Vec<String> = sigs.iter().map(|s| s.name.clone()).collect();
        assert!(names.contains(&"ZIP archive".to_string()));
        assert!(names.contains(&"PNG image".to_string()));
        assert!(names.contains(&"PDF document".to_string()));
    }
}
