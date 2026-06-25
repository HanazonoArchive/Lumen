// Binary to generate the initial signatures.db
fn main() {
    let db_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "signatures.db".to_string());

    let conn = lumen_engine::db::open_db(&db_path).expect("Failed to open DB");
    let count = lumen_engine::db::seed_database(&conn).expect("Failed to seed DB");
    println!("Seeded {} signatures into {}", count, db_path);
}
