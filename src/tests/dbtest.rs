mod server::db;



fn setup() {
    setup_db().await;
}

#[test]
fn test_setup_db() {
    setup();
    // Check if the database was created
    let conn = Connection::open("turtur.db").unwrap();
    
    let query = format!("SELECT * FROM users");
    let mut stmt = conn.prepare(&query).unwrap();
    let mut rows = stmt.query([]).unwrap();
    let mut count = 0;
    while let Some(row) = rows.next().unwrap() {
        count += 1;
    }

    assert_eq!(count, 0);

}
    
