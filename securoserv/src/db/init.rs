// Database initialization and connection management
use diesel::sqlite::SqliteConnection;
use diesel::Connection;
use std::sync::{Arc, Mutex};

pub type DbPool = Arc<Mutex<SqliteConnection>>;

/// Initialize SQLite database connection
/// Creates database.db file if it doesn't exist
/// Note: SQLite has built-in thread-safety; Arc<Mutex<>> provides safe shared access
pub fn init_db() -> Result<DbPool, Box<dyn std::error::Error>> {
    let database_url = "database.db";

    Ok(Arc::new(Mutex::new(SqliteConnection::establish(database_url)?)))
}

/// Run migrations on the database
pub fn run_migrations(db: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::sql_query;
    use diesel::RunQueryDsl;

    let mut conn = db.lock().unwrap();
    
    // Execute each CREATE TABLE separately for better error handling
    let tables = vec![
        "CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY NOT NULL,
            session_uuid TEXT NOT NULL UNIQUE,
            license_key TEXT NOT NULL,
            hardware_id TEXT,
            client_public_key BLOB NOT NULL,
            client_verifying_key TEXT NOT NULL,
            client_kyber_public TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_heartbeat INTEGER NOT NULL,
            is_authenticated BOOLEAN NOT NULL DEFAULT 0
        )",
        
        "CREATE TABLE IF NOT EXISTS licenses (
            id TEXT PRIMARY KEY NOT NULL,
            license_key TEXT NOT NULL UNIQUE,
            created_at INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            is_revoked BOOLEAN NOT NULL DEFAULT 0,
            max_connections INTEGER NOT NULL DEFAULT 1,
            license_type TEXT NOT NULL DEFAULT 'standard'
        )",
        
        "CREATE TABLE IF NOT EXISTS bans (
            id TEXT PRIMARY KEY NOT NULL,
            banned_entity TEXT NOT NULL,
            ban_type TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            banned_by TEXT,
            reporter_session TEXT,
            reported_session TEXT,
            evidence TEXT,
            status TEXT NOT NULL DEFAULT 'active'
        )",
        
        "CREATE TABLE IF NOT EXISTS messages (
            id TEXT PRIMARY KEY NOT NULL,
            sender_session TEXT NOT NULL,
            recipient_session TEXT,
            content TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            is_delivered BOOLEAN NOT NULL DEFAULT 0,
            delivered_at INTEGER
        )",
        
        "CREATE TABLE IF NOT EXISTS audit_logs (
            id TEXT PRIMARY KEY NOT NULL,
            session_uuid TEXT,
            event_type TEXT NOT NULL,
            event_data TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            ip_address TEXT
        )",
    ];
    
    // Create tables
    for table_sql in tables {
        match sql_query(table_sql).execute(&mut *conn) {
            Ok(_) => tracing::debug!("✅ Table created/verified"),
            Err(e) => tracing::warn!("Table creation warning: {:?}", e),
        }
    }
    
    // Create indexes
    let indexes = vec![
        "CREATE INDEX IF NOT EXISTS idx_sessions_session_uuid ON sessions(session_uuid)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_license_key ON sessions(license_key)",
        "CREATE INDEX IF NOT EXISTS idx_licenses_license_key ON licenses(license_key)",
        "CREATE INDEX IF NOT EXISTS idx_bans_banned_entity ON bans(banned_entity)",
        "CREATE INDEX IF NOT EXISTS idx_messages_sender ON messages(sender_session)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_event_type ON audit_logs(event_type)",
    ];
    
    for index_sql in indexes {
        match sql_query(index_sql).execute(&mut *conn) {
            Ok(_) => tracing::debug!("✅ Index created/verified"),
            Err(e) => tracing::warn!("Index creation warning: {:?}", e),
        }
    }
    
    // Migrate reports table into bans (if reports exists)
    let migrate_reports = "INSERT OR IGNORE INTO bans (id, banned_entity, ban_type, reason, created_at, banned_by, reporter_session, reported_session, evidence, status) 
                           SELECT id, reported_session, 'session', reason, created_at, NULL, reporter_session, reported_session, evidence, status FROM reports WHERE NOT EXISTS (SELECT 1 FROM bans WHERE bans.reported_session = reports.reported_session)";
    match sql_query(migrate_reports).execute(&mut *conn) {
        Ok(_) => tracing::debug!("✅ Reports migration completed"),
        Err(_) => tracing::debug!("Reports table not found (expected for fresh install)"),
    }
    
    Ok(())
}

/// Initialize admin license if it doesn't exist
pub fn init_admin_license(db: &DbPool) -> Result<(), Box<dyn std::error::Error>> {
    use diesel::sql_query;
    use diesel::RunQueryDsl;
    use chrono::Utc;
    use uuid::Uuid;

    let admin_license_key = "b7f4c2e9-8d3a-4f1b-9e2c-5a6d7f8e9c1a-admin-bootstrap-key";
    
    let mut conn = db.lock().unwrap();
    
    let license_id = Uuid::new_v4().to_string();
    let now = Utc::now().timestamp();
    let exp = now + (365 * 24 * 60 * 60 * 100); // 100 years
    
    let insert_query = "INSERT OR IGNORE INTO licenses (id, license_key, created_at, expires_at, is_revoked, max_connections, license_type) VALUES (?, ?, ?, ?, ?, ?, ?)";
    match sql_query(insert_query)
        .bind::<diesel::sql_types::Text, _>(license_id)
        .bind::<diesel::sql_types::Text, _>(admin_license_key)
        .bind::<diesel::sql_types::BigInt, _>(now)
        .bind::<diesel::sql_types::BigInt, _>(exp)
        .bind::<diesel::sql_types::Bool, _>(false)
        .bind::<diesel::sql_types::Integer, _>(999)
        .bind::<diesel::sql_types::Text, _>("admin")
        .execute(&mut *conn) {
        Ok(_) => {
            tracing::info!("Admin license initialized successfully : {}", admin_license_key);
            Ok(())
        }
        Err(e) => {
            tracing::error!("Failed to initialize admin license: {:?}", e);
            Err(format!("Failed to initialize admin license: {:?}", e).into())
        }
    }
}
