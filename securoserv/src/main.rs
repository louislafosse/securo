mod handlers;
mod db;
mod admin;

use tracing::info;
use actix_web::{
    App,
    HttpServer,
    middleware::Logger
};
use securo::server::pin::init_rustls_config;
use securo::server::crypto::SecuroServ;
use securo::tls::TlsMode;
use std::time::Duration;

use actix_web::web::{self};
use crate::admin::AdminSessions;

pub fn configure_routes() -> impl actix_web::dev::HttpServiceFactory {
    web::scope("")
        .route("/", web::get().to(handlers::pong))
        .service(
            web::scope("/api")
                .route("/exchange/stage1", web::get().to(handlers::exchange_stage1))
                .route("/exchange/stage2", web::post().to(handlers::exchange_stage2))
                .route("/auth", web::post().to(handlers::auth))
                .route("/unauth", web::post().to(handlers::unauth))
                .route("/report", web::post().to(handlers::report))
                .route("/check", web::post().to(handlers::check_license))
                .route("/refresh", web::post().to(handlers::refresh_token))
                .route("/encrypted", web::post().to(handlers::receive_encrypted))
                .route("/encrypted/get", web::post().to(handlers::get_encrypted))
                .route("/encrypted/send", web::post().to(handlers::send_encrypted))
                .service(
                    web::scope("/admin")
                        .route("/create_license", web::post().to(handlers::admin_create_license))
                        .route("/remove_license", web::post().to(handlers::admin_remove_license))
                )
        )
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    let mut _guard = None;

    if std::env::var("SERVER_LOG").unwrap_or_default() == "true" {
        let file_appender = tracing_appender::rolling::RollingFileAppender::new(
            tracing_appender::rolling::Rotation::DAILY,
            "./logs",
            "securo-server.log"
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_writer(tracing_subscriber::fmt::writer::MakeWriterExt::and(non_blocking, std::io::stdout))
            .with_file(true)
            .with_line_number(true)
            .with_env_filter("info,actix_server=warn,actix_http::h1::dispatcher=off")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();

        _guard = Some(guard);
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stdout)
            .with_file(true)
            .with_line_number(true)
            .with_env_filter("info,actix_server=warn,actix_http::h1::dispatcher=off")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();
    }

    let use_tls = std::env::var("USE_TLS").unwrap_or_default() == "true";

    // Initialize SQLite database
    let db_pool = db::init::init_db()
        .expect("Failed to initialize database");
    
    db::init::run_migrations(&db_pool)
        .expect("Failed to run database migrations");

    // Initialize admin license for bootstrapping
    db::init::init_admin_license(&db_pool)
        .expect("Failed to initialize admin license");

    tracing::info!("Database initialized");

    // Create the server crypto instance with tracing logger
    let server_crypto = web::Data::from(
        SecuroServ::new_with_verbose_housekeeping(Duration::from_secs(60))
    );

    let db_data = web::Data::new(db_pool);
    let admin_sessions = web::Data::new(AdminSessions::default());
    
    if use_tls {
        info!("Server starting with mTLS and certificate pinning on https://127.0.0.1:8443/");

        let cert = include_bytes!("../cert.pem");
        let key = include_bytes!("../key.pem");
        let config = init_rustls_config(cert, key, TlsMode::MutualTlsPinning);

        HttpServer::new(move || {
            App::new()
                .app_data(server_crypto.clone())
                .app_data(db_data.clone())
                .app_data(admin_sessions.clone())
                .wrap(Logger::default())
                .service(configure_routes())
        })
        .bind_rustls_0_23(("0.0.0.0", 8443), config)?
        .run()
        .await
    } else {
        info!("Server starting on http://127.0.0.1:8080/");
        
        HttpServer::new(move || {
            App::new()
                .app_data(server_crypto.clone())
                .app_data(db_data.clone())
                .app_data(admin_sessions.clone())
                .wrap(Logger::default())
                .service(configure_routes())
        })
        .bind(("0.0.0.0", 8080))?
        .run()
        .await
    }
}
