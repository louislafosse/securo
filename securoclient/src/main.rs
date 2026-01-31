mod modules {
    pub mod client;
    pub mod antidebug;
    pub mod auth;
    pub mod token;
    pub mod messaging;
    pub mod license;
}

use securo::client::crypto::SecuroClient;
use securo::tls::TlsMode;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {

    let mut _guard = None;
    let env_cert = include_bytes!("../../securoserv/cert.pem");
    let env_key = include_bytes!("../../securoserv/key.pem");

    if std::env::var("SERVER_LOG").unwrap_or_default() == "true" {
        let file_appender = tracing_appender::rolling::RollingFileAppender::new(
            tracing_appender::rolling::Rotation::DAILY,
            "./logs",
            "securo-client.log"
        );
        let (non_blocking, guard) = tracing_appender::non_blocking(file_appender);

        tracing_subscriber::fmt()
            .with_writer(tracing_subscriber::fmt::writer::MakeWriterExt::and(non_blocking, std::io::stdout))
            .with_target(false)
            .with_env_filter("info")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();

        _guard = Some(guard);
    } else {
        tracing_subscriber::fmt()
            .with_writer(std::io::stdout)
            .with_target(false)
            .with_env_filter("info")
            .with_timer(tracing_subscriber::fmt::time::ChronoLocal::new("%Y-%m-%dT%H:%M:%S".to_string()))
            .init();
    }

    tracing::info!("Starting SecuroClient (E2EE) with mTLS and certificate pinning\n");

    // Get machine ID for anti-debug and ban system
    let machine_id = modules::antidebug::get_machine_id()?;
    tracing::info!("Machine ID: {}\n", machine_id);

    // Create pinned HTTP client with random pin (pins are embedded at compile time)
    let client = modules::client::create_pinned_client(env_cert, Some(env_key), TlsMode::MutualTlsPinning)?;
    tracing::info!("🔒 Certificate pinning enabled (compile-time pins embedded)");
    tracing::info!(" ↪  SSL pinning set");

    tracing::info!("Test 1: Testing server connection...");
    match client.get("https://127.0.0.1:8443/").send().await {
        Ok(resp) => {
            tracing::info!("✅ Connection successful! Status: {}", resp.status());
            if let Ok(body) = resp.text().await {
                tracing::info!("Response: {}\n", body);
            }
        }
        Err(e) => {
            tracing::error!("❌ Connection failed: {}", e);
            tracing::warn!("This is expected if:");
            tracing::warn!("   - Server is not running");
            tracing::warn!("   - Certificate doesn't match");
            tracing::warn!("   - Burp/mitmproxy is intercepting\n");
            return Err(e.into());
        }
    }

    tracing::info!("Test 2: Performing two-stage secure key exchange...");
    let mut crypto = SecuroClient::new();
    
    let stage1_response = modules::auth::exchange_keys_stage1(&client).await?;
    tracing::info!("✅ Stage 1: Received server ephemeral key");
    
    let exchange_response = modules::auth::exchange_keys_stage2(&client, &mut crypto, stage1_response).await?;
    tracing::info!("✅ Stage 2: Exchange completed");
    
    let temp_jwt = exchange_response.temp_jwt.clone();
    let original_session_id = crypto.get_session_id().unwrap().to_string();
    tracing::info!("Temp JWT (10 min): {}...", &temp_jwt[..std::cmp::min(30, temp_jwt.len())]);
    tracing::info!("");

    // Test 2.5: Verify that temp JWT (exchange token) is rejected on ALL protected endpoints
    tracing::info!("Test 2.5: Verifying exchange token rejection on ALL protected endpoints...");
    let test_payload = serde_json::json!({"message": "test data"});
    
    // Test endpoints that require access tokens (not exchange tokens)
    let protected_endpoints = vec![
        "/api/encrypted/send",
        "/api/encrypted",
        "/api/encrypted/get",
        "/api/check",
        "/api/refresh",
        "/api/unauth",
    ];
    
    let mut all_rejected = true;
    for endpoint in protected_endpoints {
        let encrypted_req = crypto.encrypt_request(&original_session_id, test_payload.clone())?;
        let resp = client
            .post(format!("https://127.0.0.1:8443{}", endpoint))
            .json(&encrypted_req)
            .send()
            .await?;
        
        if resp.status() == 401 {
            tracing::info!("{} → Rejected (401)", endpoint);
        } else {
            tracing::warn!("{} → Accepted with status {}", endpoint, resp.status());
            all_rejected = false;
        }
    }
    
    if all_rejected {
        tracing::info!("✅ Exchange tokens correctly rejected on ALL protected endpoints");
        tracing::info!("   This confirms exchange tokens are ONLY valid for /auth endpoint");
    } else {
        tracing::warn!("Some endpoints did not reject the exchange token!");
    }
    tracing::info!("");

    // Send encrypted authentication with admin license key - get admin tokens
    tracing::info!("Test 3: Sending encrypted authentication with admin license...");
    let admin_license_key = "b7f4c2e9-8d3a-4f1b-9e2c-5a6d7f8e9c1a-admin-bootstrap-key";
    let auth_response = modules::auth::auth(&client, &mut crypto, admin_license_key).await?;
    let admin_access_token = auth_response.access_token.clone();
    let _admin_refresh_token = auth_response.refresh_token.clone();
    // Update session_id to admin access token for admin operations
    crypto.set_session_id(admin_access_token.clone());
    tracing::info!("✅ Admin authenticated");
    tracing::info!("");

    // Now create our first user license using admin session
    tracing::info!("Test 4: Creating first user license...");
    let (access_token, refresh_token, license_key) = {
        match modules::license::create_license(&client, &crypto, Some(86400)).await {
            Ok(license_data) => {
                tracing::info!("✅ User license created\n");
                
                let lic_key = license_data.get("license_id")
                    .and_then(|v| v.as_str())
                    .ok_or("license_id missing")?;
                
                // Logout from admin session and login with user license
                // Need fresh key exchange for new session
                tracing::info!("Test 5: Starting fresh key exchange for user session...");
                let stage1_response = modules::auth::exchange_keys_stage1(&client).await?;
                let _ = modules::auth::exchange_keys_stage2(&client, &mut crypto, stage1_response).await?;
                tracing::info!("✅ Key exchange completed for user session");
                
                tracing::info!("Test 5.5: Logging in with user license...");
                let user_auth_response = modules::auth::auth(&client, &mut crypto, lic_key).await?;
                let access_token = user_auth_response.access_token.clone();
                let refresh_token = user_auth_response.refresh_token.clone();
                crypto.set_session_id(access_token.clone());  // Update session_id to permanent access token
                tracing::info!("✅ User authenticated with license\n");
                tracing::info!("Access Token: {}...", &access_token[..std::cmp::min(30, access_token.len())]);
                tracing::info!("Refresh Token: {}...", &refresh_token[..std::cmp::min(30, refresh_token.len())]);
                tracing::info!("");
                
                Ok::<(String, String, String), Box<dyn std::error::Error>>((access_token, refresh_token, lic_key.to_string()))
            }
            Err(e) => {
                tracing::error!("Failed to create user license: {}", e);
                Err(e)
            }
        }
    }?;

    let monitor_client = client.clone();
    let monitor_crypto = crypto.clone();
    let monitor_machine_id = machine_id.clone();
    tokio::spawn(async move {
        modules::antidebug::debugger_monitor_task(monitor_client, monitor_crypto, monitor_machine_id).await;
    });
    tracing::info!("🔍 Debugger monitoring started in background\n");

    tracing::info!("Test 6: Sending encrypted message...");
    let response = modules::messaging::send_encrypted_message(
        &client,
        &crypto,
        "Hello from client! This is a secret message."
    ).await?;
    tracing::info!("✅ Message sent successfully");
    tracing::info!("Server response: {}\n", response);

    tracing::info!("Test 5: Sending second encrypted message...");
    let response = modules::messaging::send_encrypted_message(
        &client,
        &crypto,
        "Second message - authenticated by session ID!"
    ).await?;
    tracing::info!("✅ Message sent successfully");
    tracing::info!("Server response: {}\n", response);

    tracing::info!("Test 5: Requesting encrypted message from server...");
    let decrypted_message = modules::messaging::receive_encrypted_message(
        &client,
        &crypto,
        &access_token
    ).await?;
    tracing::info!("✅ Received and decrypted message from server");
    tracing::info!("Message: {}\n", decrypted_message);

    tracing::info!("Test 6: Checking license validity...");
    match modules::license::check_license(&client, &crypto, &license_key, &machine_id).await {
        Ok(result) => {
            tracing::info!("✅ License check result: {}\n", result);
        }
        Err(e) => {
            tracing::error!("License check failed: {}\n", e);
        }
    }

    tracing::info!("Test 7: Refreshing access token...");
    modules::token::refresh_access_token(&client, &mut crypto, &refresh_token).await?;
    tracing::info!("");

    // Bootstrap: Authenticate with admin license to get admin session
    // First, do a fresh key exchange to get a new exchange token
    tracing::info!("Test 7.5: Starting fresh key exchange for admin bootstrap...");
    let stage1_response = modules::auth::exchange_keys_stage1(&client).await?;
    let _ = modules::auth::exchange_keys_stage2(&client, &mut crypto, stage1_response).await?;
    tracing::info!("✅ Key exchange completed");
    
    tracing::info!("Test 7.6: Bootstrap admin authentication...");
    let (admin_access_token, _admin_refresh_token) = modules::license::bootstrap_authenticate(&client, &crypto).await?;
    tracing::info!("✅ Admin session authenticated\n");
    
    // Update crypto to use admin access token
    crypto.set_session_id(admin_access_token);

    tracing::info!("Test 8: Creating license (admin demo)...");
    match modules::license::create_license(&client, &crypto, None).await {
        Ok(lic_data) => {
            tracing::info!("✅ License created : {:?}", lic_data);
            // Store license_id for removal test
            let remove_lic_id = lic_data.get("license_id")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");            

            tracing::info!("Test 9: Removing license (admin demo)...");
            match modules::license::remove_license(&client, &crypto, remove_lic_id).await {
                Ok(result) => {
                    tracing::info!("✅ License removed: {}\n", result);
                }
                Err(e) => {
                    tracing::warn!("License removal failed (expected if not admin): {}\n", e);
                }
            }
        }
        Err(e) => {
            tracing::warn!("License creation failed (expected if not admin): {}\n", e);
        }
    }


    tracing::info!("Test 10: unauthenticating session...");
    modules::auth::unauth(&client, &crypto).await?;
    tracing::info!("");

    tracing::info!("✅ All tests completed successfully!");
    Ok(())
}
