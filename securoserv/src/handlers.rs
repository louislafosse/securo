use actix_web::{http::StatusCode, web, HttpResponse};
use serde::Serialize;
use chrono::Utc;
use uuid::Uuid;

use crate::db::{self, DbPool, Ban, AuditLog, License, Message};
use crate::admin::AdminSessions;
use securo::server::crypto::{SecuroServ, EncryptedRequest, ExchangeStage2Request};

/// Admin license key - used for bootstrapping admin session creation
const ADMIN_LICENSE_KEY: &str = "b7f4c2e9-8d3a-4f1b-9e2c-5a6d7f8e9c1a-admin-bootstrap-key";

pub async fn pong() -> HttpResponse {
    HttpResponse::Ok().body("pong")
}

/// Admin: create a license for a session_id
pub async fn admin_create_license(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    admin_sessions: web::Data<AdminSessions>,
    req: web::Bytes,
) -> HttpResponse {

    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt admin_create_license request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        tracing::info!("Admin create license request (encrypted) from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

        // Extract session UUID from the JWT access token to check if it's an admin session
        let session_uuid = match crypto.validate_access_token(&session_id) {
            Ok(uuid) => uuid,
            Err(e) => {
                tracing::warn!("Invalid access token for admin_create_license: {:?}", e);
                return HttpResponse::Unauthorized().body("Invalid session");
            }
        };

        // Check if this session is marked as admin
        if !admin_sessions.is_admin(&session_uuid) {
            tracing::warn!("Rejected admin_create_license: session is not admin");
            return HttpResponse::Unauthorized().body("Admin privileges required");
        }

        let expires_in = payload.get("expires_in").and_then(|v| v.as_u64());
        
        // Create license in database
        let license_id = Uuid::new_v4().to_string();
        let license_key = Uuid::new_v4().to_string();
        let now = Utc::now().timestamp();
        let expires_at = expires_in.map(|e| now + e as i64).unwrap_or(now + 2592000);
        
        let db_license = License {
            id: license_id.clone(),
            license_key: license_key.clone(),
            created_at: now,
            expires_at,
            is_revoked: false,
            max_connections: 1,
            license_type: "standard".to_string(),
        };
        
        match db::insert_license(&db, db_license) {
            Ok(_) => {
                let audit = AuditLog {
                    id: Uuid::new_v4().to_string(),
                    session_uuid: Some(session_id.clone()),
                    event_type: "license_create".to_string(),
                    event_data: serde_json::json!({"license_key": license_key}).to_string(),
                    created_at: now,
                    ip_address: None,
                };
                if let Err(e) = db::insert_audit_log(&db, audit) {
                    tracing::error!("Failed to save audit log: {:?}", e);
                }
                
                let response = serde_json::json!({
                    "license_id": license_key,
                    "expires_at": expires_at
                });
                
                match crypto.encrypt_response(&session_id, response) {
                    Ok(encrypted_resp) => HttpResponse::Ok().json(encrypted_resp),
                    Err(e) => {
                        tracing::error!("Failed to encrypt response: {:?}", e);
                        HttpResponse::InternalServerError().body("Encryption failed")
                    }
                }
            }
            Err(e) => {
                tracing::error!("Failed to create license: {:?}", e);
                HttpResponse::InternalServerError().body("Failed to create license")
            }
        }
    } else {
        tracing::error!("Failed to deserialize EncryptedRequest from bytes");
        HttpResponse::BadRequest().body("Invalid request format")
    }
}

pub async fn admin_remove_license(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    admin_sessions: web::Data<AdminSessions>,
    req: web::Bytes,
) -> HttpResponse {

    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt admin_remove_license request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        tracing::info!("Admin remove license request (encrypted) from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

        // Extract session UUID from the JWT access token to check if it's an admin session
        let session_uuid = match crypto.validate_access_token(&session_id) {
            Ok(uuid) => uuid,
            Err(e) => {
                tracing::warn!("Invalid access token for admin_remove_license: {:?}", e);
                return HttpResponse::Unauthorized().body("Invalid session");
            }
        };

        // Check if this session is marked as admin
        if !admin_sessions.is_admin(&session_uuid) {
            tracing::warn!("Rejected admin_remove_license: session is not admin");
            return HttpResponse::Unauthorized().body("Admin privileges required");
        }

        let license_key = match payload.get("license_key").and_then(|v| v.as_str()) {
            Some(key) => key,
            None => {
                return HttpResponse::BadRequest().body("license_key required");
            }
        };

        // Revoke license in database
        match db::revoke_license(&db, license_key) {
            Ok(_) => {
                // Audit log
                let audit = AuditLog {
                    id: Uuid::new_v4().to_string(),
                    session_uuid: Some(session_id.clone()),
                    event_type: "license_revoke".to_string(),
                    event_data: serde_json::json!({"license_key": license_key}).to_string(),
                    created_at: Utc::now().timestamp(),
                    ip_address: None,
                };
                if let Err(e) = db::insert_audit_log(&db, audit) {
                    tracing::error!("Failed to save audit log: {:?}", e);
                }
                
                let response = serde_json::json!({"status": "revoked"});
                match crypto.encrypt_response(&session_id, response) {
                    Ok(encrypted_resp) => HttpResponse::Ok().json(encrypted_resp),
                    Err(e) => {
                        tracing::error!("Failed to encrypt response: {:?}", e);
                        HttpResponse::InternalServerError().body("Encryption failed")
                    }
                }
            }
            Err(e) => {
                tracing::error!("❌ Failed to revoke license: {:?}", e);
                HttpResponse::InternalServerError().body("Failed to revoke license")
            }
        }
    } else {
        tracing::error!("Failed to deserialize EncryptedRequest from bytes");
        HttpResponse::BadRequest().body("Invalid request format")
    }
}

pub async fn check_license(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    req: web::Bytes,
) -> HttpResponse {

    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt check_license request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        let license_key = payload.get("license_key").and_then(|v| v.as_str());
        
        if license_key.is_none() {
            let error_resp = serde_json::json!({"error": "license_key required"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::BadRequest().json(encrypted_err),
                Err(_) => HttpResponse::BadRequest().body("license_key required"),
            };
        }

        let hwid = match payload.get("hwid").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                let error_resp = serde_json::json!({"error": "hwid required"});
                return match crypto.encrypt_response(&session_id, error_resp) {
                    Ok(encrypted_err) => HttpResponse::BadRequest().json(encrypted_err),
                    Err(_) => HttpResponse::BadRequest().body("hwid required"),
                };
            }
        };

        // Check if banned by session_id or hwid
        let is_banned_session = db::is_entity_banned(&db, &session_id).unwrap_or_default();
        
        let is_banned_hwid = db::is_entity_banned(&db, hwid).unwrap_or_default();

        if is_banned_session || is_banned_hwid {
            let error_resp = serde_json::json!({"status": "banned"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_resp) => HttpResponse::Forbidden().json(encrypted_resp),
                Err(_) => HttpResponse::Forbidden().body("banned"),
            };
        }

        // Check license validity
        let is_valid = match db::get_license_by_key(&db, license_key.unwrap_or("")) {
            Ok(Some(lic)) => !lic.is_revoked && lic.expires_at > Utc::now().timestamp(),
            Ok(None) => false,
            Err(e) => {
                tracing::error!("Failed to check license: {:?}", e);
                false
            }
        };

        let response = serde_json::json!({
            "status": if is_valid { "valid" } else { "invalid or expired" }
        });

        match crypto.encrypt_response(&session_id, response) {
            Ok(encrypted_resp) => {
                let status_code = if is_valid { StatusCode::OK } else { StatusCode::FORBIDDEN };
                HttpResponse::build(status_code).json(encrypted_resp)
            }
            Err(e) => {
                tracing::error!("Failed to encrypt check_license response: {:?}", e);
                HttpResponse::InternalServerError().body("Encryption failed")
            }
        }
    } else {
        HttpResponse::BadRequest().body("Invalid request format")
    }
}

/// Report debugger detection from client: bans a session-id reported by client
pub async fn report(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    req: web::Bytes,
) -> HttpResponse {
    if let Ok(encrypted_req) = serde_json::from_slice::<EncryptedRequest>(&req) {
        let (session_id, payload) = match crypto.decrypt_request(&encrypted_req) {
            Ok(result) => result,
            Err(e) => {
                tracing::error!("Failed to decrypt report request: {:?}", e);
                e.log_security_event();
                return HttpResponse::Unauthorized().body("Decryption failed");
            }
        };

        let hwid = match payload.get("hwid").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => {
                let error_resp = serde_json::json!({"error": "hwid required"});
                return match crypto.encrypt_response(&session_id, error_resp) {
                    Ok(encrypted_err) => HttpResponse::BadRequest().json(encrypted_err),
                    Err(_) => HttpResponse::BadRequest().body("hwid required"),
                };
            }
        };

        // Get session UUID for audit/report tracking
        let reporter_uuid = match crypto.validate_access_token(&session_id) {
            Ok(uuid) => uuid.to_string(),
            Err(_) => "unknown".to_string(),
        };

        // Ban by session_id
        let ban = Ban {
            id: Uuid::new_v4().to_string(),
            banned_entity: session_id.to_string(),
            ban_type: "session".to_string(),
            reason: "client-reported debugger".to_string(),
            created_at: Utc::now().timestamp(),
            banned_by: Some(reporter_uuid.clone()),
            reporter_session: Some(reporter_uuid.clone()),
            reported_session: Some(session_id.clone()),
            evidence: Some(format!("hwid: {}", hwid)),
            status: "active".to_string(),
        };
        if let Err(e) = db::insert_ban(&db, ban) {
            tracing::error!("Failed to save ban to database: {:?}", e);
        }
        
        // Also ban by HWID
        let hwid_ban = Ban {
            id: Uuid::new_v4().to_string(),
            banned_entity: hwid.to_string(),
            ban_type: "hardware".to_string(),
            reason: "client-reported debugger".to_string(),
            created_at: Utc::now().timestamp(),
            banned_by: Some(reporter_uuid.clone()),
            reporter_session: Some(reporter_uuid.clone()),
            reported_session: Some(session_id.clone()),
            evidence: Some(format!("hwid: {}", hwid)),
            status: "active".to_string(),
        };
        if let Err(e) = db::insert_ban(&db, hwid_ban) {
            tracing::error!("Failed to save HWID ban to database: {:?}", e);
        }
        
        // Audit log
        let audit = AuditLog {
            id: Uuid::new_v4().to_string(),
            session_uuid: Some(reporter_uuid),
            event_type: "security_report".to_string(),
            event_data: serde_json::json!({
                "reported_session": session_id,
                "hwid": hwid,
            }).to_string(),
            created_at: Utc::now().timestamp(),
            ip_address: None,
        };
        if let Err(e) = db::insert_audit_log(&db, audit) {
            tracing::error!("Failed to save audit log: {:?}", e);
        }

        let response = serde_json::json!({"status": "banned"});
        match crypto.encrypt_response(&session_id, response) {
            Ok(encrypted_resp) => HttpResponse::Ok().json(encrypted_resp),
            Err(e) => {
                tracing::error!("Failed to encrypt report response: {:?}", e);
                HttpResponse::InternalServerError().body("Encryption failed")
            }
        }
    } else {
        HttpResponse::BadRequest().body("Invalid request format")
    }
}

/// Stage 1 of secure key exchange - Server sends ephemeral key
/// Server responds with: server_public_key, server_ephemeral_public, server_signature
pub async fn exchange_stage1(
    crypto: web::Data<SecuroServ>,
) -> HttpResponse {
    match crypto.perform_exchange_stage1() {
        Ok(response) => {
            tracing::info!("✅ Exchange Stage 1 completed");
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            tracing::error!("Exchange Stage 1 failed: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Stage 2 of secure key exchange - Client sends their public key
/// Client sends client_public_key_b64 and receives encrypted exchange response
pub async fn exchange_stage2(
    crypto: web::Data<SecuroServ>,
    _db: web::Data<DbPool>,
    body: web::Bytes,
) -> HttpResponse {
    // Parse the request
    let req: ExchangeStage2Request = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            tracing::error!("Failed to parse stage2 request: {}", e);
            return HttpResponse::BadRequest().body("Invalid request format");
        }
    };
    
    // Process the stage 2 exchange
    match crypto.perform_exchange_stage2(req) {
        Ok(response) => {
            tracing::info!("✅ Exchange Stage 2 completed");
            HttpResponse::Ok().json(response)
        }
        Err(e) => {
            tracing::error!("Exchange Stage 2 failed: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Authentication - validates license, returns permanent access & refresh tokens
pub async fn auth(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    admin_sessions: web::Data<AdminSessions>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    // Use decrypt_auth_request which accepts BOTH access and exchange tokens
    // Regular endpoints must use decrypt_request which only accepts access tokens
    let (session_id, payload) = match crypto.decrypt_auth_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt auth request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::info!("Auth request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    // License key is required for authentication
    let license_key = match payload.get("license_key").and_then(|v| v.as_str()) {
        Some(k) => k,
        None => {
            let error_resp = serde_json::json!({"error": "license_key required"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Forbidden().json(encrypted_err),
                Err(_) => HttpResponse::Forbidden().body("license_key required"),
            };
        }
    };

    tracing::info!("Validating license_key: {}", license_key);

    // Verify license exists and is valid
    let is_valid_license = match db::get_license_by_key(&db, license_key) {
        Ok(Some(lic)) => !lic.is_revoked && lic.expires_at > Utc::now().timestamp(),
        Ok(None) => false,
        Err(e) => {
            tracing::error!("Failed to check license: {:?}", e);
            false
        }
    };

    if !is_valid_license {
        tracing::warn!("Invalid or missing license_key: {}", license_key);
        let error_resp = serde_json::json!({"error": "invalid license_key"});
        return match crypto.encrypt_response(&session_id, error_resp) {
            Ok(encrypted_err) => HttpResponse::Forbidden().json(encrypted_err),
            Err(_) => HttpResponse::Forbidden().body("invalid license_key"),
        };
    }

    // Check if the license itself is banned
    let is_license_banned = db::is_entity_banned(&db, license_key).unwrap_or_default();
    if is_license_banned {
        tracing::warn!("License is banned: {}", license_key);
        let error_resp = serde_json::json!({"error": "license is banned"});
        return match crypto.encrypt_response(&session_id, error_resp) {
            Ok(encrypted_err) => HttpResponse::Forbidden().json(encrypted_err),
            Err(_) => HttpResponse::Forbidden().body("license is banned"),
        };
    }

    // Parse temp_jwt to get session UUID (verify it's valid and not expired)
    let session_uuid = match crypto.validate_exchange_token(&session_id) {
        Ok(uuid) => {
            tracing::info!("Exchange token validated for session: {}", uuid);
            uuid
        }
        Err(e) => {
            // If temp_jwt expired or invalid, reject
            tracing::warn!("Expired or invalid temp_jwt: {:?}", e);
            let error_resp = serde_json::json!({"error": "temp_jwt expired or invalid"});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Unauthorized().json(encrypted_err),
                Err(_) => HttpResponse::Unauthorized().body("temp_jwt expired or invalid"),
            };
        }
    };

    tracing::info!("Processing authenticated session with license: {}", license_key);

    // Check if this is the admin bootstrap license - if so, mark the session as admin
    let is_admin = license_key == ADMIN_LICENSE_KEY;
    if is_admin {
        tracing::warn!("Admin session authenticated - marking session as admin");
        admin_sessions.mark_as_admin(session_uuid);
    }

    // Generate permanent tokens
    match crypto.generate_token_pair(&session_uuid) {
        Ok(token_pair) => {
            // Persist session to database
            let now = Utc::now().timestamp();
            let session = db::Session {
                id: Uuid::new_v4().to_string(),
                session_uuid: session_uuid.to_string(),
                license_key: license_key.to_string(),
                hardware_id: None,
                client_public_key: vec![],
                client_verifying_key: String::new(),
                client_kyber_public: String::new(),
                created_at: now,
                last_heartbeat: now,
                is_authenticated: true,
            };
            
            if let Err(e) = db::insert_session(&db, session) {
                tracing::warn!("Failed to persist session to DB: {:?}", e);
            } else {
                tracing::debug!("✅ Session persisted to database");
            }
            
            // Audit log: authentication
            let audit = AuditLog {
                id: Uuid::new_v4().to_string(),
                session_uuid: Some(session_uuid.to_string()),
                event_type: "auth".to_string(),
                event_data: serde_json::json!({
                    "license_key": license_key,
                    "is_admin": is_admin,
                }).to_string(),
                created_at: now,
                ip_address: None,
            };
            if let Err(e) = db::insert_audit_log(&db, audit) {
                tracing::error!("Failed to save auth audit log: {:?}", e);
            }

            #[derive(Serialize)]
            struct AuthSuccessResponse {
                access_token: String,
                refresh_token: String,
                token_type: String,
                expires_in: u64,
            }

            let response = AuthSuccessResponse {
                access_token: token_pair.access_token,
                refresh_token: token_pair.refresh_token,
                token_type: token_pair.token_type,
                expires_in: token_pair.expires_in,
            };

            tracing::info!("Authentication successful for session: {} (admin: {})", session_uuid, is_admin);
            
            match crypto.encrypt_response(&session_id, serde_json::to_value(&response).unwrap_or(serde_json::json!({}))) {
                Ok(encrypted_resp) => HttpResponse::Ok().json(encrypted_resp),
                Err(e) => {
                    tracing::error!("Failed to encrypt auth response: {:?}", e);
                    e.log_security_event();
                    HttpResponse::InternalServerError().body("Encryption failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to generate tokens: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}

/// Receive encrypted message (POST)
pub async fn receive_encrypted(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    // Decrypt the request
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt message: {:?}", e);
            e.log_security_event();

            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Received encrypted message from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let message = payload.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("Message received");

    // Validate access token and get session UUID
    let session_uuid = match crypto.validate_access_token(&session_id) {
        Ok(uuid) => uuid.to_string(),
        Err(_) => "unknown".to_string(),
    };
    
    // Store message in database
    let msg = Message {
        id: Uuid::new_v4().to_string(),
        sender_session: session_uuid.clone(),
        recipient_session: None, // Broadcast/server message
        content: message.to_string(),
        created_at: Utc::now().timestamp(),
        is_delivered: true,
        delivered_at: Some(Utc::now().timestamp()),
    };
    if let Err(e) = db::insert_message(&db, msg) {
        tracing::warn!("Failed to store received message in DB: {:?}", e);
    }
    
    // Audit log: message received
    let audit = AuditLog {
        id: Uuid::new_v4().to_string(),
        session_uuid: Some(session_uuid.clone()),
        event_type: "message_received".to_string(),
        event_data: serde_json::json!({
            "message_preview": message.chars().take(50).collect::<String>(),
        }).to_string(),
        created_at: Utc::now().timestamp(),
        ip_address: None,
    };
    if let Err(e) = db::insert_audit_log(&db, audit) {
        tracing::debug!("Failed to save message received log: {:?}", e);
    }

    // Encrypt the response with the received message (server echoes it back)
    let response_payload = serde_json::json!({
        "message": message,
        "status": "received"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted response sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Get encrypted message (POST)
pub async fn get_encrypted(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, _payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt get_encrypted request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Get encrypted message request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let response_payload = serde_json::json!({
        "message": "Hello from server"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted response sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Send an encrypted message to a session (via encrypted request/response)
pub async fn send_encrypted(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt send_encrypted request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::debug!("Send encrypted message request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let message = payload.get("message")
        .and_then(|m| m.as_str())
        .unwrap_or("Hello from server");

    // Validate access token and get session UUID
    let session_uuid = match crypto.validate_access_token(&session_id) {
        Ok(uuid) => uuid.to_string(),
        Err(_) => "unknown".to_string(),
    };
    
    // Store message in database
    let msg = Message {
        id: Uuid::new_v4().to_string(),
        sender_session: session_uuid.clone(),
        recipient_session: None, // Broadcast/server message
        content: message.to_string(),
        created_at: Utc::now().timestamp(),
        is_delivered: true,
        delivered_at: Some(Utc::now().timestamp()),
    };
    if let Err(e) = db::insert_message(&db, msg) {
        tracing::warn!("Failed to store sent message in DB: {:?}", e);
    }
    
    // Audit log: message sent
    let audit = AuditLog {
        id: Uuid::new_v4().to_string(),
        session_uuid: Some(session_uuid),
        event_type: "message_sent".to_string(),
        event_data: serde_json::json!({
            "message_preview": message.chars().take(50).collect::<String>(),
        }).to_string(),
        created_at: Utc::now().timestamp(),
        ip_address: None,
    };
    if let Err(e) = db::insert_audit_log(&db, audit) {
        tracing::debug!("Failed to save message sent log: {:?}", e);
    }

    let response_payload = serde_json::json!({
        "message": message,
        "status": "sent"
    });

    match crypto.encrypt_response(&session_id, response_payload) {
        Ok(encrypted_resp) => {
            tracing::debug!("Encrypted message sent successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to encrypt send_encrypted response: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().body("Encryption failed")
        }
    }
}

/// Unauthenticate a client session (by access token)
pub async fn unauth(
    crypto: web::Data<SecuroServ>,
    db: web::Data<DbPool>,
    admin_sessions: web::Data<AdminSessions>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, _payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt unauth request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    let session_uuid = match crypto.validate_access_token(&session_id) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid access token in unauth: {:?}", e);
            e.log_security_event();
            
            let error_resp = serde_json::json!({"error": e.to_string()});
            return match crypto.encrypt_response(&session_id, error_resp) {
                Ok(encrypted_err) => HttpResponse::Unauthorized().json(encrypted_err),
                Err(_) => HttpResponse::Unauthorized().body(e.to_string()),
            };
        }
    };

    // Encrypt response BEFORE removing session
    let response = serde_json::json!({"status": "Session unauthenticated successfully"});
    let encrypted_resp = match crypto.encrypt_response(&session_id, response) {
        Ok(resp) => resp,
        Err(e) => {
            tracing::error!("Failed to encrypt unauth response: {:?}", e);
            e.log_security_event();
            return HttpResponse::InternalServerError().body("Encryption failed");
        }
    };

    // Remove from admin sessions if it was marked as admin
    admin_sessions.remove(&session_uuid);
    
    // Update session in DB to mark as unauthenticated
    if let Err(e) = db::update_session_authenticated(&db, &session_uuid.to_string(), false) {
        tracing::warn!("Failed to update session auth status in DB: {:?}", e);
    }
    
    // Audit log: unauthentication
    let audit = AuditLog {
        id: Uuid::new_v4().to_string(),
        session_uuid: Some(session_uuid.to_string()),
        event_type: "unauth".to_string(),
        event_data: serde_json::json!({}).to_string(),
        created_at: Utc::now().timestamp(),
        ip_address: None,
    };
    if let Err(e) = db::insert_audit_log(&db, audit) {
        tracing::error!("Failed to save unauth audit log: {:?}", e);
    }

    match crypto.unauth(&session_uuid.to_string()) {
        Ok(_) => {
            tracing::info!("Session unauthenticated successfully");
            HttpResponse::Ok().json(encrypted_resp)
        }
        Err(e) => {
            tracing::error!("Failed to unauthenticate session: {:?}", e);
            e.log_security_event();
            HttpResponse::InternalServerError().json(encrypted_resp)
        }
    }
}

/// Refresh access token using refresh token (OAuth2-style)
pub async fn refresh_token(
    crypto: web::Data<SecuroServ>,
    req: web::Json<EncryptedRequest>,
) -> HttpResponse {
    let (session_id, payload) = match crypto.decrypt_request(&req) {
        Ok(result) => result,
        Err(e) => {
            tracing::error!("Failed to decrypt refresh token request: {:?}", e);
            e.log_security_event();
            return HttpResponse::Unauthorized().body("Decryption failed");
        }
    };

    tracing::info!("Refresh token request from session: {}", &session_id[..std::cmp::min(40, session_id.len())]);

    let refresh_token = match payload.get("refresh_token").and_then(|v| v.as_str()) {
        Some(t) => t,
        None => return HttpResponse::BadRequest().body("refresh_token required in encrypted payload"),
    };

    let session_uuid = match crypto.validate_refresh_token(refresh_token) {
        Ok(u) => u,
        Err(e) => {
            tracing::error!("Invalid refresh token: {:?}", e);
            e.log_security_event();
            return HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string());
        }
    };

    match crypto.generate_token_pair(&session_uuid) {
        Ok(tp) => {
            #[derive(Serialize)]
            struct RefreshResponse {
                access_token: String,
                token_type: String,
                expires_in: u64,
            }
            let resp = RefreshResponse { access_token: tp.access_token, token_type: tp.token_type, expires_in: tp.expires_in };
            
            match crypto.encrypt_response(&session_id, serde_json::to_value(&resp).unwrap_or(serde_json::json!({}))) {
                Ok(encrypted_resp) => {
                    tracing::info!("Refresh token successful, response encrypted");
                    HttpResponse::Ok().json(encrypted_resp)
                }
                Err(e) => {
                    tracing::error!("Failed to encrypt refresh token response: {:?}", e);
                    e.log_security_event();
                    HttpResponse::InternalServerError().body("Encryption failed")
                }
            }
        }
        Err(e) => {
            tracing::error!("Failed to generate tokens: {:?}", e);
            e.log_security_event();
            HttpResponse::build(StatusCode::from_u16(e.status_code()).unwrap()).body(e.to_string())
        }
    }
}
