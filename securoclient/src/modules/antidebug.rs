use securo::client::crypto::{SecuroClient, EncryptedResponse};

#[inline(always)]
pub fn detect_from_procfs() -> bool {
    if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
        let tracer_pid = status.lines().find(|line| line.starts_with("TracerPid:"));
        if let Some(tracer_pid) = tracer_pid
            && let Some(pid) = tracer_pid.split(':').nth(1) {
                let pid = pid.trim();
                if pid != "0" {
                    return true;
                }
            }
    }
    false
}

pub fn get_machine_id() -> Result<String, Box<dyn std::error::Error>> {
    #[cfg(target_os = "linux")]
    {
        let machine_id = std::fs::read_to_string("/etc/machine-id")?;
        Ok(machine_id.trim().to_string())
    }
    #[cfg(target_os = "windows")]
    {
        let machine_id = {
            use winreg::enums::HKEY_LOCAL_MACHINE;
            use winreg::RegKey;
            let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
            let key = hklm.open_subkey("SOFTWARE\\Microsoft\\Cryptography")?;
            key.get_value("MachineGuid")?
        };
        Ok(machine_id)
    }
}

pub async fn report_debugger_detection(
    client: &reqwest::Client,
    crypto: &SecuroClient,
    hwid: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    tracing::warn!("Debugger detected! Reporting to server...");
    
    let session_id = crypto.get_session_id()
        .ok_or("Session ID not set")?;
    
    let payload = serde_json::json!({
        "hwid": hwid
    });
    
    let encrypted_req = crypto.encrypt_request(session_id, payload)?;
    
    let resp = client
        .post("https://127.0.0.1:8443/api/report")
        .json(&encrypted_req)
        .send()
        .await?;
    
    if resp.status().is_success() {
        let encrypted_resp: EncryptedResponse = resp.json().await?;
        let _response_data = crypto.decrypt_response(&encrypted_resp)?;
        tracing::info!("✅ Debugger report sent successfully");
    } else {
        tracing::error!("Failed to report debugger: Status {}", resp.status());
    }
    
    Ok(())
}

/// Background task to continuously monitor for debuggers
pub async fn debugger_monitor_task(
    client: reqwest::Client,
    crypto: SecuroClient,
    hwid: String,
) {
    let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(5));
    
    loop {
        interval.tick().await;
        
        #[cfg(target_os = "linux")]
        {
            if detect_from_procfs() {
                tracing::warn!("Debugger detected via /proc/self/status!");
                
                // Report to server
                if let Err(e) = report_debugger_detection(&client, &crypto, &hwid).await {
                    tracing::error!("Failed to report debugger: {}", e);
                } else {
                    tracing::warn!("Machine ID {} has been banned by server", hwid);
                    tracing::error!("Terminating client due to debugger detection");
                    std::process::exit(1);
                }
            }
        }

        #[cfg(target_os = "windows")]
        {
            if unsafe { winapi::um::debugapi::IsDebuggerPresent() } != 0 {
                tracing::warn!("Debugger detected via IsDebuggerPresent!");
                
                // Report to server
                if let Err(e) = report_debugger_detection(&client, &crypto, &hwid).await {
                    tracing::error!("Failed to report debugger: {}", e);
                } else {
                    tracing::warn!("Machine ID {} has been banned by server", hwid);
                    tracing::error!("Terminating client due to debugger detection");
                    std::process::exit(1);
                }
            }
        }
    }
}
