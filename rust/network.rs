use serde::Serialize;
use serde_json::{json, Value};

#[derive(Clone, Serialize)]
pub struct PluginNetworkResponse {
    pub status: u16,
    pub body: Value,
}

pub async fn dispatch_plugin_network_request(request_json: String) -> Result<PluginNetworkResponse, String> {
    let request: Value = serde_json::from_str(&request_json)
        .map_err(|e| format!("Invalid request JSON: {e}"))?;

    let operation = request
        .get("operation")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    Ok(PluginNetworkResponse {
        status: 501,
        body: json!({
            "ok": false,
            "error": "CTB tauri network dispatcher is not implemented yet",
            "operation": operation,
        }),
    })
}
