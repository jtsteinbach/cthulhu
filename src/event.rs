// src/event.rs
use chrono::{DateTime, Utc, TimeZone};
use serde::Serialize;
use serde_json::Value;
use std::collections::HashMap;

/// A single event, combining journald fields and any merged auditd keys.
#[derive(Debug, Serialize)]
pub struct Event {
    pub pid: Option<u32>,
    pub uid: Option<u32>,
    pub user: Option<String>,
    pub is_admin: Option<bool>,
    pub ip_src: Option<String>,
    pub port_src: Option<u16>,
    pub ip_dst: Option<String>,
    pub port_dst: Option<u16>,
    pub path: Option<String>,
    pub time: DateTime<Utc>,
    pub event_type: String,
    pub message: Option<String>,
    pub extra: HashMap<String, Value>,
}

/// Extract an Event from a JSON‐style map.
pub fn extract_event(map: &serde_json::Map<String, Value>) -> Event {
    let pid = map.get(crate::F_PID)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .or_else(|| map.get("pid").and_then(Value::as_str).and_then(|s| s.parse().ok()));

    let uid = map.get(crate::F_UID)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .or_else(|| map.get("auid").and_then(Value::as_str).and_then(|s| s.parse().ok()))
        .or_else(|| map.get("uid").and_then(Value::as_str).and_then(|s| s.parse().ok()));

    let user = map.get("_USER_NAME").and_then(Value::as_str).map(String::from);
    let is_admin = uid.map(|u| u == 0);

    let ip_src = map.get(crate::F_SRC_IP).and_then(Value::as_str).map(String::from);
    let port_src = map.get(crate::F_SRC_PORT).and_then(Value::as_str).and_then(|s| s.parse().ok());
    let ip_dst = map.get(crate::F_DST_IP).and_then(Value::as_str).map(String::from);
    let port_dst = map.get(crate::F_DST_PORT).and_then(Value::as_str).and_then(|s| s.parse().ok());

    let path = if let Some(p) = map.get(crate::F_EXE).and_then(Value::as_str) {
        Some(p.to_string())
    } else if let Some(p) = map.get("path").and_then(Value::as_str) {
        Some(p.to_string())
    } else {
        None
    };

    let event_type = if let Some(Value::String(syscall)) = map.get("syscall") {
        match syscall.as_str() {
            "execve" => "exec".to_string(),
            "connect" => "outbound_conn".to_string(),
            "accept" => "inbound_conn".to_string(),
            "listen" => "port_listen".to_string(),
            _ => {
                if map.get("exe").and_then(Value::as_str).is_some() {
                    "program_start".to_string()
                } else {
                    "other".to_string()
                }
            }
        }
    } else if map.contains_key(crate::F_CMDLINE) {
        "exec".to_string()
    } else if map.get(crate::F_SRC_IP).is_some() && map.get(crate::F_DST_PORT).is_none() {
        "inbound_conn".to_string()
    } else if map.get(crate::F_DST_IP).is_some() && map.get(crate::F_SRC_PORT).is_none() {
        "outbound_conn".to_string()
    } else if map.get(crate::F_LISTEN_PID).is_some() || map.get(crate::F_LISTEN_FDS).is_some() {
        "port_listen".to_string()
    } else if map.get(crate::F_EXE).is_some() {
        "program_start".to_string()
    } else if let Some(msg) = map.get(crate::F_MSG).and_then(Value::as_str) {
        if msg.contains("session opened") {
            "login".to_string()
        } else if msg.contains("session closed") {
            "logout".to_string()
        } else {
            "other".to_string()
        }
    } else {
        "other".to_string()
    };

    let time = map.get(crate::F_REALTIME)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|u| {
            let secs = u / 1_000_000;
            let nsecs = ((u % 1_000_000) * 1_000) as u32;
            Utc.timestamp_opt(secs, nsecs).single()
        })
        .unwrap_or_else(Utc::now);

    let message = map.get(crate::F_MSG).and_then(Value::as_str).map(String::from);
    let extra = map.clone().into_iter().collect();

    Event { pid, uid, user, is_admin, ip_src, port_src, ip_dst, port_dst, path, time, event_type, message, extra }
}