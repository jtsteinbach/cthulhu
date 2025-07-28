// src/main.rs
mod config;
mod rules;
mod event;
mod evaluator;
mod alert;
mod processor;

use std::{
    fs::{self, Permissions},
    os::unix::fs::PermissionsExt,
    sync::{Arc, Mutex},
    collections::{HashMap, HashSet},
    io,
    path::Path,
    process::Command,
};
use chrono::{DateTime, Utc};
use serde_json::Value;
use config::load_config;
use rules::load_rules;
use event::extract_event;
use evaluator::rule_matches;
use alert::{build_alert_signature, dispatch_alert};
use processor::{spawn_audit_processor, stream_journal};

pub const RULES_FILE: &str   = "/cthulhu/rules";
pub const CONFIG_FILE: &str  = "/cthulhu/config";
pub const ALERTS_DIR: &str   = "/cthulhu/alerts";
pub const AUDIT_LOG: &str    = "/var/log/audit/audit.log";

pub const F_CMDLINE: &str    = "_CMDLINE";
pub const F_EXE: &str        = "_EXE";
pub const F_PID: &str        = "_PID";
pub const F_UID: &str        = "_UID";
pub const F_MSG: &str        = "MESSAGE";
pub const F_CURSOR: &str     = "__CURSOR";
pub const F_SRC_IP: &str     = "SRC_IP";
pub const F_SRC_PORT: &str   = "SRC_PORT";
pub const F_DST_IP: &str     = "DST_IP";
pub const F_DST_PORT: &str   = "DST_PORT";
pub const F_LISTEN_PID: &str = "LISTEN_PID";
pub const F_LISTEN_FDS: &str = "LISTEN_FDS";
pub const F_REALTIME: &str   = "__REALTIME_TIMESTAMP";

// Ensure auditd is installed
fn ensure_auditd_installed() -> io::Result<()> {
    let output = Command::new("which").arg("auditd").output()?;
    if !output.status.success() {
        println!("🛠️ auditd not found. Installing...");
        let script = "./src/scripts/install_auditd.sh";
        if !Path::new(script).exists() {
            return Err(io::Error::new(io::ErrorKind::NotFound, "Missing install_auditd.sh"));
        }
        let status = Command::new("bash").arg(script).status()?;
        if !status.success() {
            return Err(io::Error::new(io::ErrorKind::Other, "auditd install script failed"));
        }
    } else {
        println!("Auditd already installed.");
    }
    Ok(())
}

// Ensure config exists
fn ensure_config_exists() -> io::Result<()> {
    if !Path::new(CONFIG_FILE).exists() {
        println!("Creating default config at {CONFIG_FILE}...");
        let default = b"alerts_dir = allow\nalerts_journald = allow\n";
        fs::create_dir_all(Path::new(CONFIG_FILE).parent().unwrap())?;
        fs::write(CONFIG_FILE, default)?;
    }
    Ok(())
}

fn main() -> io::Result<()> {
    ensure_auditd_installed()?;
    ensure_config_exists()?;

    fs::create_dir_all(ALERTS_DIR)?;
    fs::set_permissions(ALERTS_DIR, Permissions::from_mode(0o700))?;

    tracing_subscriber::fmt().init();

    let cfg = load_config().map_err(|e| {
        eprintln!("Failed to load config: {}", e);
        e
    })?;

    let rules = Arc::new(load_rules().map_err(|e| {
        eprintln!("Failed to load rules: {}", e);
        e
    })?);

    let seen_signatures: Arc<Mutex<HashMap<String, DateTime<Utc>>>> =
        Arc::new(Mutex::new(HashMap::new()));

    // Spawn audit log processor
    {
        let rules_clone = Arc::clone(&rules);
        let seen_clone = Arc::clone(&seen_signatures);
        let cfg_clone = cfg.clone();
        spawn_audit_processor(rules_clone, seen_clone, cfg_clone);
    }

    // Main thread: process journald logs
    let mut seen_cursor: HashSet<String> = HashSet::new();
    let mut rules_index = Arc::try_unwrap(rules).unwrap_or_else(|arc| (*arc).clone());
    let mut last_mod = fs::metadata(RULES_FILE)?.modified()?;

    for line in stream_journal()? {
        // Reload rules if modified
        if let Ok(meta) = fs::metadata(RULES_FILE) {
            if let Ok(modified) = meta.modified() {
                if modified > last_mod {
                    if let Ok(new_rules) = load_rules() {
                        rules_index = new_rules;
                        last_mod = modified;
                        println!("Reloaded rules after modification");
                    }
                }
            }
        }

        if let Ok(l) = line {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&l) {
                let cursor = map.get(F_CURSOR).and_then(Value::as_str).unwrap_or_default().to_string();
                if !seen_cursor.insert(cursor.clone()) { continue; }
                let event = extract_event(&map);
                let now = Utc::now();
                {
                    let mut seen = seen_signatures.lock().unwrap();
                    seen.retain(|_, &mut ts| now.signed_duration_since(ts).num_seconds() < 60);
                }
                for key in &[Some(event.event_type.clone()), None] {
                    if let Some(bucket) = rules_index.get(key) {
                        for rule in bucket {
                            if rule_matches(&event, rule) {
                                let sig = build_alert_signature(rule, &event);
                                let mut seen = seen_signatures.lock().unwrap();
                                if !seen.contains_key(&sig) {
                                    seen.insert(sig.clone(), now);
                                    dispatch_alert(rule, &event, &sig, &cfg);
                                    println!("Journal-alert {} fired", rule.name);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Ok(())
}
