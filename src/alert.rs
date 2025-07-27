// src/alert.rs
use rand::{distributions::Alphanumeric, Rng};
use serde_json::json;
use sha2::{Sha256, Digest};
use std::fs::File;
use std::io::Write;
use std::process::{Command, Stdio};
use chrono::Local;
use crate::event::Event;
use crate::rules::RuleSpec;
use crate::evaluator::get_field;
use crate::ALERTS_DIR;

/// Generate a random alert ID.
pub fn generate_alert_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

/// Build a signature for the alert.
pub fn build_alert_signature(rule: &RuleSpec, event: &Event) -> String {
    let cmd = get_field(event, "_CMDLINE").as_str().unwrap_or("na").to_string();

    fn to_string_opt<T: ToString>(opt: &Option<T>) -> String {
        opt.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "na".into())
    }

    let sig_obj = json!({
        "rule":       rule.name,
        "event_type": event.event_type,
        "uid":        to_string_opt(&event.uid),
        "user":       event.user.clone().unwrap_or_else(|| "na".into()),
        "is_admin":   event.is_admin.map(|b| b.to_string()).unwrap_or_else(|| "na".into()),
        "ip_src":     event.ip_src.clone().unwrap_or_else(|| "na".into()),
        "port_src":   event.port_src.map(|p| p.to_string()).unwrap_or_else(|| "na".into()),
        "ip_dst":     event.ip_dst.clone().unwrap_or_else(|| "na".into()),
        "port_dst":   event.port_dst.map(|p| p.to_string()).unwrap_or_else(|| "na".into()),
        "path":       event.path.clone().unwrap_or_else(|| "na".into()),
        "command":    cmd,
    });

    let mut hasher = Sha256::new();
    hasher.update(sig_obj.to_string().as_bytes());
    format!("{:x}", hasher.finalize())
}

/// Dispatch the alert based on config.
pub fn dispatch_alert(rule: &RuleSpec, event: &Event, signature: &str, cfg: &crate::config::Config) {
    let alert_id = generate_alert_id();
    let ts_local = event.time.with_timezone(&Local).format("%Y-%m-%d %H:%M:%S").to_string();

    let alert_obj = json!({
        "alertID":        alert_id,
        "alertSignature": signature,
        "time":           ts_local,
        "alertName":      rule.name,
        "description":    rule.description,
        "event":          event,
    });
    let body = serde_json::to_string_pretty(&alert_obj).unwrap() + "\n";

    if cfg.alerts_dir {
        let filename = format!(
            "{}/{}_{}_{}.alert",
            ALERTS_DIR,
            rule.name,
            event.time.with_timezone(&Local).format("%Y%m%d_%H%M%S"),
            alert_id
        );
        let _ = File::create(&filename).and_then(|mut f| f.write_all(body.as_bytes()));
    }

    if cfg.alerts_journald {
        if let Ok(mut logger) = Command::new("logger")
            .arg("-t")
            .arg("alerts")
            .stdin(Stdio::piped())
            .spawn()
        {
            if let Some(mut stdin) = logger.stdin.take() {
                let _ = stdin.write_all(body.as_bytes());
            }
            let _ = logger.wait();
        }
    }
}