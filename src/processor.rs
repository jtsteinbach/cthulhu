// src/processor.rs
use std::{sync::{Arc, Mutex}, io::{self, BufRead, BufReader}, thread};
use std::process::{Command, Stdio};
use chrono::Utc;
use serde_json::Value;
use crate::rules::RuleIndex;
use crate::event::extract_event;
use crate::evaluator::{rule_matches};
use crate::alert::{build_alert_signature, dispatch_alert};
use crate::config::Config;
use crate::{AUDIT_LOG, F_REALTIME};

/// Spawn a thread that tails the audit log and processes events.
pub fn spawn_audit_processor(
    rules: Arc<RuleIndex>,
    seen: Arc<Mutex<std::collections::HashMap<String, chrono::DateTime<Utc>>>>,
    cfg: Config
) {
    thread::spawn(move || {
        let parser = linux_audit_parser::Parser::default();
        let child = match Command::new("tail")
            .args(&["-n", "0", "-F", AUDIT_LOG])
            .stdout(Stdio::piped())
            .spawn()
        {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Failed to spawn tail for {}: {}", AUDIT_LOG, e);
                return;
            }
        };
        let stdout = child.stdout.expect("Failed to capture tail stdout");
        let reader = BufReader::new(stdout);

        for line_res in reader.lines() {
            if let Ok(line) = line_res {
                if let Ok(msg) = parser.parse(line.as_bytes()) {
                    let mut json_map = serde_json::Map::new();
                    let mut has_syscall = false;
                    for (k, v) in msg.body {
                        let key_str = k.to_string();
                        if key_str == "syscall" { has_syscall = true; }
                        json_map.insert(key_str, Value::String(format!("{:?}", v)));
                    }
                    if !has_syscall { continue; }
                    if let Some(Value::String(ts_str)) = json_map.get("msg") {
                        if let (Some(start), Some(colon)) = (ts_str.find('('), ts_str.find(':')) {
                            if let Ok(us_int) = ts_str[start+1..colon].replace('.', "").parse::<i64>() {
                                json_map.insert(F_REALTIME.to_string(), Value::String(us_int.to_string()));
                            }
                        }
                    }
                    let event = extract_event(&json_map);
                    let now = Utc::now();
                    {
                        let mut seen_map = seen.lock().unwrap();
                        seen_map.retain(|_, &mut ts| now.signed_duration_since(ts).num_seconds() < 60);
                    }
                    for key in &[Some(event.event_type.clone()), None] {
                        if let Some(bucket) = rules.get(key) {
                            for rule in bucket {
                                if rule_matches(&event, rule) {
                                    let sig = build_alert_signature(rule, &event);
                                    let mut seen_map = seen.lock().unwrap();
                                    if !seen_map.contains_key(&sig) {
                                        seen_map.insert(sig.clone(), now);
                                        dispatch_alert(rule, &event, &sig, &cfg);
                                        println!("Audit alert fired: {}", rule.name);
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    });
}

/// Stream journald JSON lines.
pub fn stream_journal() -> io::Result<impl Iterator<Item = io::Result<String>>> {
    let mut cmd = Command::new("journalctl");
    cmd.args(&["-f", "-o", "json"]).stdout(Stdio::piped());
    let child = cmd.spawn()?;
    let stdout = child.stdout.ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No stdout"))?;
    Ok(BufReader::new(stdout).lines())
}
