// shard siem src/main.rs
//
// NOTES NEED TO DO: use auditd and AIDE intrusion detection environment to make SIEM POWERFUL
//
use std::{
    collections::{HashMap, HashSet},
    fs::{self, File, Permissions},
    io::{self, BufRead, BufReader, Write},
    os::unix::fs::PermissionsExt,
    process::{Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::SystemTime,
};
use chrono::{DateTime, Utc, TimeZone};
use ipnetwork::IpNetwork;
use linux_audit_parser::Parser as AuditParser;
use rand::{distributions::Alphanumeric, Rng};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{self, json, Value};
use sha2::{Digest, Sha256};
use tracing::{error, info};

// Paths to configuration and rules
const RULES_FILE: &str   = "/obsidian/shard/siem/rules";
const CONFIG_FILE: &str  = "/obsidian/shard/siem/config";
const ALERTS_DIR: &str   = "/obsidian/shard/siem/alerts";
const AUDIT_LOG: &str    = "/var/log/audit/audit.log";

// Field constants (journald)
const F_CMDLINE: &str    = "_CMDLINE";
const F_EXE: &str        = "_EXE";
const F_PID: &str        = "_PID";
const F_UID: &str        = "_UID";
const F_MSG: &str        = "MESSAGE";
const F_CURSOR: &str     = "__CURSOR";
const F_SRC_IP: &str     = "SRC_IP";
const F_SRC_PORT: &str   = "SRC_PORT";
const F_DST_IP: &str     = "DST_IP";
const F_DST_PORT: &str   = "DST_PORT";
const F_LISTEN_PID: &str = "LISTEN_PID";
const F_LISTEN_FDS: &str = "LISTEN_FDS";
const F_REALTIME: &str   = "__REALTIME_TIMESTAMP";

/// A single event, combining journald fields (and any “auditd.*” keys we merged into the Map).
#[derive(Debug, Serialize)]
struct Event {
    pid: Option<u32>,
    uid: Option<u32>,
    user: Option<String>,
    is_admin: Option<bool>,
    ip_src: Option<String>,
    port_src: Option<u16>,
    ip_dst: Option<String>,
    port_dst: Option<u16>,
    path: Option<String>,
    time: DateTime<Utc>,
    event_type: String,
    message: Option<String>,
    extra: HashMap<String, Value>,
}

#[derive(Debug, Deserialize, Clone)]
struct RuleSpec {
    name: String,
    description: String,
    event_type: Option<String>,
    criteria: Vec<Criterion>,
}

#[derive(Debug, Deserialize, Clone)]
struct Criterion {
    field: String,
    op: String,
    value: Value, // if op=="exists" or "missing", value==Value::Bool(true)
}

type RuleIndex = HashMap<Option<String>, Vec<RuleSpec>>;

/// Controls whether we emit alerts into files, journald, or both.
#[derive(Clone)]
struct Config {
    alerts_dir: bool,
    alerts_journald: bool,
}

impl Config {
    fn load() -> io::Result<Self> {
        let file = match File::open(CONFIG_FILE) {
            Ok(f) => f,
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("Config file not found: {}", CONFIG_FILE),
                ));
            }
            Err(e) => return Err(e),
        };

        let reader = BufReader::new(file);
        let mut alerts_dir = false;
        let mut alerts_journald = false;

        for line_res in reader.lines() {
            let line = line_res?;
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if let Some((key, val)) = trimmed.split_once('=') {
                let key = key.trim();
                let val = val.trim();
                match key {
                    "alerts_dir" => {
                        alerts_dir = matches!(val, "allow");
                    }
                    "alerts_journald" => {
                        alerts_journald = matches!(val, "allow");
                    }
                    _ => {}
                }
            }
        }

        Ok(Config {
            alerts_dir,
            alerts_journald,
        })
    }
}

/// Load all rules from the DSL file at RULES_FILE. Each rule block looks like:
///     rule_name(event_type)
///         | "Description"
///         : field operator value
/// Or for existence checks:
///     : field exists
///     : field missing
/// Skip empty lines and lines starting with '#' or '//' .
fn load_rules() -> io::Result<RuleIndex> {
    let file = File::open(RULES_FILE)?;
    let mut idx = RuleIndex::new();
    let reader = BufReader::new(file);
    let mut current_rule: Option<RuleSpec> = None;

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();

        // Skip blank lines or lines starting with '#' or '//'
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        // Detect start of a new rule: name(event_type)
        if let Some(end) = trimmed.strip_suffix(')') {
            if let Some((name, event_type)) = end.split_once('(') {
                if let Some(rule) = current_rule.take() {
                    idx.entry(rule.event_type.clone()).or_default().push(rule);
                }
                current_rule = Some(RuleSpec {
                    name: name.trim().to_string(),
                    event_type: Some(event_type.trim().to_string()),
                    description: String::new(),
                    criteria: Vec::new(),
                });
            }
        }
        // Parse description line starting with '|'
        else if trimmed.starts_with('|') {
            if let Some(rule) = current_rule.as_mut() {
                rule.description = trimmed[1..].trim().trim_matches('"').to_string();
            }
        }
        // Parse a criterion line starting with ':'
        else if trimmed.starts_with(':') {
            if let Some(rule) = current_rule.as_mut() {
                let expr = trimmed[1..].trim();
                let parts: Vec<&str> = expr.split_whitespace().collect();
                if parts.len() == 2 && (parts[1] == "exists" || parts[1] == "missing") {
                    rule.criteria.push(Criterion {
                        field: parts[0].to_string(),
                        op: parts[1].to_string(),
                        value: Value::Bool(true),
                    });
                } else if parts.len() >= 3 {
                    let field = parts[0];
                    let op = parts[1];
                    let val_str = parts[2..].join(" ");
                    let value = if val_str.starts_with('[') && val_str.ends_with(']') {
                        serde_json::from_str::<Value>(&val_str).unwrap_or(Value::String(val_str))
                    } else if val_str.starts_with('"') && val_str.ends_with('"') {
                        Value::String(val_str.trim_matches('"').to_string())
                    } else if let Ok(n) = val_str.parse::<f64>() {
                        Value::Number(serde_json::Number::from_f64(n).unwrap())
                    } else {
                        Value::String(val_str)
                    };
                    rule.criteria.push(Criterion {
                        field: field.to_string(),
                        op: op.to_string(),
                        value,
                    });
                }
            }
        }
    }

    if let Some(rule) = current_rule {
        idx.entry(rule.event_type.clone()).or_default().push(rule);
    }

    Ok(idx)
}

/// Compare two JSON values with extended operators.
fn compare(a: &Value, op: &str, b: &Value) -> bool {
    match op {
        "==" => a == b,
        "!=" => a != b,
        ">" | ">=" | "<" | "<=" => {
            if let (Some(an), Some(bn)) = (a.as_f64(), b.as_f64()) {
                match op {
                    ">"  => an > bn,
                    ">=" => an >= bn,
                    "<"  => an < bn,
                    "<=" => an <= bn,
                    _    => false,
                }
            } else {
                false
            }
        }
        "contains" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                as_.contains(bs)
            } else {
                false
            }
        }
        "icontains" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                as_.to_lowercase().contains(&bs.to_lowercase())
            } else {
                false
            }
        }
        "startswith" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                as_.starts_with(bs)
            } else {
                false
            }
        }
        "endswith" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                as_.ends_with(bs)
            } else {
                false
            }
        }
        "matches" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                if let Ok(re) = Regex::new(bs) {
                    re.is_match(as_)
                } else {
                    false
                }
            } else {
                false
            }
        }
        "in" | "not_in" => {
            if let Value::Array(list) = b {
                if let Some(val_str) = a.as_str() {
                    let contains = list.iter().any(|item| item == &Value::String(val_str.to_string()));
                    if op == "in" { contains } else { !contains }
                } else if let Some(val_n) = a.as_f64() {
                    let contains = list.iter().any(|item| item.as_f64().map_or(false, |bn| bn == val_n));
                    if op == "in" { contains } else { !contains }
                } else {
                    false
                }
            } else {
                false
            }
        }
        "bitwise_and" | "&" => {
            if let (Some(an), Some(bn)) = (a.as_u64(), b.as_u64()) {
                (an & bn) != 0
            } else {
                false
            }
        }
        "between" | "not_between" => {
            if let (Some(an), Value::Array(arr)) = (a.as_f64(), b) {
                if arr.len() == 2 {
                    if let (Some(min), Some(max)) = (arr[0].as_f64(), arr[1].as_f64()) {
                        let in_range = an >= min && an <= max;
                        if op == "between" { in_range } else { !in_range }
                    } else { false }
                } else { false }
            } else {
                false
            }
        }
        "cidr_contains" | "in_cidr" => {
            if let (Some(ip_str), Some(cidr_str)) = (a.as_str(), b.as_str()) {
                if let (Ok(ip), Ok(network)) = (ip_str.parse::<std::net::IpAddr>(), cidr_str.parse::<IpNetwork>()) {
                    let contains = network.contains(ip);
                    if op == "cidr_contains" { contains } else { !contains }
                } else {
                    false
                }
            } else {
                false
            }
        }
        "before" | "after" => {
            if let (Some(a_str), Some(b_str)) = (a.as_str(), b.as_str()) {
                if let (Ok(a_time), Ok(b_time)) = (
                    DateTime::parse_from_rfc3339(a_str).map(|dt| dt.with_timezone(&Utc)),
                    DateTime::parse_from_rfc3339(b_str).map(|dt| dt.with_timezone(&Utc)),
                ) {
                    if op == "before" { a_time < b_time } else { a_time > b_time }
                } else { false }
            } else { false }
        }
        "within" => {
            if let Some(a_time) = a.as_str().and_then(|s| DateTime::parse_from_rfc3339(s).ok()).map(|dt| dt.with_timezone(&Utc)) {
                if let Some(dur_str) = b.as_str() {
                    let num: i64 = dur_str[..dur_str.len()-1].parse().unwrap_or(0);
                    let unit = &dur_str[dur_str.len()-1..];
                    let duration = match unit {
                        "s" => chrono::Duration::seconds(num),
                        "m" => chrono::Duration::seconds(num * 60),
                        "h" => chrono::Duration::seconds(num * 3600),
                        "d" => chrono::Duration::seconds(num * 86400),
                        _ => chrono::Duration::seconds(0),
                    };
                    let cutoff = Utc::now() - duration;
                    a_time >= cutoff
                } else {
                    false
                }
            } else {
                false
            }
        }
        _ => false,
    }
}

/// Determine if a given field exists in the event, using prefix logic.
/// Supports top-level fields (“path”, “event_type”), prefixed “journald.FIELD” or “auditd.FIELD”,
/// and falls back to unprefixed extra.
fn field_exists(event: &Event, field_name: &str) -> bool {
    if field_name == "path" {
        return event.path.is_some();
    }
    if field_name == "event_type" {
        return true;
    }
    if let Some(stripped) = field_name.strip_prefix("journald.") {
        return event.extra.contains_key(stripped);
    }
    if let Some(stripped) = field_name.strip_prefix("auditd.") {
        return event.extra.contains_key(stripped);
    }
    event.extra.contains_key(field_name)
}

/// Fetch the value of any field given its DSL name:
/// - "path", "event_type", prefixed "journald.X" / "auditd.X"
/// - fallback to unprefixed extra
fn get_field_value(event: &Event, field_name: &str) -> Value {
    if field_name == "path" {
        return event
            .path
            .clone()
            .map(Value::String)
            .unwrap_or(Value::String("".into()));
    }
    if field_name == "event_type" {
        return Value::String(event.event_type.clone());
    }
    if let Some(stripped) = field_name.strip_prefix("journald.") {
        return event
            .extra
            .get(stripped)
            .cloned()
            .unwrap_or(Value::String("".into()));
    }
    if let Some(stripped) = field_name.strip_prefix("auditd.") {
        return event
            .extra
            .get(stripped)
            .cloned()
            .unwrap_or(Value::String("".into()));
    }
    event
        .extra
        .get(field_name)
        .cloned()
        .unwrap_or(Value::String("".into()))
}

fn matches(event: &Event, rule: &RuleSpec) -> bool {
    for crit in &rule.criteria {
        if crit.op == "exists" {
            if !field_exists(event, &crit.field) {
                return false;
            }
            continue;
        }
        if crit.op == "missing" {
            if field_exists(event, &crit.field) {
                return false;
            }
            continue;
        }
        let val = get_field_value(event, &crit.field);
        if !compare(&val, &crit.op, &crit.value) {
            return false;
        }
    }
    true
}

fn gen_alert_id() -> String {
    rand::thread_rng()
        .sample_iter(&Alphanumeric)
        .take(12)
        .map(char::from)
        .collect()
}

fn build_signature(rule: &RuleSpec, event: &Event) -> String {
    let cmd = get_field_value(event, "journald._CMDLINE")
        .as_str()
        .unwrap_or("na")
        .to_string();

    fn s<T: ToString>(opt: &Option<T>) -> String {
        opt.as_ref().map(|v| v.to_string()).unwrap_or_else(|| "na".into())
    }

    let sig_obj = json!({
        "rule":       rule.name,
        "event_type": event.event_type,
        "uid":        s(&event.uid),
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

/// Write an alert according to config flags:
/// - If alerts_dir is true, write a file under ALERTS_DIR with timestamp + alert_id.
/// - If alerts_journald is true, send to `logger`.
fn write_alert(
    rule: &RuleSpec,
    event: &Event,
    alert_sig: &str,
    allow_dir: bool,
    allow_journald: bool,
) {
    let alert_id = gen_alert_id();
    let ts_local = event
        .time
        .with_timezone(&chrono::Local)
        .format("%Y-%m-%d %H:%M:%S")
        .to_string();

    if allow_dir {
        let filename = format!(
            "{}/{}_{}_{}.alert",
            ALERTS_DIR,
            rule.name,
            event
                .time
                .with_timezone(&chrono::Local)
                .format("%Y%m%d_%H%M%S"),
            alert_id
        );

        let alert_obj = json!({
            "alertID":        alert_id,
            "alertSignature": alert_sig,
            "time":           ts_local,
            "alertName":      rule.name,
            "description":    rule.description,
            "event":          event,
        });
        let body = serde_json::to_string_pretty(&alert_obj).unwrap() + "\n";

        let _ = File::create(&filename)
            .and_then(|mut f| f.write_all(body.as_bytes()));
    }

    if allow_journald {
        let alert_obj = json!({
            "alertID":        alert_id,
            "alertSignature": alert_sig,
            "time":           ts_local,
            "alertName":      rule.name,
            "description":    rule.description,
            "event":          event,
        });
        let body = serde_json::to_string_pretty(&alert_obj).unwrap() + "\n";

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

fn stream_journal() -> io::Result<impl Iterator<Item = io::Result<String>>> {
    let mut cmd = Command::new("journalctl");
    cmd.args(&["-f", "-o", "json"]).stdout(Stdio::piped());
    let child = cmd.spawn()?;
    let stdout = child
        .stdout
        .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "No stdout"))?;
    Ok(BufReader::new(stdout).lines())
}

/// Extract an Event from a JSON‐style `map`. For journald lines, the JSON keys are as-is.
/// For auditd‐derived events, we insert `auditd.*` keys (and then route into the same logic).
fn extract_event_from_json(map: &serde_json::Map<String, Value>) -> Event {
    let pid = map
        .get(F_PID)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            map.get("pid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
        });

    let uid = map
        .get(F_UID)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok())
        .or_else(|| {
            map.get("auid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
        })
        .or_else(|| {
            map.get("uid")
                .and_then(Value::as_str)
                .and_then(|s| s.parse().ok())
        });

    let user = map.get("_USER_NAME").and_then(Value::as_str).map(String::from);
    let is_admin = uid.map(|u| u == 0);

    let ip_src = map.get(F_SRC_IP).and_then(Value::as_str).map(String::from);
    let port_src = map
        .get(F_SRC_PORT)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok());
    let ip_dst = map.get(F_DST_IP).and_then(Value::as_str).map(String::from);
    let port_dst = map
        .get(F_DST_PORT)
        .and_then(Value::as_str)
        .and_then(|s| s.parse().ok());

    let path = if let Some(p) = map.get(F_EXE).and_then(Value::as_str) {
        Some(p.to_string())
    } else if let Some(p) = map.get("path").and_then(Value::as_str) {
        Some(p.to_string())
    } else {
        None
    };

    let event_type = if let Some(Value::String(syscall)) = map.get("syscall") {
        match syscall.as_str() {
            "execve"   => "exec".to_string(),
            "connect"  => "outbound_conn".to_string(),
            "accept"   => "inbound_conn".to_string(),
            "listen"   => "port_listen".to_string(),
            _ => {
                if map.get("exe").and_then(Value::as_str).is_some() {
                    "program_start".to_string()
                } else {
                    "other".to_string()
                }
            }
        }
    } else {
        if map.contains_key(F_CMDLINE) {
            "exec".to_string()
        } else if map.get(F_SRC_IP).is_some() && map.get(F_DST_PORT).is_none() {
            "inbound_conn".to_string()
        } else if map.get(F_DST_IP).is_some() && map.get(F_SRC_PORT).is_none() {
            "outbound_conn".to_string()
        } else if map.get(F_LISTEN_PID).is_some() || map.get(F_LISTEN_FDS).is_some() {
            "port_listen".to_string()
        } else if map.get(F_EXE).is_some() {
            "program_start".to_string()
        } else if let Some(msg) = map.get(F_MSG).and_then(Value::as_str) {
            if msg.contains("session opened") {
                "login".to_string()
            } else if msg.contains("session closed") {
                "logout".to_string()
            } else {
                "other".to_string()
            }
        } else {
            "other".to_string()
        }
    };

    let time = map
        .get(F_REALTIME)
        .and_then(Value::as_str)
        .and_then(|s| s.parse::<i64>().ok())
        .and_then(|u| {
            let secs = u / 1_000_000;
            let nsecs = ((u % 1_000_000) * 1_000) as u32;
            Utc.timestamp_opt(secs, nsecs).single()
        })
        .unwrap_or_else(Utc::now);

    let message = map.get(F_MSG).and_then(Value::as_str).map(String::from);
    let extra = map.clone().into_iter().collect();

    Event {
        pid,
        uid,
        user,
        is_admin,
        ip_src,
        port_src,
        ip_dst,
        port_dst,
        path,
        time,
        event_type,
        message,
        extra,
    }
}

fn main() -> io::Result<()> {
    fs::create_dir_all(ALERTS_DIR)?;
    fs::set_permissions(ALERTS_DIR, Permissions::from_mode(0o700))?;

    tracing_subscriber::fmt().init();

    let config = Config::load().map_err(|e| {
        error!("Failed to load config: {}", e);
        e
    })?;

    let mut rules = load_rules().map_err(|e| {
        error!("Failed to load rules: {}", e);
        e
    })?;
    let mut last_mod: SystemTime = fs::metadata(RULES_FILE)?.modified()?;

    let seen_signatures = Arc::new(Mutex::new(HashMap::<String, DateTime<Utc>>::new()));

    // Thread: tail and parse audit.log
    {
        let rules = Arc::new(rules.clone());
        let seen_signatures = Arc::clone(&seen_signatures);
        let config = config.clone();

        thread::spawn(move || {
            let mut parser = AuditParser::default();

            let mut child = match Command::new("tail")
                .args(&["-n", "0", "-F", AUDIT_LOG])
                .stdout(Stdio::piped())
                .spawn()
            {
                Ok(c) => c,
                Err(e) => {
                    error!("Failed to spawn tail for {}: {}", AUDIT_LOG, e);
                    return;
                }
            };
            let stdout = match child.stdout.take() {
                Some(s) => s,
                None => {
                    error!("No stdout from tail process");
                    return;
                }
            };
            let reader = BufReader::new(stdout);

            for line_res in reader.lines() {
                if let Ok(line) = line_res {
                    if let Ok(msg) = parser.parse(line.as_bytes()) {
                        // Build a JSON map from msg.body (fields), track if "syscall" is present
                        let mut json_map = serde_json::Map::new();
                        let mut has_syscall = false;
                        for (k, v) in msg.body {
                            let key_str = k.to_string();
                            if key_str == "syscall" {
                                has_syscall = true;
                            }
                            json_map.insert(key_str, Value::String(format!("{:?}", v)));
                        }
                        if !has_syscall {
                            continue;
                        }

                        if let Some(Value::String(ts_str)) = json_map.get("msg") {
                            if let Some(start) = ts_str.find('(') {
                                if let Some(colon) = ts_str.find(':') {
                                    let micros = &ts_str[start + 1..colon];
                                    if let Ok(us_int) = micros.replace('.', "").parse::<i64>() {
                                        json_map.insert(
                                            F_REALTIME.to_string(),
                                            Value::String(us_int.to_string()),
                                        );
                                    }
                                }
                            }
                        }

                        let event = extract_event_from_json(&json_map);
                        let now = Utc::now();
                        {
                            let mut seen = seen_signatures.lock().unwrap();
                            seen.retain(|_, &mut ts| now.signed_duration_since(ts).num_seconds() < 60);
                        }

                        for key in &[Some(event.event_type.clone()), None] {
                            if let Some(bucket) = rules.get(key) {
                                for rule in bucket {
                                    if matches(&event, rule) {
                                        let sig = build_signature(rule, &event);
                                        let mut seen = seen_signatures.lock().unwrap();
                                        if !seen.contains_key(&sig) {
                                            seen.insert(sig.clone(), now);
                                            write_alert(
                                                rule,
                                                &event,
                                                &sig,
                                                config.alerts_dir,
                                                config.alerts_journald,
                                            );
                                            info!("Audit-alert {} fired", rule.name);
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

    // Main thread: stream journald JSON
    let mut seen_cursor = HashSet::new();

    for line in stream_journal()? {
        if let Ok(meta) = fs::metadata(RULES_FILE) {
            if let Ok(mod_time) = meta.modified() {
                if mod_time > last_mod {
                    if let Ok(r) = load_rules() {
                        rules = r;
                        last_mod = mod_time;
                        info!("Reloaded DSL rules after modification");
                    }
                }
            }
        }

        if let Ok(l) = line {
            if let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&l) {
                let cursor = map
                    .get(F_CURSOR)
                    .and_then(Value::as_str)
                    .unwrap_or_default()
                    .to_string();
                if !seen_cursor.insert(cursor.clone()) {
                    continue;
                }
                let event = extract_event_from_json(&map);
                let now = Utc::now();
                {
                    let mut seen = seen_signatures.lock().unwrap();
                    seen.retain(|_, &mut ts| now.signed_duration_since(ts).num_seconds() < 60);
                }
                for key in &[Some(event.event_type.clone()), None] {
                    if let Some(bucket) = rules.get(key) {
                        for rule in bucket {
                            if matches(&event, rule) {
                                let sig = build_signature(rule, &event);
                                let mut seen = seen_signatures.lock().unwrap();
                                if !seen.contains_key(&sig) {
                                    seen.insert(sig.clone(), now);
                                    write_alert(
                                        rule,
                                        &event,
                                        &sig,
                                        config.alerts_dir,
                                        config.alerts_journald,
                                    );
                                    info!("Journal-alert {} fired", rule.name);
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
