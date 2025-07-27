// src/evaluator.rs
use chrono::{DateTime, Utc};
use chrono::Duration;
use regex::Regex;
use ipnetwork::IpNetwork;
use serde_json::Value;
use crate::event::Event;
use crate::rules::RuleSpec;

/// Compare two JSON values with extended operators.
pub fn compare_json(a: &Value, op: &str, b: &Value) -> bool {
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
            } else { false }
        }
        // string ops
        "contains" => a.as_str().zip(b.as_str()).map_or(false, |(as_, bs)| as_.contains(bs)),
        "icontains" => a.as_str().zip(b.as_str()).map_or(false, |(as_, bs)| as_.to_lowercase().contains(&bs.to_lowercase())),
        "startswith" => a.as_str().zip(b.as_str()).map_or(false, |(as_, bs)| as_.starts_with(bs)),
        "endswith" => a.as_str().zip(b.as_str()).map_or(false, |(as_, bs)| as_.ends_with(bs)),
        "matches" => {
            if let (Some(as_), Some(bs)) = (a.as_str(), b.as_str()) {
                Regex::new(bs).map_or(false, |re| re.is_match(as_))
            } else { false }
        }
        // array membership
        "in" | "not_in" => {
            if let Value::Array(list) = b {
                if let Some(val_str) = a.as_str() {
                    let contains = list.iter().any(|item| item == &Value::String(val_str.to_string()));
                    if op == "in" { contains } else { !contains }
                } else if let Some(val_n) = a.as_f64() {
                    let contains = list.iter().any(|item| item.as_f64().map_or(false, |bn| bn == val_n));
                    if op == "in" { contains } else { !contains }
                } else { false }
            } else { false }
        }
        // bitwise
        "&" | "bitwise_and" => a.as_u64().zip(b.as_u64()).map_or(false, |(an, bn)| (an & bn) != 0),
        // range
        "between" | "not_between" => {
            if let (Some(an), Value::Array(arr)) = (a.as_f64(), b) {
                if arr.len() == 2 {
                    if let (Some(min), Some(max)) = (arr[0].as_f64(), arr[1].as_f64()) {
                        let in_range = an >= min && an <= max;
                        if op == "between" { in_range } else { !in_range }
                    } else { false }
                } else { false }
            } else { false }
        }
        // CIDR
        "in_cidr" | "cidr_contains" => {
            if let (Some(ip_str), Some(cidr_str)) = (a.as_str(), b.as_str()) {
                if let (Ok(ip), Ok(network)) = (ip_str.parse::<std::net::IpAddr>(), cidr_str.parse::<IpNetwork>()) {
                    network.contains(ip)
                } else { false }
            } else { false }
        }
        // time
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
                        "s" => Duration::seconds(num),
                        "m" => Duration::minutes(num),
                        "h" => Duration::hours(num),
                        "d" => Duration::days(num),
                        _ => Duration::seconds(0),
                    };
                    let cutoff = Utc::now() - duration;
                    a_time >= cutoff
                } else { false }
            } else { false }
        }
        _ => false,
    }
}

/// Check if a field exists on the event.
pub fn field_exists(event: &Event, field: &str) -> bool {
    if field == "path" {
        return event.path.is_some();
    }
    if field == "event_type" {
        return true;
    }
    if let Some(stripped) = field.strip_prefix("journald.") {
        return event.extra.contains_key(stripped);
    }
    if let Some(stripped) = field.strip_prefix("auditd.") {
        return event.extra.contains_key(stripped);
    }
    event.extra.contains_key(field)
}

/// Get a field value from the event.
pub fn get_field(event: &Event, field: &str) -> Value {
    if field == "path" {
        return event.path.clone().map(Value::String).unwrap_or_else(|| Value::String(String::new()));
    }
    if field == "event_type" {
        return Value::String(event.event_type.clone());
    }
    if let Some(stripped) = field.strip_prefix("journald.") {
        return event.extra.get(stripped).cloned().unwrap_or_else(|| Value::String(String::new()));
    }
    if let Some(stripped) = field.strip_prefix("auditd.") {
        return event.extra.get(stripped).cloned().unwrap_or_else(|| Value::String(String::new()));
    }
    event.extra.get(field).cloned().unwrap_or_else(|| Value::String(String::new()))
}

/// Determine if an event matches a rule.
pub fn rule_matches(event: &Event, rule: &RuleSpec) -> bool {
    for crit in &rule.criteria {
        if crit.op == "exists" {
            if !field_exists(event, &crit.field) { return false; }
            continue;
        }
        if crit.op == "missing" {
            if field_exists(event, &crit.field) { return false; }
            continue;
        }
        let val = get_field(event, &crit.field);
        if !compare_json(&val, &crit.op, &crit.value) {
            return false;
        }
    }
    true
}