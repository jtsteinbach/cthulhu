// src/rules.rs
use std::collections::HashMap;
use std::fs::File;
use std::io::{self, BufRead, BufReader};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// A single rule specification.
#[derive(Debug, Deserialize, Clone, Serialize)]
pub struct RuleSpec {
    pub name: String,
    pub description: String,
    pub event_type: Option<String>,
    pub criteria: Vec<Criterion>,
}

/// A single criterion within a rule.
#[derive(Debug, Deserialize, Clone)]
pub struct Criterion {
    pub field: String,
    pub op: String,
    pub value: Value,
}

/// Map from event_type (or None) to list of rules.
pub type RuleIndex = HashMap<Option<String>, Vec<RuleSpec>>;

/// Load all rules from the DSL file.
pub fn load_rules() -> io::Result<RuleIndex> {
    let file = File::open(crate::RULES_FILE)?;
    let mut idx: RuleIndex = HashMap::new();
    let reader = BufReader::new(file);
    let mut current_rule: Option<RuleSpec> = None;

    for line_res in reader.lines() {
        let line = line_res?;
        let trimmed = line.trim();

        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with("//") {
            continue;
        }

        if trimmed.ends_with(')') {
            if let Some((name, evtype_part)) = trimmed[..trimmed.len()-1].split_once('(') {
                if let Some(rule) = current_rule.take() {
                    idx.entry(rule.event_type.clone()).or_default().push(rule);
                }
                current_rule = Some(RuleSpec {
                    name: name.trim().to_string(),
                    event_type: Some(evtype_part.trim().to_string()),
                    description: String::new(),
                    criteria: Vec::new(),
                });
            }
        } else if trimmed.starts_with('|') {
            if let Some(rule) = current_rule.as_mut() {
                rule.description = trimmed[1..].trim().trim_matches('"').to_string();
            }
        } else if trimmed.starts_with(':') {
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
                        serde_json::from_str(&val_str).unwrap_or(Value::String(val_str.clone()))
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