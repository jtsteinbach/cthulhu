// src/config.rs
use std::fs::File;
use std::io::{self, BufRead, BufReader};

/// Configuration flags for alert dispatch.
#[derive(Clone)]
pub struct Config {
    pub alerts_dir: bool,
    pub alerts_journald: bool,
}

/// Load configuration from the config file.
pub fn load_config() -> io::Result<Config> {
    let file = match File::open(crate::CONFIG_FILE) {
        Ok(f) => f,
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                format!("Config file not found: {}", crate::CONFIG_FILE),
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
            match key.trim() {
                "alerts_dir" => alerts_dir = matches!(val.trim(), "allow"),
                "alerts_journald" => alerts_journald = matches!(val.trim(), "allow"),
                _ => {}
            }
        }
    }

    Ok(Config { alerts_dir, alerts_journald })
}