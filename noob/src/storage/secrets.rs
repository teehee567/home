// so i can develop more interesting parts for now, will add proper persistence.
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};

pub const PASSWORD_KEY: &str = "password";
const DEFAULT_DEV_PASSWORD: &str = "noob";

pub fn default_path() -> PathBuf {
    PathBuf::from("noob-secrets.txt")
}

#[derive(Default)]
pub struct Secrets {
    path: PathBuf,
    map: HashMap<String, String>,
}

impl Secrets {
    pub fn load(path: impl Into<PathBuf>) -> Self {
        let path = path.into();
        let mut map = HashMap::new();
        if let Ok(text) = fs::read_to_string(&path) {
            for line in text.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((k, v)) = line.split_once('=') {
                    map.insert(k.trim().to_string(), v.trim().to_string());
                }
            }
        }
        Self { path, map }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    pub fn set(&mut self, key: &str, value: &str) {
        self.map.insert(key.to_string(), value.to_string());
    }

    pub fn save(&self) -> Result<()> {
        let mut out = String::new();
        for (k, v) in &self.map {
            out.push_str(k);
            out.push_str(" = ");
            out.push_str(v);
            out.push('\n');
        }
        fs::write(&self.path, out)
            .with_context(|| format!("write secrets to {}", self.path.display()))
    }

    pub fn password(&self) -> Vec<u8> {
        self.get(PASSWORD_KEY)
            .unwrap_or(DEFAULT_DEV_PASSWORD)
            .as_bytes()
            .to_vec()
    }
}
