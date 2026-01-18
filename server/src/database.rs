use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const DB_PATH: &str = "../database/templates.json";

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct TemplateEntry {
    pub user_id: String,

    // Enrolled plaintext bits under FHE (Vec<FheBool> serialized with bincode)
    pub encrypted_template_bytes: Vec<u8>,

    pub created_at: String,
    pub updated_at: String,
}

impl TemplateEntry {
    pub fn new(user_id: String, encrypted_template_bytes: Vec<u8>) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            user_id,
            encrypted_template_bytes,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Database {
    pub version: String,
    pub templates: HashMap<String, TemplateEntry>,
}

impl Database {
    pub fn new() -> Self {
        Self {
            version: "2.0".to_string(),
            templates: HashMap::new(),
        }
    }

    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        if !Path::new(DB_PATH).exists() {
            let db = Database::new();
            db.save()?;
            return Ok(db);
        }

        let json = fs::read_to_string(DB_PATH)?;
        let db: Database = serde_json::from_str(&json)?;

        // Optional: version sanity check (helps when migrating old DB formats)
        if db.version != "2.0" {
            return Err(format!(
                "Database version mismatch: expected 2.0, found {}. \
                 Delete/backup {} and re-register templates.",
                db.version, DB_PATH
            )
            .into());
        }

        Ok(db)
    }

    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all("../database")?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(DB_PATH, json)?;
        Ok(())
    }

    /// Insert or overwrite template. (created_at will be preserved if user existed.)
    pub fn insert(&mut self, entry: TemplateEntry) {
        let user_id = entry.user_id.clone();

        if let Some(existing) = self.templates.get(&user_id) {
            // preserve created_at on updates
            let created_at = existing.created_at.clone();

            let mut updated = entry;
            updated.created_at = created_at;
            updated.updated_at = chrono::Utc::now().to_rfc3339();

            self.templates.insert(user_id, updated);
        } else {
            self.templates.insert(user_id, entry);
        }
    }

    pub fn exists(&self, user_id: &str) -> bool {
        self.templates.contains_key(user_id)
    }

    pub fn get(&self, user_id: &str) -> Option<&TemplateEntry> {
        self.templates.get(user_id)
    }

    #[allow(dead_code)]
    pub fn remove(&mut self, user_id: &str) -> bool {
        self.templates.remove(user_id).is_some()
    }

    #[allow(dead_code)]
    pub fn list_users(&self) -> Vec<String> {
        let mut v: Vec<String> = self.templates.keys().cloned().collect();
        v.sort();
        v
    }

    #[allow(dead_code)]
    pub fn count(&self) -> usize {
        self.templates.len()
    }
}
