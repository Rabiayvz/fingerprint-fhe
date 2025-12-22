use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

const DB_PATH: &str = "../database/templates.json";

#[derive(Serialize, Deserialize, Debug)]
pub struct Database {
    pub version: String,
    pub templates: HashMap<String, TemplateEntry>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TemplateEntry {
    pub user_id: String,
    pub ciphertext: Vec<u8>,             // ✅ Vec<u8> olarak değiştir
    pub encrypted_key_bytes: Vec<u8>,
    pub encrypted_iv_bytes: Vec<u8>,
    pub created_at: String,
    pub updated_at: String,
}

impl Database {
    /// Load database from JSON file
    pub fn load() -> Result<Self, Box<dyn std::error::Error>> {
        if !Path::new(DB_PATH).exists() {
            println!("⚠️  Database not found, creating new one...");
            let db = Database {
                version: "1.0".to_string(),
                templates: HashMap::new(),
            };
            db.save()?;
            return Ok(db);
        }
        
        let data = fs::read_to_string(DB_PATH)?;
        let db: Database = serde_json::from_str(&data)?;
        println!("✅ Database loaded: {} templates", db.templates.len());
        Ok(db)
    }
    
    /// Save database to JSON file
    pub fn save(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::create_dir_all("../database")?;
        let json = serde_json::to_string_pretty(self)?;
        fs::write(DB_PATH, json)?;
        Ok(())
    }
    
    /// Insert or update template
    pub fn insert(&mut self, entry: TemplateEntry) {
        self.templates.insert(entry.user_id.clone(), entry);
    }
    
    /// Get template by user_id
    pub fn get(&self, user_id: &str) -> Option<&TemplateEntry> {
        self.templates.get(user_id)
    }
    
    /// Check if user exists
    pub fn exists(&self, user_id: &str) -> bool {
        self.templates.contains_key(user_id)
    }
}

impl TemplateEntry {
    pub fn new(
        user_id: String,
        ciphertext: Vec<u8>,  // ✅ Vec<u8> olarak değiştir
        encrypted_key_bytes: Vec<u8>,
        encrypted_iv_bytes: Vec<u8>,
    ) -> Self {
        let now = chrono::Utc::now().to_rfc3339();
        Self {
            user_id,
            ciphertext,
            encrypted_key_bytes,
            encrypted_iv_bytes,
            created_at: now.clone(),
            updated_at: now,
        }
    }
}