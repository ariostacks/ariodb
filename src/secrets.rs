//! An encrypted store for database URLs and agent tokens, so they need not
//! live in environment variables or the config file.
//!
//! Each value is sealed with XChaCha20-Poly1305 under a 32-byte master key.
//! The key comes from `ARIODB_MASTER_KEY` (base64) or, failing that, from
//! `<state dir>/master.key`, created with mode 0600 on first use. Keep the
//! key away from backups of the state directory and the secrets are safe in
//! those backups.

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default, Serialize, Deserialize)]
struct File {
    secrets: BTreeMap<String, Sealed>,
}

#[derive(Serialize, Deserialize)]
struct Sealed {
    nonce: String,
    ciphertext: String,
}

pub struct Store {
    path: PathBuf,
    cipher: XChaCha20Poly1305,
}

impl Store {
    pub fn open(state_dir: &Path) -> Result<Store, String> {
        ensure_private_dir(state_dir)?;
        let key = master_key(state_dir)?;
        Ok(Store {
            path: state_dir.join("secrets.json"),
            cipher: XChaCha20Poly1305::new(&Key::from(key)),
        })
    }

    fn read(&self) -> Result<File, String> {
        match fs::read_to_string(&self.path) {
            Ok(text) => {
                serde_json::from_str(&text).map_err(|e| format!("{}: {e}", self.path.display()))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(File::default()),
            Err(e) => Err(format!("{}: {e}", self.path.display())),
        }
    }

    fn write(&self, file: &File) -> Result<(), String> {
        let text = serde_json::to_string_pretty(file).map_err(|e| e.to_string())?;
        let tmp = self.path.with_extension("json.tmp");
        write_private(&tmp, text.as_bytes())?;
        fs::rename(&tmp, &self.path).map_err(|e| e.to_string())
    }

    pub fn set(&self, name: &str, value: &str) -> Result<(), String> {
        let nonce_bytes: [u8; 24] = rand::random();
        let nonce = XNonce::from(nonce_bytes);
        // The name is bound in as associated data, so a sealed value cannot
        // be moved to another name.
        let payload = chacha20poly1305::aead::Payload {
            msg: value.as_bytes(),
            aad: name.as_bytes(),
        };
        let ciphertext = self
            .cipher
            .encrypt(&nonce, payload)
            .map_err(|_| "encryption failed".to_string())?;
        let mut file = self.read()?;
        file.secrets.insert(
            name.to_string(),
            Sealed {
                nonce: B64.encode(nonce_bytes),
                ciphertext: B64.encode(ciphertext),
            },
        );
        self.write(&file)
    }

    pub fn get(&self, name: &str) -> Result<Option<String>, String> {
        let file = self.read()?;
        let Some(sealed) = file.secrets.get(name) else {
            return Ok(None);
        };
        let nonce: [u8; 24] = B64
            .decode(&sealed.nonce)
            .ok()
            .and_then(|n| n.try_into().ok())
            .ok_or_else(|| format!("secret '{name}' is damaged"))?;
        let ciphertext = B64
            .decode(&sealed.ciphertext)
            .map_err(|_| format!("secret '{name}' is damaged"))?;
        let payload = chacha20poly1305::aead::Payload {
            msg: &ciphertext,
            aad: name.as_bytes(),
        };
        let plain = self
            .cipher
            .decrypt(&XNonce::from(nonce), payload)
            .map_err(|_| format!("secret '{name}' cannot be decrypted with this master key"))?;
        String::from_utf8(plain)
            .map(Some)
            .map_err(|_| format!("secret '{name}' is not text"))
    }

    pub fn delete(&self, name: &str) -> Result<bool, String> {
        let mut file = self.read()?;
        let existed = file.secrets.remove(name).is_some();
        self.write(&file)?;
        Ok(existed)
    }

    pub fn names(&self) -> Result<Vec<String>, String> {
        Ok(self.read()?.secrets.keys().cloned().collect())
    }
}

fn master_key(state_dir: &Path) -> Result<[u8; 32], String> {
    if let Ok(text) = std::env::var("ARIODB_MASTER_KEY") {
        return B64
            .decode(text.trim())
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| "ARIODB_MASTER_KEY must be 32 bytes, base64-encoded".to_string());
    }
    let path = state_dir.join("master.key");
    match fs::read_to_string(&path) {
        Ok(text) => B64
            .decode(text.trim())
            .ok()
            .and_then(|k| k.try_into().ok())
            .ok_or_else(|| format!("{} is not a valid key", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            let key: [u8; 32] = rand::random();
            write_private(&path, B64.encode(key).as_bytes())?;
            Ok(key)
        }
        Err(e) => Err(format!("{}: {e}", path.display())),
    }
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<(), String> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .map_err(|e| format!("{}: {e}", path.display()))?;
    f.write_all(bytes).map_err(|e| e.to_string())
}

/// Create the state directory as 0700, and warn if an existing one is looser.
pub fn ensure_private_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
    if !dir.exists() {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .map_err(|e| format!("{}: {e}", dir.display()))?;
        return Ok(());
    }
    let mode = fs::metadata(dir)
        .map_err(|e| e.to_string())?
        .permissions()
        .mode()
        & 0o777;
    if mode & 0o077 != 0 {
        eprintln!(
            "ariodb: warning: {} is readable by other users (mode {mode:o}); run chmod 700 on it",
            dir.display()
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seals_and_opens_and_detects_tampering() {
        let dir = std::env::temp_dir().join(format!("ariodb-secrets-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = Store::open(&dir).unwrap();
        store
            .set("pg-writer", "postgres://u:not-a-real-password@db/app")
            .unwrap();
        assert_eq!(
            store.get("pg-writer").unwrap().as_deref(),
            Some("postgres://u:not-a-real-password@db/app")
        );
        assert_eq!(store.get("missing").unwrap(), None);
        assert!(
            !fs::read_to_string(dir.join("secrets.json"))
                .unwrap()
                .contains("not-a-real-password")
        );

        // Moving a sealed value to another name fails to decrypt.
        let text = fs::read_to_string(dir.join("secrets.json"))
            .unwrap()
            .replace("pg-writer", "pg-admin");
        fs::write(dir.join("secrets.json"), text).unwrap();
        assert!(store.get("pg-admin").is_err());

        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(dir.join("master.key"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }
}
