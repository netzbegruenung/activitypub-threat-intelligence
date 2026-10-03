//! The actor's RSA key pair.

use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::Path;

use anyhow::Context;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::sha2::Sha256;
use rsa::RsaPrivateKey;

pub struct Keys {
    pub signing: SigningKey<Sha256>,
    pub public_pem: String,
}

impl Keys {
    pub fn from_private(key: RsaPrivateKey) -> anyhow::Result<Self> {
        let public_pem = key.to_public_key().to_public_key_pem(LineEnding::LF)?;
        Ok(Self {
            signing: SigningKey::<Sha256>::new(key),
            public_pem,
        })
    }

    pub fn generate() -> anyhow::Result<(Self, String)> {
        let key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048)?;
        let pem = key.to_pkcs8_pem(LineEnding::LF)?.to_string();
        Ok((Self::from_private(key)?, pem))
    }

    /// Load the PKCS#8 PEM key, generating it (mode 0600) if absent.
    pub fn load_or_generate(path: &Path) -> anyhow::Result<Self> {
        if path.exists() {
            let pem = std::fs::read_to_string(path)
                .with_context(|| format!("reading {}", path.display()))?;
            let key = RsaPrivateKey::from_pkcs8_pem(&pem).context("parsing actor key")?;
            return Self::from_private(key);
        }
        tracing::info!(path = %path.display(), "generating actor key");
        if let Some(dir) = path.parent() {
            if !dir.as_os_str().is_empty() {
                std::fs::create_dir_all(dir)?;
            }
        }
        let (keys, pem) = Self::generate()?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("creating {}", path.display()))?;
        f.write_all(pem.as_bytes())?;
        Ok(keys)
    }
}
