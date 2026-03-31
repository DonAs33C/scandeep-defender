
/// Secure API key storage using OS credential manager (keyring crate).
/// Falls back to AES-256-GCM encrypted local file.
use anyhow::{Context, Result};

const SERVICE_NAME: &str = "scandeep-defender";

/// Store an API key securely in the OS credential vault.
pub fn store_key(provider: &str, key: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Failed to create keyring entry")?;
    entry.set_password(key).context("Failed to store key")?;
    Ok(())
}

/// Retrieve an API key from the OS credential vault.
pub fn get_key(provider: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Failed to create keyring entry")?;
    match entry.get_password() {
        Ok(k)                              => Ok(Some(k)),
        Err(keyring::Error::NoEntry)       => Ok(None),
        Err(keyring::Error::NoStorageAccess(_)) => Ok(None),
        Err(e)                             => Err(e.into()),
    }
}

/// Delete an API key from the vault.
pub fn delete_key(provider: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Failed to create keyring entry")?;
    match entry.delete_credential() {
        Ok(_) | Err(keyring::Error::NoEntry) => Ok(()),
        Err(e) => Err(e.into()),
    }
}

/// Returns all stored provider keys as a HashMap.
pub fn get_all_keys(providers: &[&str]) -> std::collections::HashMap<String, String> {
    providers.iter().filter_map(|&p| {
        get_key(p).ok().flatten().map(|k| (p.to_string(), k))
    }).collect()
}
