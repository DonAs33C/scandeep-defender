
use anyhow::{Context, Result};

const SERVICE_NAME: &str = "scandeep-defender";

pub fn store_key(provider: &str, key: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Creazione entry keyring fallita")?;
    entry.set_password(key).context("Salvataggio chiave fallito")?;
    Ok(())
}

pub fn get_key(provider: &str) -> Result<Option<String>> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Creazione entry keyring fallita")?;
    match entry.get_password() {
        Ok(k)                               => Ok(Some(k)),
        Err(keyring::Error::NoEntry)        => Ok(None),
        Err(keyring::Error::NoStorageAccess(_)) => Ok(None),
        Err(e)                              => Err(anyhow::anyhow!("{}", e)),
    }
}

/// FIX: delete_credential non esiste in keyring v2 → usa delete_password
pub fn delete_key(provider: &str) -> Result<()> {
    let entry = keyring::Entry::new(SERVICE_NAME, provider)
        .context("Creazione entry keyring fallita")?;
    match entry.delete_password() {
        Ok(_)                        => Ok(()),
        Err(keyring::Error::NoEntry) => Ok(()),
        Err(e)                       => Err(anyhow::anyhow!("{}", e)),
    }
}

pub fn get_all_keys(providers: &[&str]) -> std::collections::HashMap<String, String> {
    providers.iter().filter_map(|&p| {
        get_key(p).ok().flatten().map(|k| (p.to_string(), k))
    }).collect()
}
