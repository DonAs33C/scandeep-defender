use anyhow::Result;
use keyring::Entry;
use std::collections::HashMap;

const SERVICE: &str = "scandeep-defender";

pub fn set_key(provider: &str, value: &str) -> Result<()> {
    Entry::new(SERVICE, provider)?.set_password(value)?;
    Ok(())
}

/// Alias usato da settings.rs
pub fn store_key(provider: &str, value: &str) -> Result<()> {
    set_key(provider, value)
}

pub fn get_key(provider: &str) -> Result<Option<String>> {
    match Entry::new(SERVICE, provider)?.get_password() {
        Ok(v) if v.is_empty()        => Ok(None),
        Ok(v)                        => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e)                       => Err(e.into()),
    }
}

/// Ritorna mappa provider → chiave (stringa vuota se assente)
pub fn get_all_keys(providers: &[&str]) -> HashMap<String, String> {
    providers.iter().map(|&p| {
        let val = get_key(p).unwrap_or(None).unwrap_or_default();
        (p.to_string(), val)
    }).collect()
}

#[allow(dead_code)]
pub fn delete_key(provider: &str) -> Result<()> {
    Entry::new(SERVICE, provider)?.delete_password()?;
    Ok(())
}
