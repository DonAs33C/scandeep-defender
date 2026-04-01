use anyhow::Result;
use keyring::Entry;

const SERVICE: &str = "scandeep-defender";

pub fn set_key(provider: &str, value: &str) -> Result<()> {
    Entry::new(SERVICE, provider)?.set_password(value)?;
    Ok(())
}

pub fn get_key(provider: &str) -> Result<Option<String>> {
    match Entry::new(SERVICE, provider)?.get_password() {
        Ok(v) if v.is_empty() => Ok(None),
        Ok(v)                 => Ok(Some(v)),
        Err(keyring::Error::NoEntry) => Ok(None),
        Err(e)                => Err(e.into()),
    }
}

#[allow(dead_code)]   // usato dalla pagina Impostazioni quando l'utente rimuove una chiave
pub fn delete_key(provider: &str) -> Result<()> {
    Entry::new(SERVICE, provider)?.delete_credential()?;
    Ok(())
}
