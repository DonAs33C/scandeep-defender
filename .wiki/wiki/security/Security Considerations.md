---
type: reference
title: "Security Considerations"
created: 2025-01-15
updated: 2025-01-15
status: evergreen
tags:
  - security
  - audit
  - threat-model
  - best-practices
project: "ScanDeep Defender"
---

# ScanDeep Defender - Security Considerations

## Threat Model

### Assets to Protect

1. **User API Keys** - VirusTotal, MetaDefender, Hybrid Analysis, Cloudmersive
2. **Scan Results/History** - Malware detection data, file hashes, paths
3. **Quarantined Files** - Potentially malicious executables
4. **System Integrity** - No unauthorized file execution or modification
5. **User Privacy** - No telemetry, no data exfiltration

### Threat Actors

- **Malicious Files** - Files being scanned may exploit parser vulnerabilities
- **Compromised APIs** - Cloud scanning services could return malicious payloads
- **Local Attacker** - Access to user's machine, attempting privilege escalation
- **Supply Chain** - Compromised dependencies (mitigated by cargo-deny)

### Trust Boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                      USER MACHINE                           │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐  │
│  │   Frontend  │◄─│   Tauri IPC │──│    Backend (Rust)   │  │
│  │  (React)    │  │  (JSON)     │  │  - Commands         │  │
│  └─────────────┘  └─────────────┘  │  - Pipeline         │  │
│                                    │  - Adapters         │  │
│                                    │  - Database         │  │
│                                    │  - Keyring          │  │
│                                    └──────────┬──────────┘  │
│                                               │             │
│                    ┌──────────────────────────┼──────────┐  │
│                    ▼                          ▼          ▼  │
│            ┌─────────────┐           ┌─────────────┐ ┌─────┐ │
│            │  Downloads  │           │   Keyring   │ │ClamAV│ │
│            │   Folder    │           │  (Windows   │ │Binary│ │
│            │  (Watcher)  │           │ Credential  │ │       │ │
│            └─────────────┘           │   Manager)  │ └─────┘ │
│                                     └─────────────┘         │
│                    ┌─────────────────────────────────────┐  │
│                    │        NETWORK (HTTPS/TLS)          │  │
│                    │  VT API │ MD API │ HA API │ CM API  │  │
│                    └─────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## Security Controls Implemented

### 1. Secrets Management (Keyring)

**Location:** `src-tauri/src/security/crypto.rs`

```rust
// Keys stored in Windows Credential Manager
pub fn store_key(service: &str, key: &str) -> Result<()> {
    keyring::Entry::new("scandeep-defender", service)?.set_password(key)
}

pub fn get_key(service: &str) -> Result<String> {
    keyring::Entry::new("scandeep-defender", service)?.get_password()
}
```

**Properties:**
- ✅ No plaintext keys on disk
- ✅ OS-level encryption (DPAPI on Windows)
- ✅ Per-service isolation
- ✅ Keys loaded at startup, kept in `Arc<Mutex<String>>`

**Review Points:**
- [ ] Keys cleared from memory on app exit
- [ ] No logging of key values (even partial)
- [ ] Key rotation supported (overwrite in keyring)

### 2. File System Security

#### Path Validation

**Location:** `commands/scan.rs`, `commands/quarantine.rs`

```rust
let path = PathBuf::from(&file_path);
if !path.exists() {
    return Err(format!("File not found: {}", file_path));
}
// TODO: Add canonicalization and traversal check
```

**Required Hardening:**
```rust
// ADD: Canonicalize and validate path stays within allowed directories
let canonical = path.canonicalize().map_err(|e| e.to_string())?;
let allowed_dirs = [dirs::download_dir().unwrap(), /* quarantine dir */];
if !allowed_dirs.iter().any(|d| canonical.starts_with(d)) {
    return Err("Path outside allowed directories".into());
}
```

#### Quarantine Isolation

**Location:** `src-tauri/src/security/quarantine.rs`

- Files moved (not copied) to quarantine directory
- Renamed to SHA256 hash (no extension, no original name)
- Original path stored in database for restoration
- Quarantine directory: `%APPDATA%\ScanDeep Defender\quarantine\`

**Review Points:**
- [ ] Quarantine dir ACLs restrict access (Admin/SYSTEM only)
- [ ] No auto-execution of quarantined files
- [ ] Restore validates hash matches before moving back

### 3. Process Execution (ClamAV)

**Location:** `src-tauri/src/adapters/clamav.rs`

```rust
// SAFE: Explicit args, no shell
let output = Command::new("clamdscan")
    .args(["--fdpass", "--move", &quarantine_dir, &file_path])
    .output()
    .await?;
```

**Properties:**
- ✅ `Command::new()` not `Command::new("sh").arg("-c")`
- ✅ Args passed as array, no string interpolation
- ✅ Input file path validated before passing

**Review Points:**
- [ ] ClamAV binary path validated (not PATH search)
- [ ] Timeout on clamdscan execution
- [ ] Output parsing handles malformed responses

### 4. Network Security

#### HTTPS Enforcement

All adapters use `reqwest::Client` with default TLS:

```rust
let client = reqwest::Client::new(); // Uses system CA store
let resp = client.post(url).json(&payload).send().await?;
```

**Properties:**
- ✅ TLS 1.2+ enforced by reqwest
- ✅ Certificate validation enabled (default)
- ✅ No `danger_accept_invalid_certs()`

#### Rate Limiting

**Location:** `src-tauri/src/rate_limiter/`

Token bucket per provider:
- VirusTotal: 4 req/min, 500/day
- MetaDefender: per API tier
- Hybrid Analysis: per API tier
- Cloudmersive: per API tier

### 5. Supply Chain Security

**Configuration:** `deny.toml`

```toml
[advisories]
db = "https://github.com/RustSec/advisory-db"
severity = "high"

[licenses]
allow = ["MIT", "Apache-2.0", "BSD-*", "ISC", ...]
deny = ["AGPL-3.0", "GPL-3.0", "LGPL-3.0", "SSPL-1.0"]

[bans]
yanked = "deny"
multiple-versions = "warn"
```

**CI Integration:** `.github/workflows/ci.yml`
```yaml
- name: Run cargo deny check
  run: cargo deny check
```

### 6. Tauri-Specific Security

#### Current State

```json
// tauri.conf.json
"app": {
  "security": { "csp": null }
}
```

#### Recommended CSP

```json
"security": {
  "csp": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self' https://*.virustotal.com https://*.metadefender.com https://*.hybrid-analysis.com https://*.cloudmersive.com;"
}
```

#### Capabilities (Least Privilege)

**Location:** `src-tauri/capabilities/`

Review each capability file for:
- [ ] Only required permissions granted
- [ ] No `allow-all` or wildcard permissions
- [ ] File system access scoped to specific directories

---

## Security Review Checklist

### Per-Feature Review

When adding new features, verify:

- [ ] **Input Validation**: All command params validated in Rust before use
- [ ] **Output Encoding**: No raw user input in logs, errors, or UI
- [ ] **Path Safety**: `canonicalize()` + allowlist check for all file ops
- [ ] **Process Safety**: No shell, explicit args, timeouts on external commands
- [ ] **Network Safety**: HTTPS only, cert validation, rate limiting
- [ ] **Secrets**: No keys in logs, config files, database, or memory dumps
- [ ] **Dependencies**: `cargo deny check` passes, no new high/critical advisories
- [ ] **Error Handling**: No `unwrap()`/`expect()` on security paths

### Periodic Audits

| Frequency | Task |
|-----------|------|
| **Per PR** | CI runs: clippy, deny, tests, typecheck |
| **Weekly** | `cargo audit` (or `cargo deny check advisories`) |
| **Monthly** | Review `cargo outdated` for security updates |
| **Per Release** | Full security review by security-reviewer agent |
| **Quarterly** | Threat model review, penetration testing |

---

## Incident Response

### If API Key Compromised

1. User: Revoke key at provider dashboard
2. App: `load_api_keys` returns empty, user enters new key
3. Keyring: Old key overwritten automatically

### If Malicious File Escapes Quarantine

1. Quarantine uses hash-based names (no extension)
2. No auto-execution path exists
3. Restore requires explicit user action + hash verification

### If Dependency Vulnerability Found

1. `cargo deny check` fails CI
2. Update dependency in `Cargo.toml`
3. Run `cargo update -p <crate>`
4. Verify tests pass
5. Deploy patch release

---

## Security Contacts

- **Internal**: Security review via `security-reviewer` subagent
- **Dependencies**: RustSec advisory DB (auto-checked by cargo-deny)
- **Reporting**: GitHub Security Advisories for this repo

---

## References

- [Tauri Security Guide](https://tauri.app/v2/guides/security/)
- [RustSec Advisory Database](https://github.com/RustSec/advisory-db)
- [OWASP Desktop App Security](https://owasp.org/www-project-desktop-application-security/)
- [Windows Credential Manager](https://learn.microsoft.com/en-us/windows/security/credential-protection/credential-manager)