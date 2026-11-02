---
type: reference
title: "Tauri Command Patterns"
created: 2025-01-15
updated: 2025-01-15
status: evergreen
tags:
  - tauri
  - commands
  - patterns
  - rust
  - typescript
  - ipc
project: "ScanDeep Defender"
---

# ScanDeep Defender - Tauri Command Patterns

This document describes the established patterns for Tauri commands in this project. Follow these patterns for consistency and maintainability.

---

## Command Structure

### Rust Side (`src-tauri/src/commands/<domain>/<command>.rs`)

```rust
use std::sync::Arc;
use tauri::State;
use crate::app_state::AppState;
use crate::engine::job::ScanJob;  // Domain-specific types

/// Brief description of what this command does
#[tauri::command]
pub async fn command_name(
    // Parameters in snake_case (auto-converted to camelCase for TS)
    param_one: String,
    param_two: Vec<String>,
    optional_param: Option<u32>,
    
    // State access (always last, always Arc<AppState>)
    state: State<'_, Arc<AppState>>,
    
    // AppHandle only if emitting events
    app: AppHandle,  // Optional
) -> Result<ReturnType, String> {
    // 1. Validate inputs early
    if param_one.is_empty() {
        return Err("param_one cannot be empty".into());
    }
    
    // 2. Extract config/state under lock (minimize lock scope)
    let config_value = {
        let cfg = state.config.read().map_err(|e| e.to_string())?;
        cfg.some_field.clone()
    };
    
    // 3. Execute business logic
    let result = do_work(param_one, param_two, &state).await?;
    
    // 4. Return typed result (serializes via serde)
    Ok(result)
}

// Private helper functions for complex logic
async fn do_work(...) -> Result<ReturnType, String> { ... }
```

### TypeScript Side (`src/types/index.ts`)

```typescript
// ============================================================================
// CommandName Command Types
// ============================================================================

/** Payload for command_name command */
export interface CommandNamePayload {
  // snake_case → camelCase conversion automatic
  paramOne: string;
  paramTwo: string[];
  optionalParam?: number;  // Option<T> → T | undefined
}

/** Return type for command_name command */
export interface CommandNameReturn {
  // Match Rust ReturnType structure exactly
  field1: string;
  field2: number;
  items: ItemType[];
}
```

### Frontend Usage (`src/components/Component.tsx`)

```typescript
import { invoke } from "@tauri-apps/api/core";
import type { CommandNamePayload, CommandNameReturn } from "../types";

const handleAction = async () => {
  try {
    const payload: CommandNamePayload = {
      paramOne: "value",
      paramTwo: ["a", "b"],
      optionalParam: 42,
    };
    
    const result = await invoke<CommandNameReturn>("command_name", payload);
    // result is fully typed as CommandNameReturn
    console.log(result.field1);
  } catch (error) {
    // Error is string (from Rust Result<T, String>)
    const message = typeof error === "string" ? error : JSON.stringify(error);
    setError(message);
  }
};
```

---

## Parameter Mapping Rules

| Rust Type | TypeScript Type | Notes |
|-----------|-----------------|-------|
| `String` / `&str` | `string` | |
| `bool` | `boolean` | |
| `u8`/`u16`/`u32`/`u64`/`usize` | `number` | |
| `i8`/`i16`/`i32`/`i64`/`isize` | `number` | |
| `f32`/`f64` | `number` | |
| `Vec<T>` | `T[]` | |
| `Option<T>` | `T \| undefined` | Not `null` - Tauri sends undefined |
| `HashMap<K, V>` | `Record<K, V>` | Keys must be string |
| Custom struct (Serialize) | Interface | Must match field-by-field |
| `Result<T, E>` | `T` (throws `E`) | Tauri unwraps automatically |

### Naming Conversion

- **Rust**: `snake_case` (parameters, struct fields)
- **TypeScript**: `camelCase` (automatic via serde)
- **Command names**: `snake_case` in Rust, same string in `invoke()`

---

## State Access Patterns

### AppState Structure

```rust
// src-tauri/src/app_state.rs
pub struct AppState {
    pub db: Arc<Database>,
    pub pipeline: Arc<ScanPipeline>,
    pub queue: Arc<JobQueue>,
    pub keys: Arc<ApiKeys>,
    pub auto_scan: Arc<Mutex<bool>>,
    pub config: Arc<RwLock<AppConfig>>,
}
```

### Reading State (Minimize Lock Scope)

```rust
// ✅ GOOD: Short lock scope
let providers = {
    let cfg = state.config.read().map_err(|e| e.to_string())?;
    cfg.enabled_providers.clone()
};

// ❌ BAD: Holding lock across await
let cfg = state.config.read().map_err(|e| e.to_string())?;
let result = async_operation(&cfg).await; // Lock held during await!
```

### Writing State

```rust
// For Mutex (auto_scan, keys)
*state.auto_scan.lock().unwrap() = true;

// For RwLock (config)
let mut cfg = state.config.write().unwrap();
cfg.enabled_providers = new_providers;
```

### Accessing Nested State

```rust
// Database
let record = state.db.find_by_hash(&hash).map_err(|e| e.to_string())?;

// Pipeline
let report = state.pipeline.execute(job, &app).await.map_err(|e| e.to_string())?;

// Queue
state.queue.add_job(job);

// Keys (in-memory cache synced with keyring)
let vt_key = state.keys.vt.lock().unwrap().clone();
```

---

## Event Emission Pattern

### Rust: Emitting Events

```rust
use tauri::AppHandle;

#[tauri::command]
pub async fn start_scan(
    file_path: String,
    state: State<'_, Arc<AppState>>,
    app: AppHandle,  // Required for emit
) -> Result<ScanReport, String> {
    // Emit progress events
    app.emit("scan-progress", ScanProgressEvent {
        job_id: job.id.clone(),
        status: "Hashing".into(),
        message: "Calculating file hash...".into(),
    }).map_err(|e| e.to_string())?;
    
    // ... do work ...
    
    app.emit("scan-progress", ScanProgressEvent {
        job_id: job.id.clone(),
        status: "Completed".into(),
        message: "Scan complete".into(),
    }).map_err(|e| e.to_string())?;
    
    Ok(report)
}
```

### TypeScript: Listening to Events

```typescript
import { listen, UnlistenFn } from "@tauri-apps/api/event";
import { useEffect, useRef } from "react";
import type { ScanProgressEvent } from "../types";

const ScanComponent = () => {
  const unlistenRef = useRef<UnlistenFn | null>(null);
  
  useEffect(() => {
    const setupListener = async () => {
      unlistenRef.current = await listen<ScanProgressEvent>(
        "scan-progress",
        ({ payload }) => {
          // payload is fully typed as ScanProgressEvent
          console.log(payload.status, payload.message);
        }
      );
    };
    setupListener();
    
    return () => {
      unlistenRef.current?.(); // Cleanup on unmount
    };
  }, []);
  
  // ...
};
```

### Event Payload Types

```typescript
// src/types/index.ts
export interface ScanProgressEvent {
  job_id: string;
  status: string;
  message: string;
}
```

---

## Error Handling Pattern

### Rust: Result<T, String>

```rust
#[tauri::command]
pub async fn risky_command(
    input: String,
    state: State<'_, Arc<AppState>>,
) -> Result<SuccessType, String> {
    // Validate
    if input.is_empty() {
        return Err("Input cannot be empty".into());
    }
    
    // Operations that can fail
    let data = state.db.query(&input)
        .map_err(|e| format!("Database error: {}", e))?;
    
    let result = external_api_call(&data).await
        .map_err(|e| format!("API error: {}", e))?;
    
    Ok(result)
}
```

### TypeScript: try/catch

```typescript
try {
  const result = await invoke<SuccessType>("risky_command", { input });
  // Success - result is typed
} catch (error) {
  // Error is always string (from Rust String error)
  const message = typeof error === "string" ? error : "Unknown error";
  setError(message);
}
```

---

## Command Registration (main.rs)

```rust
// src-tauri/src/main.rs
mod commands;

fn main() {
    tauri::Builder::default()
        // ... plugins ...
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            // Scan commands
            commands::scan::scan_file,
            commands::scan::poll_result,
            commands::scan::check_duplicate,
            // Settings commands
            commands::settings::save_api_keys,
            commands::settings::load_api_keys,
            commands::settings::set_watcher_keys,
            commands::settings::set_auto_scan,
            commands::settings::set_config,
            commands::settings::open_browser,
            // History commands
            commands::history::get_history,
            commands::history::clear_history,
            // Quarantine commands
            commands::quarantine::quarantine_file,
            commands::quarantine::restore_file,
            commands::quarantine::list_quarantine,
            commands::quarantine::delete_permanently,
            // NEW COMMANDS ADDED HERE
        ])
        // ...
}
```

---

## Domain Organization

Commands grouped by domain in `src-tauri/src/commands/`:

| Domain | File | Commands |
|--------|------|----------|
| `scan` | `scan.rs` | scan_file, poll_result, check_duplicate |
| `settings` | `settings.rs` | save_api_keys, load_api_keys, set_watcher_keys, set_auto_scan, set_config, open_browser |
| `history` | `history.rs` | get_history, clear_history |
| `quarantine` | `quarantine.rs` | quarantine_file, restore_file, list_quarantine, delete_permanently |
| `job` | `job.rs` | (future: job management) |

### Adding New Domain

1. Create `src-tauri/src/commands/new_domain.rs`
2. Add `pub mod new_domain;` to `commands/mod.rs`
3. Add commands to `tauri::generate_handler![]` in `main.rs`

---

## Best Practices Checklist

### Rust Command

- [ ] `#[tauri::command]` attribute present
- [ ] `async fn` (all commands async)
- [ ] Parameters: `snake_case`, validated early
- [ ] State: `State<'_, Arc<AppState>>` as last param (before AppHandle)
- [ ] Return: `Result<T, String>` (not `anyhow::Error`)
- [ ] Lock scope minimized (no `.await` while holding lock)
- [ ] Errors: `map_err(|e| e.to_string())` or formatted context
- [ ] Documentation comment (`/// `) for auto-docs

### TypeScript Types

- [ ] Payload interface: `<CommandName>Payload`
- [ ] Return interface: `<CommandName>Return`
- [ ] Fields: `camelCase` matching Rust `snake_case`
- [ ] `Option<T>` → `T | undefined` (not `null`)
- [ ] Exported from `src/types/index.ts`

### Frontend Usage

- [ ] Import types from `../types`
- [ ] Use `invoke<ReturnType>("command_name", payload)`
- [ ] Payload cast: `as PayloadType`
- [ ] `try/catch` with string error handling
- [ ] Event listeners cleaned up in `useEffect` return

### Testing

- [ ] Unit test in Rust: `#[cfg(test)] mod tests`
- [ ] Component test in Vitest: `*.test.tsx`
- [ ] Integration test: invoke command from test

---

## Common Patterns Reference

### Pagination

```rust
// Rust
#[tauri::command]
pub async fn list_items(
    limit: usize,
    offset: usize,
    state: State<'_, Arc<AppState>>,
) -> Result<Vec<Item>, String> {
    state.db.list_items(limit, offset).map_err(|e| e.to_string())
}
```

```typescript
// TypeScript
export interface ListItemsPayload {
  limit: number;
  offset: number;
}
export interface ListItemsReturn {
  items: Item[];
  total: number;  // Consider adding total count
}
```

### File Path Parameter

```rust
// Rust - always validate
let path = PathBuf::from(&file_path);
if !path.exists() {
    return Err("File not found".into());
}
// Consider canonicalize() + allowlist check
```

```typescript
// TypeScript
export interface FilePathPayload {
  filePath: string;  // From file dialog
}
```

### Configuration Update

```rust
// Rust - use RwLock for config
#[tauri::command]
pub async fn update_config(
    new_config: AppConfig,
    state: State<'_, Arc<AppState>>,
) -> Result<(), String> {
    *state.config.write().unwrap() = new_config;
    Ok(())
}
```

---

## Generation via Skill

Use the `gen-tauri-command` skill to scaffold:

```bash
/gen-tauri-command get_user_scans "user_id: String, limit: usize" "Vec<ScanRecord>"
```

This creates:
1. Rust command template in correct domain
2. TypeScript interfaces in `src/types/index.ts`
3. Usage example

Then implement the `unimplemented!()` body and register in `main.rs`.