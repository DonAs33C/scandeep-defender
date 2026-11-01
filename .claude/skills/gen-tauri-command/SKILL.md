---
name: gen-tauri-command
description: Generate a new Tauri command with Rust handler, TypeScript types, and invoke wrapper
disable-model-invocation: true
---

# Generate Tauri Command Skill

Creates a complete Tauri command with all boilerplate:
- Rust command handler in `src-tauri/src/commands/`
- TypeScript payload/return types in `src/types/index.ts`
- Example frontend invoke usage

## Usage

```
/gen-tauri-command <command_name> <payload_fields> [return_type]
```

### Examples

```bash
# Simple command with string param returning a struct
/gen-tauri-command get_scan_status "scan_id: String" "ScanStatus"

# Command with multiple params returning Vec
/gen-tauri-command list_scans "limit: usize, offset: usize" "Vec<ScanRecord>"

# Command with complex payload
/gen-tauri-command update_settings "config: AppConfig" "()"
```

## What It Generates

### 1. Rust Command (`src-tauri/src/commands/<domain>/<command_name>.rs`)
```rust
use crate::app_state::AppState;
use tauri::State;

#[tauri::command]
pub async fn <command_name>(
    <params>,
    state: State<'_, Arc<AppState>>,
) -> Result<<ReturnType>, String> {
    // TODO: Implement
    unimplemented!()
}
```

### 2. TypeScript Types (`src/types/index.ts`)
```typescript
export interface <CommandName>Payload {
  <camelCaseParams>: <Types>;
}

export interface <CommandName>Return {
  // matches Rust return type
}
```

### 3. Command Registration
- Adds to `tauri::generate_handler![]` in `main.rs`
- Imports the new command module

### 4. Frontend Usage Example
```typescript
import { invoke } from "@tauri-apps/api/core";
import type { <CommandName>Payload, <CommandName>Return } from "../types";

const result = await invoke<CommandNameReturn>("<command_name>", { <params> } as <CommandName>Payload);
```

## Templates

Templates are in `.claude/skills/gen-tauri-command/templates/`