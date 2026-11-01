---
tags: [architecture, overview, scandeep-defender]
created: 2025-01-15
project: ScanDeep Defender
---

# ScanDeep Defender - Project Architecture

## Overview
ScanDeep Defender is a **Windows desktop malware scanner** built with **Tauri v2** (Rust backend + React/TypeScript frontend). It provides multi-engine scanning via cloud APIs (VirusTotal, MetaDefender, Hybrid Analysis, Cloudmersive) and local ClamAV.

## Technology Stack

### Backend (Rust)
| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | Tauri v2 | Native desktop app framework |
| Async Runtime | Tokio | Async I/O for scanning operations |
| Database | rusqlite (SQLite) | Local scan history & quarantine records |
| HTTP Client | reqwest | Cloud API requests |
| File Watching | notify | Downloads folder monitoring |
| Secrets | keyring | System credential manager (Windows Credential Manager) |
| Serialization | serde / serde_json | Rust↔TypeScript IPC |
| Logging | tracing / tracing-subscriber | Structured logging |
| Error Handling | anyhow | Error context propagation |
| Testing | mockall, tokio-test, serial_test | Unit & integration tests |

### Frontend (TypeScript/React)
| Component | Technology | Purpose |
|-----------|------------|---------|
| Framework | React 18 | UI components |
| Build Tool | Vite 6 | Fast dev server & bundler |
| Tauri API | @tauri-apps/api, @tauri-apps/plugin-* | IPC & native plugins |
| Testing | Vitest + React Testing Library | Unit/component tests |
| Linting | ESLint + TypeScript ESLint | Code quality |
| Formatting | Prettier | Code formatting |

## Project Structure

```
ScanDeep Defender/
├── .claude/                    # Claude Code automation configs
│   ├── agents/                 # Specialized subagents
│   ├── skills/                 # Reusable skills
│   └── settings.json           # Hook configurations
├── .github/workflows/          # CI/CD pipelines
├── .wiki/inbox/                # Obsidian documentation (this folder)
├── src/                        # Frontend source
│   ├── components/             # React components (Scan, History, Quarantine, Settings)
│   ├── types/                  # TypeScript type definitions
│   ├── __tests__/              # Frontend tests
│   ├── App.tsx, main.tsx       # App entry points
│   └── i18n.ts                 # Internationalization (IT/EN)
├── src-tauri/                  # Rust backend
│   ├── src/
│   │   ├── commands/           # Tauri command handlers (scan, settings, history, quarantine)
│   │   ├── engine/             # Scan pipeline, job queue, risk scoring
│   │   ├── adapters/           # Scanner implementations (VT, MD, HA, CM, ClamAV)
│   │   ├── persistence/        # Database layer
│   │   ├── security/           # Crypto, quarantine, rules engine
│   │   ├── watcher/            # File system watcher
│   │   ├── rate_limiter/       # API rate limiting
│   │   ├── app_state.rs        # Shared application state
│   │   └── main.rs             # Entry point
│   ├── Cargo.toml              # Rust dependencies
│   ├── tauri.conf.json         # Tauri configuration
│   └── deny.toml               # cargo-deny security/license policy
├── package.json                # Node dependencies & scripts
├── vitest.config.ts            # Vitest configuration
├── eslint.config.js            # ESLint configuration
└── deny.toml                   # cargo-deny configuration
```

## Data Flow

```
User Action (UI)
       │
       ▼
invoke("command_name", payload)  ←── TypeScript @tauri-apps/api
       │
       ▼
Tauri IPC (JSON over WebView2)
       │
       ▼
#[tauri::command] async fn       ←── Rust command handler
       │
       ├──► AppState (Arc<AppState>)     Shared state: DB, Pipeline, Queue, Keys, Config
       ├──► ScanPipeline.execute()       Orchestrates multi-provider scanning
       ├──► JobQueue                     Manages concurrent scan jobs
       ├──► Database (rusqlite)          Persists history & quarantine
       ├──► Adapters (ScanProvider)      Cloud APIs + ClamAV
       └──► FileWatcher                  Monitors Downloads folder
       │
       ▼
Result → Serialize → IPC → TypeScript → UI Update
```

## Key Architectural Patterns

### 1. Command Pattern (Tauri Commands)
All backend operations exposed via `#[tauri::command]` async functions. Frontend uses `invoke()` for request/response and `listen()` for events.

### 2. Provider Adapter Pattern
Each scanner implements `ScanProvider` trait:
```rust
trait ScanProvider {
    fn id(&self) -> &str;
    async fn scan(&self, job: ScanJob) -> ProviderResult;
    async fn poll_result(&self, poll_id: &str) -> ProviderResult;
}
```

### 3. Pipeline Architecture
`ScanPipeline` coordinates:
- Hash calculation (SHA256)
- Cache lookup (duplicate detection)
- Provider selection & execution
- Result aggregation & risk scoring
- Progress event emission

### 4. State Management
`AppState` (Arc<AppState>) holds:
- `Database` - SQLite connection pool
- `ScanPipeline` - Scan orchestration
- `JobQueue` - Concurrent job management
- `ApiKeys` - In-memory key cache (synced with keyring)
- `Config` - User settings (auto-scan, providers, cloud upload)
- `auto_scan` - Watcher toggle

### 5. Security Layers
- **Keyring**: API keys stored in Windows Credential Manager
- **Quarantine**: Suspicious files moved to isolated location with hash-based names
- **Rules Engine**: Heuristic analysis on scan results
- **Rate Limiting**: Per-provider token bucket
- **Input Validation**: All command params validated in Rust

## Build & Release

### Development
```bash
npm run tauri:dev    # Hot-reload dev mode
```

### Production Build
```bash
npm run tauri:build  # Creates NSIS installer, MSI, portable ZIP
```

### CI/CD (GitHub Actions)
- **CI** (`.github/workflows/ci.yml`): Runs on PR/push - Rust checks, Node checks, Tauri build verification
- **Release** (`.github/workflows/build-windows.yml`): Triggered on `v*` tags - builds Windows artifacts, creates GitHub Release

## Security Considerations

1. **API Keys**: Never logged, stored only in system keyring
2. **File Paths**: Validated against traversal, canonicalized before use
3. **ClamAV Execution**: Uses `Command::new()` with explicit args (no shell)
4. **HTTPS Only**: All cloud APIs use TLS with certificate validation
5. **CSP**: Recommended to add Content Security Policy in `tauri.conf.json`
6. **Dependencies**: `cargo-deny` enforces vulnerability/license policies

## Extending the Application

### Adding a New Scanner
1. Create `src-tauri/src/adapters/new_scanner.rs` implementing `ScanProvider`
2. Add to `main.rs` providers vector
3. Add provider ID to `ProviderId` type in `src/types/index.ts`
4. Add UI entry in `Scan.tsx` SERVICES array

### Adding a New Tauri Command
Use the `gen-tauri-command` skill:
```bash
/gen-tauri-command <name> "<params>" "<return_type>"
```

### Adding a New Settings Option
1. Add to `AppConfig` in `app_state.rs`
2. Add Tauri command in `commands/settings.rs`
3. Add TypeScript types in `src/types/index.ts`
4. Add UI in `Settings.tsx`