// ScanDeep Defender - TypeScript Type Definitions
// Centralized types for Tauri commands, components, and state

// ============================================================================
// Core Scan Types (from engine/job.rs, adapters/scanner_trait.rs)
// ============================================================================

/** Verdict from a scan provider or overall scan */
export type Verdict = "Clean" | "Suspicious" | "Malicious" | "Pending" | "Unavailable" | "Error";

/** Result from a single scan provider */
export interface ProviderResult {
  provider_id: string;
  verdict: Verdict;
  detections: number;
  total_engines: number;
  details: string;
  poll_id?: string;
}

/** Job status during scan pipeline execution */
export type JobStatus = "Pending" | "Hashing" | "Scanning" | "Polling" | "Completed" | "Failed";

/** Scan job submitted to the pipeline */
export interface ScanJob {
  id: string;
  file_path: string;
  filename: string;
  filesize: number;
  hash: string | null;
  status: JobStatus;
  requested_providers: string[];
  allow_cloud_upload: boolean;
  created_at: string; // ISO 8601 timestamp
  retry_count: number;
  max_retries: number;
}

/** Complete scan report returned by scan_file command */
export interface ScanReport {
  job_id: string;
  filename: string;
  filepath: string;
  filesize: number;
  hash: string;
  timestamp: string; // ISO 8601
  results: ProviderResult[];
  overall_verdict: Verdict;
  risk_score: number; // 0-100
  from_cache: boolean;
}

// ============================================================================
// History & Persistence Types (from persistence/database.rs)
// ============================================================================

/** Scan record stored in history database */
export interface ScanRecord {
  id: string;
  filename: string;
  filepath: string;
  filesize: number;
  filehash: string;
  timestamp: string; // ISO 8601
  overall_verdict: string; // Stored as lowercase string
  risk_score: number;
}

// ============================================================================
// Quarantine Types (from security/quarantine.rs)
// ============================================================================

/** Quarantine record for isolated files */
export interface QuarantineRecord {
  id: string;
  original_path: string;
  quarantine_path: string;
  filename: string;
  hash: string;
  quarantined_at: string; // ISO 8601
  scan_id: string;
}

// ============================================================================
// Settings Types (from Settings.tsx, app_state.rs, commands/settings.rs)
// ============================================================================

/** UI settings persisted in localStorage */
export interface SettingsState {
  auto_scan: boolean;
  allow_cloud_upload: boolean;
}

/** API keys for cloud providers (keys map: vt, md, ha, cm) */
export interface ApiKeys {
  vt: string; // VirusTotal
  md: string; // MetaDefender
  ha: string; // Hybrid Analysis
  cm: string; // Cloudmersive
}

/** Internal API keys structure (from app_state.rs) - for Tauri commands */
export interface ApiKeysInternal {
  virustotal?: string;
  metadefender?: string;
  hybridanalysis?: string;
  cloudmersive?: string;
}

// ============================================================================
// Tauri Command Payload Types
// ============================================================================

/** Payload for scan_file command */
export interface ScanFilePayload {
  filePath: string;
  services: string[];
}

/** Payload for save_api_keys command */
export interface SaveApiKeysPayload {
  vt: string;
  md: string;
  ha: string;
  cm: string;
}

/** Payload for set_watcher_keys command */
export interface SetWatcherKeysPayload {
  vt: string;
  md: string;
  ha: string;
  cm: string;
}

/** Payload for set_auto_scan command */
export interface SetAutoScanPayload {
  enabled: boolean;
}

/** Payload for set_config command */
export interface SetConfigPayload {
  allowCloudUpload: boolean;
  enabledProviders: string[];
}

/** Payload for quarantine_file command */
export interface QuarantineFilePayload {
  file_path: string;
  hash: string;
  scan_id: string;
}

/** Payload for restore_file command */
export type RestoreFilePayload = QuarantineRecord;

/** Payload for delete_permanently command */
export type DeletePermanentlyPayload = QuarantineRecord;

// ============================================================================
// Event Types
// ============================================================================

/** Scan progress event payload */
export interface ScanProgressEvent {
  job_id: string;
  status: string;
  message: string;
}

// ============================================================================
// Utility Types
// ============================================================================

/** Supported language codes */
export type Lang = "it" | "en";

/** Navigation tab identifiers */
export type Tab = "scanner" | "history" | "quarantine" | "settings";

/** Provider IDs */
export type ProviderId =
  | "virustotal"
  | "metadefender"
  | "hybridanalysis"
  | "cloudmersive"
  | "clamav";

/** Provider metadata for UI */
export interface ProviderInfo {
  id: ProviderId;
  label: string;
  sub: string;
}
