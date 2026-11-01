#!/usr/bin/env python3
"""Create comprehensive ingestion transaction for ScanDeep Defender sources."""

import json
import hashlib
from datetime import datetime

# Current timestamp (canonical UTC without microseconds)
NOW = datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')
OPERATION_ID = f"ingest-{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}"

# Source IDs from captured files
SOURCES = [
    {
        "id": "3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff",
        "title": "Project Architecture",
        "path": "wiki/architecture/project-architecture.md",
        "tags": ["architecture", "overview", "scandeep-defender"],
        "source_file": ".raw/captured/3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff.md",
    },
    {
        "id": "8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51",
        "title": "Automation Setup Guide",
        "path": "wiki/automation/setup-guide.md",
        "tags": ["automation", "claude-code", "setup", "hooks", "mcp", "skills", "subagents"],
        "source_file": ".raw/captured/8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51.md",
    },
    {
        "id": "8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51",
        "title": "MCP Servers Configuration",
        "path": "wiki/automation/mcp-servers.md",
        "tags": ["mcp", "context7", "github", "automation"],
        "source_file": ".raw/captured/8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51.md",
    },
    {
        "id": "318ce4d1f9cb8ca642b077ac4c90fc1178856c27e16ae45e3f4fa599807e8bab",
        "title": "Security Considerations",
        "path": "wiki/security/considerations.md",
        "tags": ["security", "audit", "threat-model", "best-practices"],
        "source_file": ".raw/captured/318ce4d1f9cb8ca642b077ac4c90fc1178856c27e16ae45e3f4fa599807e8bab.md",
    },
    {
        "id": "2d9f06182967ffe0e4f0bf8949223785426e439095b1f31d699c733ec49dd80f",
        "title": "Tauri Command Patterns",
        "path": "wiki/tauri/command-patterns.md",
        "tags": ["tauri", "commands", "patterns", "rust", "typescript", "ipc"],
        "source_file": ".raw/captured/2d9f06182967ffe0e4f0bf8949223785426e439095b1f31d699c733ec49dd80f.md",
    },
    {
        "id": "135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7",
        "title": "Release Process",
        "path": "wiki/release/process.md",
        "tags": ["release", "deployment", "ci-cd", "tauri", "windows"],
        "source_file": ".raw/captured/135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7.md",
    },
]

# MOC pages
MOC_PAGES = [
    {"path": "wiki/architecture/index.md", "title": "Architecture Index", "tags": ["architecture", "index", "moc"]},
    {"path": "wiki/automation/index.md", "title": "Automation Index", "tags": ["automation", "index", "moc"]},
    {"path": "wiki/security/index.md", "title": "Security Index", "tags": ["security", "index", "moc"]},
    {"path": "wiki/tauri/index.md", "title": "Tauri Index", "tags": ["tauri", "index", "moc"]},
    {"path": "wiki/release/index.md", "title": "Release Index", "tags": ["release", "index", "moc"]},
]

def compute_hash(content: str) -> str:
    return hashlib.sha256(content.encode('utf-8')).hexdigest()

def read_source(source_file: str) -> str:
    with open(source_file, 'r') as f:
        return f.read()

def create_canonical_page(source: dict, source_content: str) -> dict:
    """Create a canonical page from source content."""
    # Extract frontmatter and content
    lines = source_content.split('\n')
    if lines[0] == '---':
        # Find end of frontmatter
        end_idx = -1
        for i, line in enumerate(lines[1:], 1):
            if line == '---':
                end_idx = i
                break
        if end_idx > 0:
            content = '\n'.join(lines[end_idx+1:])
        else:
            content = source_content
    else:
        content = source_content

    # Create canonical page with updated frontmatter
    canonical_content = f"""---
type: reference
title: {source['title']}
status: evergreen
created: 2025-01-15
updated: {NOW[:10]}
tags:
{chr(10).join(f'    - {tag}' for tag in source['tags'])}
source_ids:
    - {source['id']}
---

{content.strip()}"""

    return {
        "path": source['path'],
        "mode": "create",
        "content": canonical_content,
        "sha256": compute_hash(canonical_content),
    }

def create_moc_page(moc: dict, related_sources: list) -> dict:
    """Create a MOC (Map of Content) page."""
    links = []
    for src in related_sources:
        if src['path'].startswith(moc['path'].replace('/index.md', '/')):
            name = src['title']
            link_path = src['path'].replace('wiki/', '')
            links.append(f"- [[{link_path}|{name}]]")

    content = f"""---
type: moc
title: {moc['title']}
status: evergreen
created: {NOW[:10]}
updated: {NOW[:10]}
tags:
{chr(10).join(f'    - {tag}' for tag in moc['tags'])}
---

# {moc['title']}

This MOC indexes all pages in the {moc['title'].replace(' Index', '')} domain.

## Pages

{chr(10).join(links) if links else '- No pages yet.'}

---
*Generated by ingestion operation {OPERATION_ID}*"""

    return {
        "path": moc['path'],
        "mode": "create",
        "content": content,
        "sha256": compute_hash(content),
    }

def create_index_page(all_pages: list) -> dict:
    """Create the wiki index page."""
    # Get source info for titles
    source_map = {s['id']: s['title'] for s in SOURCES}

    # Group pages by domain (including MOC index pages)
    domains = {
        "Architecture": [],
        "Automation": [],
        "Security": [],
        "Tauri": [],
        "Release": [],
    }

    for page in all_pages:
        if page['path'].startswith('wiki/architecture/') and not page['path'].endswith('/index.md'):
            domains["Architecture"].append(page)
        elif page['path'].startswith('wiki/automation/') and not page['path'].endswith('/index.md'):
            domains["Automation"].append(page)
        elif page['path'].startswith('wiki/security/') and not page['path'].endswith('/index.md'):
            domains["Security"].append(page)
        elif page['path'].startswith('wiki/tauri/') and not page['path'].endswith('/index.md'):
            domains["Tauri"].append(page)
        elif page['path'].startswith('wiki/release/') and not page['path'].endswith('/index.md'):
            domains["Release"].append(page)

    sections = []
    for domain, pages in domains.items():
        if pages:
            section_items = []
            for p in pages:
                # Get title from source map
                title = None
                for s in SOURCES:
                    if s['path'] == p['path']:
                        title = s['title']
                        break
                if not title:
                    title = p['path'].split('/')[-1].replace('.md', '').replace('-', ' ').title()
                link_path = p['path'].replace('wiki/', '')
                section_items.append(f"- [[{link_path}|{title}]]")
            sections.append(f"## {domain}\n\n" + "\n".join(section_items))

    # Add MOC index pages section
    moc_pages = [p for p in all_pages if p['path'].endswith('/index.md') and p['path'] != 'wiki/index.md']
    if moc_pages:
        moc_items = []
        for p in moc_pages:
            domain = p['path'].split('/')[1].title()
            link_path = p['path'].replace('wiki/', '')
            moc_items.append(f"- [[{link_path}|{domain} Index]]")
        sections.append(f"## MOC Indexes\n\n" + "\n".join(moc_items))

    content = f"""---
type: meta
title: Wiki Index
status: evergreen
created: 2026-11-01
updated: {NOW[:10]}
tags:
    - meta
    - index
---

# Wiki Index

This catalog is updated by completed knowledge operations.

Start with [[overview|Vault overview]]. See [[hot|Recent context]] and
[[log|Operation history]] for completed work.

## Sources

- {len(set(s['id'] for s in SOURCES))} sources indexed from inbox

## Concepts

{chr(10).join(sections)}

## Entities

- ScanDeep Defender (project)
- Tauri v2 (framework)
- Rust/TypeScript (languages)
- VirusTotal, MetaDefender, Hybrid Analysis, Cloudmersive, ClamAV (scanners)

## Questions

- How to add a new scanner provider?
- What are the Tauri command patterns?
- How does the release automation work?

---
*Updated by ingestion operation {OPERATION_ID}*"""

    return {
        "path": "wiki/index.md",
        "mode": "replace",
        "content": content,
        "sha256": compute_hash(content),
    }

def create_hot_page(all_pages: list) -> dict:
    """Create the hot cache page."""
    content = f"""---
type: meta
title: Hot Cache
status: developing
created: 2026-11-01
updated: {NOW[:10]}
tags:
    - meta
    - hot-cache
---

# Recent Context

Navigation: [[index|Wiki index]] · [[overview|Vault overview]] · [[log|Operation history]]

## Last Updated

Ingestion operation {OPERATION_ID} completed at {NOW}.

## Key Recent Facts

- 5 sources ingested from inbox (architecture, automation, security, tauri, release)
- 11 canonical pages created (5 content + 5 MOCs + index)
- Source ledger updated with 5 entries
- Claim ledger updated with extracted claims

## Recent Changes

- Created architecture domain with project architecture page
- Created automation domain with setup guide and MCP servers pages
- Created security domain with considerations page
- Created tauri domain with command patterns page
- Created release domain with process page
- Updated wiki index, overview, log, and hot cache

## Active Threads

- Review and refine canonical pages
- Link related concepts across domains
- Add missing claims to claim ledger

---
*Generated by ingestion operation {OPERATION_ID}*"""

    return {
        "path": "wiki/hot.md",
        "mode": "replace",
        "content": content,
        "sha256": compute_hash(content),
    }

def create_log_page() -> dict:
    """Create the log page."""
    content = f"""---
type: meta
title: Wiki Log
status: evergreen
created: 2026-11-01
updated: {NOW[:10]}
tags:
    - meta
    - log
---

# Wiki Log

Newest completed operations appear first.

Navigation: [[index|Wiki index]] · [[overview|Vault overview]] · [[hot|Recent context]]

## {OPERATION_ID} — {NOW}

**Operation Type:** ingest
**Date:** {NOW}
**Sources Processed:** 5
**Pages Created:** 11 (5 content + 5 MOC + index)
**Ledger Updates:** source-ledger (5), claim-ledger (multiple)
**Manifest Updates:** .raw/.manifest.json (5 sources added)

### Sources Ingested

1. Project Architecture (3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff)
2. Automation Setup Guide (8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51)
3. Security Considerations (318ce4d1f9cb8ca642b077ac4c90fc1178856c27e16ae45e3f4fa599807e8bab)
4. Tauri Command Patterns (2d9f06182967ffe0e4f0bf8949223785426e439095b1f31d699c733ec49dd80f)
5. Release Process (135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7)

### Pages Created

- wiki/architecture/project-architecture.md
- wiki/architecture/index.md
- wiki/automation/setup-guide.md
- wiki/automation/mcp-servers.md
- wiki/automation/index.md
- wiki/security/considerations.md
- wiki/security/index.md
- wiki/tauri/command-patterns.md
- wiki/tauri/index.md
- wiki/release/process.md
- wiki/release/index.md

### Meta Pages Updated

- wiki/index.md
- wiki/hot.md
- wiki/log.md
- wiki/overview.md

---
*Generated by ingestion operation {OPERATION_ID}*"""

    return {
        "path": "wiki/log.md",
        "mode": "replace",
        "content": content,
        "sha256": compute_hash(content),
    }

def create_overview_page() -> dict:
    """Create the overview page."""
    content = f"""---
type: overview
title: Vault Overview
status: developing
created: 2026-11-01
updated: {NOW[:10]}
tags:
    - overview
---

# Vault Overview

This local-first vault compounds source-backed knowledge over time for the ScanDeep Defender project.

## Project Summary

**ScanDeep Defender** is a Windows desktop malware scanner built with Tauri v2 (Rust backend + React/TypeScript frontend). It provides multi-engine scanning via cloud APIs (VirusTotal, MetaDefender, Hybrid Analysis, Cloudmersive) and local ClamAV.

## Knowledge Domains

| Domain | Pages | Description |
|--------|-------|-------------|
| Architecture | 1 | System architecture, tech stack, data flow, patterns |
| Automation | 2 | MCP servers, skills, hooks, subagents, plugins |
| Security | 1 | Threat model, controls, review checklist, incident response |
| Tauri | 1 | Command patterns, state management, events, error handling |
| Release | 1 | GitHub Actions workflow, local process, version management |

## Navigation

Use [[index|Wiki index]] to find knowledge, [[hot|Recent context]] to resume work, and [[log|Operation history]] to review completed operations.

## Sources

5 source documents captured from `.wiki/inbox/` and ingested into canonical pages with full provenance tracking.

---
*Updated by ingestion operation {OPERATION_ID}*"""

    return {
        "path": "wiki/overview.md",
        "mode": "replace",
        "content": content,
        "sha256": compute_hash(content),
    }

def create_source_ledger_page() -> dict:
    """Create the source ledger page."""
    # Read existing file for expected hash
    existing_path = "D:/ClaudeCode/Projects/ScanDeep Defender/.wiki/wiki/meta/ledgers/source-ledger.json"
    try:
        with open(existing_path, 'r') as f:
            existing_content = f.read()
        expected_hash = compute_hash(existing_content)
    except FileNotFoundError:
        expected_hash = None

    # Build sources with src- prefix and origin object
    sources = {}
    for source_id, record in source_ledger_records.items():
        src_id = f"src-{source_id}"
        sources[src_id] = {
            "origin": {
                "locator": record["locator"],
                "captured_at": record.get("freshness", {}).get("refresh_due", NOW),
            },
            "authority": record["authority"],
            "review_state": record["review_state"],
            "freshness": record["freshness"],
            "independence_key": record["independence_key"],
            "linked_pages": record["linked_pages"],
        }

    content = {
        "schema": "claude-obsidian.source-ledger.v1",
        "generated_at": NOW,
        "sources": sources,
    }
    content_str = json.dumps(content, indent=2)
    return {
        "path": "wiki/meta/ledgers/source-ledger.json",
        "mode": "replace",
        "content": content_str,
        "sha256": compute_hash(content_str),
        "_expected_hash": expected_hash,
    }

def create_claim_ledger_page() -> dict:
    """Create the claim ledger page."""
    # Read existing file for expected hash
    existing_path = "D:/ClaudeCode/Projects/ScanDeep Defender/.wiki/wiki/meta/ledgers/claim-ledger.json"
    try:
        with open(existing_path, 'r') as f:
            existing_content = f.read()
        expected_hash = compute_hash(existing_content)
    except FileNotFoundError:
        expected_hash = None

    # Build claims with clm- prefix and required fields
    claims = {}
    for i, (claim_id, record) in enumerate(claim_ledger_records.items(), 1):
        clm_id = f"clm-{i:03d}"
        claims[clm_id] = {
            "text": record["statement"],
            "evidence": record["support"],
            "location": {"note": record["note_locator"]},
            "reviewed_at": NOW,
            "risk": record["risk"],
            "confidence": record["confidence"],
            "review_state": record["review_state"],
        }

    content = {
        "schema": "claude-obsidian.claim-ledger.v1",
        "generated_at": NOW,
        "claims": claims,
    }
    content_str = json.dumps(content, indent=2)
    return {
        "path": "wiki/meta/ledgers/claim-ledger.json",
        "mode": "replace",
        "content": content_str,
        "sha256": compute_hash(content_str),
        "_expected_hash": expected_hash,
    }

# Build the transaction
print("Building ingestion transaction...")

# Read source contents and create canonical pages
writes = []
all_pages = []

# Content pages
for source in SOURCES:
    source_content = read_source(source['source_file'])
    page = create_canonical_page(source, source_content)
    writes.append(page)
    all_pages.append(page)

# MOC pages
for moc in MOC_PAGES:
    # Find related sources for this MOC
    domain = moc['path'].split('/')[1]
    related = [s for s in SOURCES if s['path'].startswith(f'wiki/{domain}/')]
    page = create_moc_page(moc, related)
    writes.append(page)
    all_pages.append(page)

# Meta pages
meta_pages = [
    create_index_page(all_pages),
    create_hot_page(all_pages),
    create_log_page(),
    create_overview_page(),
]

for page in meta_pages:
    writes.append(page)

# Source manifest updates
source_manifest_updates = {}
for source in SOURCES:
    # Only add unique source IDs (automation has 2 pages from same source)
    if source['id'] not in source_manifest_updates:
        source_manifest_updates[source['id']] = {
            "captured_at": NOW,
            "sha256": source['id'],
            "source_path": source['source_file'].replace('.raw/captured/', 'inbox/').replace(source['id'] + '.md', '').rstrip('/'),
            "stored_path": source['source_file'],
        }

# Source ledger records
source_ledger_records = {}
for source in SOURCES:
    if source['id'] not in source_ledger_records:
        source_ledger_records[source['id']] = {
            "authority": "primary",
            "review_state": "active",
            "freshness": {"refresh_due": (datetime.utcnow().replace(year=datetime.utcnow().year+1)).isoformat() + "Z"},
            "independence_key": f"scandeep-defender-inbox-{source['id'][:8]}",
            "linked_pages": [s['path'] for s in SOURCES if s['id'] == source['id']],
            "locator": f"vault://.raw/captured/{source['id']}.md",
        }

# Claim ledger records (extracted from sources)
claim_ledger_records = {
    "claim-001": {
        "statement": "ScanDeep Defender is a Windows desktop malware scanner built with Tauri v2",
        "assessment": "accepted",
        "support": ["3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/architecture/project-architecture.md",
    },
    "claim-002": {
        "statement": "The application uses 5 scanner providers: VirusTotal, MetaDefender, Hybrid Analysis, Cloudmersive, and ClamAV",
        "assessment": "accepted",
        "support": ["3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff", "135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/architecture/project-architecture.md",
    },
    "claim-003": {
        "statement": "API keys are stored in Windows Credential Manager via keyring crate",
        "assessment": "accepted",
        "support": ["3254ee61cdc4232fe36bf72d5d6934a218eb2a20629615de10951e40ba2b77ff", "318ce4d1f9cb8ca642b077ac4c90fc1178856c27e16ae45e3f4fa599807e8bab"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/security/considerations.md",
    },
    "claim-004": {
        "statement": "Tauri commands follow a specific pattern with snake_case parameters auto-converted to camelCase for TypeScript",
        "assessment": "accepted",
        "support": ["2d9f06182967ffe0e4f0bf8949223785426e439095b1f31d699c733ec49dd80f"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/tauri/command-patterns.md",
    },
    "claim-005": {
        "statement": "Release process is triggered by pushing a git tag matching v* which triggers GitHub Actions build",
        "assessment": "accepted",
        "support": ["135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/release/process.md",
    },
    "claim-006": {
        "statement": "The tauri-release skill automates the full release process including quality gates, building, tagging, and GitHub release creation",
        "assessment": "accepted",
        "support": ["8788fc6bc8431a280f9a49f3878eba15f3e37896477dbaa17e4955e77f7a4e51", "135e1b38223ccb7178200e6812c3b8fc2124b863f5a1759d2debfdcfb9bea4f7"],
        "confidence": "high",
        "risk": "low",
        "review_state": "active",
        "note_locator": "wiki/automation/setup-guide.md",
    },
}

# Build transaction bundle - add ledger writes
ledger_writes = [
    create_source_ledger_page(),
    create_claim_ledger_page(),
]
writes.extend(ledger_writes)
all_pages.extend(ledger_writes)

# For new files (mode: create), expected_hash is null (file must not exist)
# For replaced files (mode: replace), expected_hash is the current file's hash
expected_hashes = {}
for write in writes:
    if write["mode"] == "create":
        expected_hashes[write["path"]] = None
    else:  # replace
        # Read current file to get its hash
        try:
            with open(f"D:/ClaudeCode/Projects/ScanDeep Defender/.wiki/{write['path']}", 'r') as f:
                current_content = f.read()
            expected_hashes[write["path"]] = compute_hash(current_content)
        except FileNotFoundError:
            expected_hashes[write["path"]] = None

transaction = {
    "schema": "claude-obsidian.transaction.v1",
    "operation_id": OPERATION_ID,
    "operation_type": "ingest",
    "expected_hashes": expected_hashes,
    "address_requests": [],
    "source_manifest_updates": source_manifest_updates,
    "writes": writes,
    "workflow": {
        "catalogs": ["wiki/index.md"]
    }
}

# Save transaction
with open('ingest-transaction.json', 'w') as f:
    json.dump(transaction, f, indent=2)

print(f"Created transaction: {OPERATION_ID}")
print(f"Total writes: {len(writes)}")
print(f"Source manifest updates: {len(source_manifest_updates)}")
print(f"Source ledger records: {len(source_ledger_records)}")
print(f"Claim ledger records: {len(claim_ledger_records)}")

# Also save ledger updates for manual application
ledger_updates = {
    "source_ledger": source_ledger_records,
    "claim_ledger": claim_ledger_records,
}
with open('ledger-updates.json', 'w') as f:
    json.dump(ledger_updates, f, indent=2)

print("Saved ledger-updates.json")
print("Saved ingest-transaction.json")