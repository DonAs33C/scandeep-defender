# ScanDeep Defender

## Description
ScanDeep Defender is a Windows desktop app for automatically scanning downloaded files. It monitors the Downloads folder and sends files to various online services (such as VirusTotal and Metadefender) and a local engine (ClamAV) to check for malware and malicious files. The interface is modern and supports a "run and go" experience with a single executable file or installer.

## Key Features
- 🖥️ Cross-platform desktop app with React interface.
- 🦠 Multi-engine scanning: VirusTotal, Metadefender, local ClamAV.
- 📦 Classic Windows installer and portable ZIP version.
- 🕒 Background daemons with file watchers for the Downloads folder.
- 📋 Local history with SQLite for all scans.

- 🖼️ UI with main tabs: Scanner, History, Settings.
- 🌐 Online API integration and configuration via checkboxes.
- 🔄 Autostart on boot (optional).
- 🗂️ Manual file selection support.

## System Requirements
- Windows 10/11 (64-bit).
- WebView2 Runtime (recommended, but will be flagged if missing).
- For full use with the online API: Internet connection.
- Optional: ClamAV installed locally for offline scans.

## Installation (installer)
1. Download the `ScanDeep-Defender-Setup.exe` or `ScanDeep-Defender-Setup.msi` file from the “Releases” section of GitHub.
2. Double-click the file to run it.
3. Follow the standard installation wizard.
4. Once finished, launch the app from the Start menu or via a desktop shortcut.

## Using the portable version
1. Download the `ScanDeep-Defender-portable.zip` file.
2. Extract the folder to a location of your choice (e.g., `C:\ScanDeep-Defender`).
3. Open the folder and double-click the `ScanDeep-Defender.exe` file.
4. The app runs without additional installation.

## Main configuration
- From the "Settings" tab, you can:
- enter your API keys for VirusTotal and Metadefender;
- enable or disable monitoring of the Downloads folder;
- enable or disable autostart on boot;
- select which scanning services to use.
- From the "Scanner" tab, you can manually upload a file to scan.

## Security Note and API Limits
This release uses the VirusTotal public API, which is limited to 500 requests per day and 4 requests per minute. Therefore, it is intended for personal use and should not be integrated into distributed products or workflows without adhering to VirusTotal's terms and conditions.

## For Developers
To compile and modify the project, you need:
- Node.js (18+).
- Rust (1.70+).
- Tauri CLI.
See the official Tauri documentation for details.

## Contributions
Want to contribute? Open an issue or PR for:
- new scanning engines;
- integrations with other APIs;
- UI/UX improvements.
