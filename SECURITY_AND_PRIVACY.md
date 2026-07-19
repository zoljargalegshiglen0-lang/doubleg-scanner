# Security and Privacy

DoubleG Scanner requires explicit local consent. It is designed as a transparent, local-only, read-only inspection tool.

## Reads

- Windows security profile and scanner integrity metadata
- Running process and CS2 loaded-module metadata
- File SHA-256 and Authenticode trust state
- Supported browser visit/download metadata retained only when relevant to local rules
- Prefetch, UserAssist, BAM, Recent Items execution artifacts
- Recycle Bin metadata without restoring deleted content
- Registered driver and Run/RunOnce/Startup metadata
- Current TCP connections and cumulative network-interface counters
- Recent executable/archive metadata in Downloads, Desktop, and Temp; ZIP entry names only

## Does not collect

- Passwords, cookies, browser sessions, Discord tokens, autofill, payment information
- Private messages, clipboard content, screenshots, key presses
- Photo, video, or document contents

## Does not perform

- Network upload, telemetry, webhook, remote server communication
- File quarantine, deletion, restoration, or modification
- Windows security setting changes
- Kernel-driver installation, service installation, or startup persistence
- Hidden/background monitoring

Temporary browser database copies are created only in the scanner's own temporary folder and removed when the scan session ends. Reports are written only to `Documents\DoubleG Scanner\Reports`.
