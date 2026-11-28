# harbor-core

[**简体中文**](./CN_README.md) | English

> This repository is the **Rust core** of Harbor File Pro and is itself a web server. Once the binary is installed and a process is started, visiting `http://<device>:9700/` in a browser gives you the complete application: frontend pages, `/api/v1/*`, `/io` streaming read/write, chunked uploads, SSH remote devices, accounts, and 2FA are all in this single process.
> If you need OpenWrt service management, UCI configuration, logs, core installation/online updates, and firewall allowlisting, install the LuCI panel **[luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro)**.

Harbor File Pro takes file management to a new level. The original Harbor File made it usable; Harbor File Pro makes it enjoyable, with features, operation experience, and visual experience refined to the finest detail.

> Unlimited-size text/Hex editing · Multi-terminal keep-alive and remote device interconnection · In-depth extraction/compression enhancements · Taskbar multi-window · Favorites · Permission visualization · Streaming loading · Resumable transfers · Perfect mobile adaptation.

---

## Quick Start

### Option 1: Release Binary

Download the `harbor-core-<version>-<triple>.tar.gz` for your architecture from [Releases](https://github.com/whzhni1/harbor-core/releases), extract it, and run:

```sh
# First-time account initialization (run locally; username and two password lines are entered without echo)
./harbor-core init-auth -s /etc/harbor

# Start the service
./harbor-core serve \
    --config /etc/config/harbor_file_pro \
    --state-dir /etc/harbor \
    --listen 0.0.0.0:9700
```

Visit `http://<device>:9700/` in a browser; it will redirect to `/login`. Log in with the account set by `init-auth`.

> The initial username and password cannot be set over the network; they can only be initialized locally via `init-auth`. Resetting likewise can only be done locally via `reset-auth`.

### Option 2: OpenWrt Users (LuCI panel recommended)

1. Install **[luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro)**;
2. Install/update the core in LuCI under **System → Harbor File Pro → Overview**;
3. Complete the initial account setup;
4. Use the file management features via `http://<device IP>:9700`.

### Option 3: Build from Source

```sh
# assets/ is the static frontend source directory; build.rs embeds it into the binary
cargo build --release

./target/release/harbor-core serve \
    --config /etc/config/harbor_file_pro \
    --state-dir /etc/harbor \
    --listen 0.0.0.0:9700
```

---

## Screenshots

<details>
<summary>Expand to view screenshots of the main interface, Hex editor, permission management, remote devices, and mobile</summary>

<p align="center">
  <img src="https://github.com/user-attachments/assets/bf021bb1-7708-4646-8543-0b0190978b77" width="720" alt="Harbor File Pro main interface">
  <br>
  <sub>Main interface: file management, multiple windows, and taskbar</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/84caffb7-326d-4bb5-befc-7549205cf562" width="720" alt="Hex editor">
  <br>
  <sub>Hex editor: dual Hex/ASCII views, regex find and replace</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/82ab9cd8-d435-47ae-8b65-6725ef53336b" width="720" alt="Permission management and personalization settings">
  <br>
  <sub>Permission visualization, recursive permissions, and personalization settings</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/e96eeafc-7322-4e32-ad33-efc0ba190d1a" width="720" alt="Remote device interconnection and multiple terminals">
  <br>
  <sub>Remote device interconnection, cross-device transfer, and multi-terminal keep-alive</sub>
</p>

<p align="center">
  <img src="https://github.com/user-attachments/assets/75592519-6025-4e92-907b-95d8479bbf6f" width="300" alt="Mobile interface">
  <img src="https://github.com/user-attachments/assets/9ca1072c-a882-4302-940e-8f1325451ba6" width="300" alt="Mobile desktop mode">
  <br>
  <sub>Mobile touch adaptation and desktop mode in mobile browsers</sub>
</p>

</details>

> For LuCI management panel screenshots, see [luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro).

---

## Core Features

### File Management

- Desktop-class window interaction: multiple windows, free resize/maximize/minimize, window size memory;
- The taskbar can be summoned at any position (left/center/right) along the bottom of the desktop and auto-hides after 3 seconds idle; window switching logic follows Windows;
- Favorites: favorite the current path; supports naming, creating folders, moving, and deleting;
- Click a blank area in the address bar to enter a path directly, on both desktop and mobile;
- Directory upload and statistics: supports uploading an entire folder directly; the properties page shows directory size, subdirectory count, and file count;
- Three paste conflict options: for same-name files, choose **Overwrite / Rename (auto-number) / Skip**;
- Preserve original permissions when overwriting files; supports direct rename input and file replacement; manually enter the destination path when moving/copying.

### Hex Editor: 1TB Files Without Lag, Browser Doesn't Freeze

The original Hex editor could only "view" and could not open large files. Pro turns the Hex editor into a **professional-grade modification tool**.

- **Zero pressure with large files**: opening **1TB or 10TB files is as smooth as 1KB files**, with streaming loading; operations on large binary files absolutely never trigger OOM, and the browser does not freeze;
- **Regex find and replace**: supports regular expressions and case sensitivity, displays match positions and counts, highlights results, and supports Replace / Replace All;
- **Synchronized dual views**: Hex view (00–0F) and ASCII view are displayed simultaneously; clicking either side highlights the corresponding position on the other;
- **Undo / Redo + crash recovery**: recover unsaved changes after an unexpected close.

### Text Editor: No Data Loss, Code Highlighting

- **No file size limit**: streaming loading; text files are smooth; the browser does not freeze;
- **Professional-grade search**: case sensitivity, match count, highlighted location, Replace / Replace All / previous/next;
- **Data safety**: undo/redo; after an unexpected close, automatically asks whether to recover unsaved changes;
- **Code highlighting**: Prism syntax highlighting; automatically removes U+200B zero-width spaces.

### Extraction and Compression: Comprehensively Outperforms the Original

The original extraction capability is very basic. Pro expands comprehensively across four dimensions: **format support, path control, conflict handling, and batch operations**:

- **Extraction enhancements**: preview files like WinRAR, select specific files to extract, and **choose the destination path before extraction** (breadcrumb navigation or manual input); same-name files prompt for overwrite, never silently overwrite or fail outright; under long paths, blank clickable areas are retained to prevent being unable to enter a path;
- **Compression enhancements**: **choose the output path when compressing**; prompt for overwrite if the target file already exists; **fixes the issue of losing existing files when overwriting folders**; supports extracting more formats;
- For conflict handling, see the three-option paste conflict mechanism in "File Management".

### File Operations and Permission Management

The original had no permission editing. Pro adds **permission editing, recursive scope control**, and **two visual modes**.

- **Permission visualization**: check read/write/execute directly on the file/folder properties page, or manually enter numeric modes such as `755`;
- **Advanced recursive permissions**: distinguish "files only" from "directories and files"; change only regular files while keeping directory permissions unchanged;
- For other operation details (preserve permissions on overwrite, rename, replace file, move/copy destination path), see "File Management".

### Remote Devices and Multiple Terminals

All remote device capabilities are implemented in this process via **russh + SFTP**; it **no longer forks the local `ssh`/`sshpass`, nor goes through LuCI / ubus**.

- **File hub center**: operations on remote devices are exactly the same as local operations;
- **Cross-device interconnection**: operate the filesystem of a remote OpenWrt device as a local directory; supports cross-device copy/paste/move/cut;
- **Multiple terminals and keep-alive**: open multiple terminals (local/remote) simultaneously; minimizing a window keeps the connection (only clicking X destroys it); supports one-click refresh/reconnect and replay on reconnect;
- **First connection TOFU**: batch probing displays `SHA256:<b64>`; after confirmation, it is written to `host_key`;
- **Multi-device adaptation**: mobile browsers, mobile browser desktop mode, HTTP / HTTPS, touch devices, and combined IME operations;
- **Dependency installation**: remote supports `apk`, `opkg`, `apt`, `dnf`, `yum`, and `pacman` command branches, executed as background tasks.

### Desktop-Class Windows and Themes

- Win11-style theme: dark/light, supports automatic switching based on the browser, and supports customizable transparency and frosted glass effects;
- Full-screen toggle; error prompts are Windows-style dialogs;
- Built-in wallpapers and online wallpapers; UApiPro, Bing, and Openverse images are loaded directly by the browser and are not downloaded to the device;
- The login page can separately choose whether to apply the current wallpaper.

### Mobile Touch Adaptation

- Tap to open, long-press for menu; long-press drag to move, with multi-select batch drag support;
- Auto-scroll when dragging to the page edge; the page auto-scrolls to the top/bottom when selecting files;
- Also adapted for mobile browsers set to desktop mode.

---

## Runtime Model

```text
       Browser
         │  HTTP :9700 (native HTTP; HTTPS requires configuring a front proxy yourself)
         ▼
┌────────────────────────── harbor-core process ──────────────────────────┐
│ Static assets (embedded index.html / js / css / icons)                   │
│ /login · /api/v1/* (66 endpoints) · /io (Range streaming read/write)     │
│ Chunked upload sessions · transfer task table · concurrency/timeout/backpressure middleware │
│ SSH remote devices (russh + SFTP, direct, bypassing ubus)                │
│ Accounts: password + TOTP + Cookie sessions; preferences, bookmarks, wallpapers │
└──────────────────────────────────────────────────────────────────────────┘
         │                         │                        │
   /etc/config/harbor_file_pro  /etc/harbor (state)   System tools (installed on demand)
```

| Role | Responsibility |
| --- | --- |
| `harbor-core` | Pages + all APIs + transport layer + account/session/2FA + preferences/wallpapers + remote devices |
| LuCI plugin (optional) | Configuration shell: UCI forms, reset password button, entry point to open `:9700`; does not contain frontend assets or backend business code |
| System tools (on demand) | Archiving, thumbnails, SSH, and package installation rely on external programs |

---

### Transfers and Backpressure

| Option | Default | Purpose |
| --- | --- | --- |
| `max_connections` | 16 | Concurrent request limit; excess requests directly return `503 queue_full` |
| `max_transfers` | 4 | Number of simultaneous transfers; excess returns `503 queue_full` |
| `request_timeout` | 60 | Total time limit per request |
| `body_idle_timeout` | 30 | Upload chunk disconnects if no data for 30 seconds |
| `chunk_size` / `chunk_limit` | 1 MiB / 16 MiB | Chunk size and maximum size per chunk |
| `upload_session_hours` | 24 | Retention duration for unfinished sessions; earlier ones are cleaned up on startup |
| `workers` | 0 (= min(cpus, 4)) | Number of Tokio worker threads; on single-core devices, setting 1 may actually be faster |

> For complete UCI configuration options, LuCI panel management items, and automatic actions after saving, see the README of [luci-app-harbor-file-pro](https://github.com/whzhni1/luci-app-harbor-file-pro).

---

## Accounts, Sessions, and Security

- **First-time initialization / reset**: the initial username and password cannot be set over the network; `init-auth` must be run locally (no echo); resetting can only be done locally via `reset-auth`;
- **System directory authorization**: before reading or writing system directories, the password must be re-entered (and the TOTP code if enabled); by default, it expires after 15 minutes of inactivity;
- **Three session parameters**: `session_ttl` (absolute upper limit, cannot be extended by sliding) / `session_idle` (idle timeout, `0` disables) / `session_sliding` (refreshes the Cookie idle lifetime when active, without changing the token);
- **Invalidation mechanism**: daemon restart rotates `auth.key` to invalidate old tokens; `/logout` immediately removes the session from the server-side session table; any 401 makes the frontend uniformly redirect to `/login?expired=1`;
- **Login rate limiting**: failures are counted by client IP; the 3rd failure locks for 30 seconds; cumulative 4th, 7th, and 10th failures enter 60-second / 180-second / no-longer-auto-unlocks-within-the-process tiers;
- **Password and key storage**: passwords use PBKDF2-SHA256 one-way hashing (`<state-dir>/password` 0600); SSH passwords and TOTP secrets are encrypted with ChaCha20-Poly1305 (`<state-dir>/secrets.enc` 0600); UCI does not store remote passwords;
- **Authentication method**: only accepts HttpOnly Cookies; does not accept URL tokens or Bearer tokens; TOTP uses RFC 6238 (SHA1 / 6 digits / 30 seconds, tolerating one time step of clock skew before and after).

---

## On-Demand Dependencies

The following dependencies are only installed "when you need a feature"; they are not runtime prerequisites:

| Feature | Dependency |
| --- | --- |
| Compression/extraction | `tar` (with `xz`/`bzip2` support), `gzip`; 7z via `bsdtar` or `7z` |
| Thumbnails | `graphicsmagick` (thumbnails) |
| Built-in terminal | In-process PTY; local still requires a login shell; remote via SSH interactive session; WebSocket same-origin direct connection with disconnect replay |
| Remote devices | In-process russh + SFTP; the remote end needs the sftp subsystem (usually `openssh-sftp-server` or `internal-sftp`) |
| Custom wallpaper URL | Any of `curl` → `wget` → `uclient-fetch` |

Local installation only supports directly calling `opkg`/`apk` as root; the remote end also recognizes `apt`/`dnf`/`yum`/`pacman` and can use non-interactive `sudo`. Tool names and package names are validated first.

---

## Related Repositories

- **harbor-core** (this repository, Rust core):
  <https://github.com/whzhni1/harbor-core>
- **luci-app-harbor-file-pro** (OpenWrt LuCI management panel):
  <https://github.com/whzhni1/luci-app-harbor-file-pro>

---

## License and Acknowledgements

Harbor File Pro V2 (this repository, Rust core) is rewritten from Harbor File Pro V1.x (ucode version), and V1.x evolved from [destan19/luci-app-harbor-file](https://github.com/destan19/luci-app-harbor-file). Thanks to the original author for the excellent foundation.

> Begun with Harbor File, surpassing Harbor File — this is Harbor File Pro.