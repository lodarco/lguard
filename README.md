# Lguard

Antivirus, torrent guard and ransomware shield for Linux desktops and home servers.

Lguard watches every file as it is written, keeps a tamper-proof inventory of
what it has checked, looks after your Torrents, Plex and Jellyfin folders, and
freezes your backups the moment something starts encrypting your files.

## Features

- **Real-time protection**: fanotify watches whole filesystems; every file
  is checked as soon as it is written. There are no per-directory watch limits.
- **Incremental scanning**: the first scan reads every file once. After that
  only changed files are scanned. Identical content found elsewhere (mirrors,
  backups) is recognised by its SHA-256 and not scanned again.
- **Full disk scan**: a little of every disk is re-read each night, so every
  file is checked again at least once a month. You can also start a full scan
  by hand. Scans can be paused, with automatic resume.
- **Torrents, Plex, Jellyfin and your own categories**: downloads are checked
  as soon as they finish. Fake movies (programs, double extensions such as
  `Movie.mp4.exe`, "videos" that are really archives) are quarantined even
  when no virus signature knows them yet.
- **Ransomware shield**: documents that suddenly turn into random data, or one
  program rewriting hundreds of existing files, raise an alarm and run your
  freeze commands (stop sync, stop backup jobs) so encrypted files cannot
  overwrite good copies.
- **Quarantine** with restore, restore-and-trust and delete.
- **Tamper-proof inventory**: every record is encrypted and authenticated
  (AES-256-GCM, blind HMAC index). The scan history is a hash chain. The key
  is sealed with `systemd-creds`, bound to the TPM 2.0 chip when the machine
  has one. A record copied, edited or rolled back is detected and the file is
  rescanned.
- **System integrity**: Lguard checks its own installation against a shipped
  SHA-256 manifest.
- **Desktop app**: native look (follows the light/dark setting of GNOME or
  KDE), side-of-screen notifications with action buttons, tray icon, desktop
  widget, starts at login. English, German and Spanish.

## Self-contained

Lguard brings its own runtime and does not depend on, or interfere with, the
system's versions of the same software:

| Component | Version |
|---|---|
| Python | 3.12 (python-build-standalone) |
| Scan engine | ClamAV 1.5, built with its own OpenSSL, curl, libxml2, PCRE2, json-c, zlib and bzip2 |
| Desktop app | Qt 6.8 LTS (PySide6, LGPLv3) |

From the system it needs only glibc ≥ 2.28 and systemd. The desktop app also
uses the desktop's own graphics libraries.

## Supported systems

Debian 10+, Ubuntu 20.04+, RHEL / Oracle Linux / AlmaLinux / Rocky 8+ and
Fedora, x86_64. On systemd older than 250, or without a TPM, the key is kept
in a root-only file instead (`lguard status` shows which).

## Install

```sh
# Debian / Ubuntu
sudo apt install ./lguard_<version>_amd64.deb ./lguard-gui_<version>_amd64.deb
# RHEL family / Fedora
sudo dnf install ./lguard-<version>-1.x86_64.rpm ./lguard-gui-<version>-1.x86_64.rpm
```

A server needs only the `lguard` package. Installing it creates the sealed
key, downloads signatures, starts protection and begins the first scan in the
background at the lowest priority.

Settings are in `/etc/lguard/lguard.toml`. Folders chosen in the app are
saved to `/etc/lguard/lguard.d/50-app.toml`.

## Command line

```
lguard status | verify | findings | history
lguard scan <path>...          scan now
lguard sweep [--full]          quick check of changed files / full disk scan
lguard quarantine list | restore <id> [--allow] | delete <id>
lguard freeze | unfreeze       backups and sync (ransomware shield)
```

## Building

The build runs in the `manylinux_2_28` container (glibc 2.28), so the result
installs everywhere listed above:

```sh
build/build-clamav.sh     # scan engine and its libraries, from verified sources
build/build-python.sh     # runtime with hash-pinned packages
build/assemble.sh         # /opt/lguard tree, manifest, licence notices
build/package.sh          # .deb and .rpm for lguard and lguard-gui
build/test-install.sh docker.io/library/debian:12 ...   # install and test in clean containers
```

Every build fails if any binary needs a newer glibc than 2.28
(`build/check-glibc.sh`).

## Licence

Lguard is free software under the **GNU General Public License v3.0**
(see [LICENSE](LICENSE)). You may use, study, change and share it, including
your own forks; anything you distribute based on it must stay under the GPL
with its source available.

The repository accepts no outside collaborators; improvements are welcome as
forks.

## Licences of bundled components

ClamAV is GPL-2.0. Qt and PySide6 are LGPL-3.0; they ship as replaceable
shared libraries, and Lguard never refuses to run with a replaced Qt. Only
LGPL Qt modules are used. Python is under the PSF licence; OpenSSL under
Apache-2.0; the rest under permissive licences. Details and source links are
in `/opt/lguard/licenses` and `/opt/lguard/gui/licenses`.
