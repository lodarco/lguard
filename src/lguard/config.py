"""Lguard configuration.

Defaults are generic (any Linux box). A host overrides them in
/etc/lguard/lguard.toml; every key is optional there.
"""
from __future__ import annotations

import fnmatch
import os
import tomllib
from dataclasses import dataclass, field

CONFIG_PATH = os.environ.get("LGUARD_CONFIG", "/etc/lguard/lguard.toml")
STATE_DIR = os.environ.get("LGUARD_STATE", "/var/lib/lguard")

# Never looked at: pseudo filesystems, read-only images, other engines'
# signature files, our own state, container layers (rewritten on every pull)
# and downloads that are still being written (scanned when they finish).
DEFAULT_EXCLUDES = [
    "/proc/*", "/sys/*", "/run/*", "/dev/pts/*", "/dev/mqueue/*",
    "/var/lib/lguard/*", "/var/lib/clamav/*", "/var/lib/snapd/*", "/snap/*",
    "/var/lib/containers/*", "/var/lib/docker/*",
    "/tmp/.mount_*",                       # AppImage FUSE mounts
    "*/.local/share/containers/*",
    "*.!qB", "*.part", "*.crdownload",
]

# Places that churn constantly (caches, logs, live databases). Their data
# files are not scanned, but a *program* found there is: caches are a
# favourite hiding place, so executables are never exempt.
DEFAULT_SOFT_EXCLUDES = [
    "/var/log/*", "/var/cache/*", "/var/tmp/systemd-private-*",
    "/var/lib/postgresql/*", "/var/lib/mysql/*", "/var/lib/systemd/coredump/*",
    "/var/lib/apt/lists/*",
    "*/.cache/*",
    "*/.local/share/Trash/info/*",
    "*/google-chrome/*/Cache/*", "*/chromium/*/Cache/*", "*/Code Cache/*",
    "*/GPUCache/*", "*/Service Worker/CacheStorage/*",
    "*/.mozilla/firefox/*/cache2/*", "*/.mozilla/firefox/*/storage/*",
    "*/steamapps/shadercache/*", "*/steamapps/downloading/*",
    "*/.git/objects/*",
    "*/__pycache__/*",
    "*/appdata_*/preview/*",               # Nextcloud thumbnails
    "*.sqlite-wal", "*.sqlite-shm", "*.db-wal", "*.db-shm", "*-journal",
]

INCOMPLETE = ("*.!qB", "*.part", "*.crdownload")

# Where the operating system keeps its own programs. Used to tell a system
# tool (tar, rsync) from a program started out of a home or temp folder.
SYSTEM_DIRS = ("/usr/", "/bin/", "/sbin/", "/lib/", "/lib64/", "/opt/", "/snap/", "/nix/store/")

# Moving a file out of these would break the OS or the package manager.
# A detection there is reported as critical and left in place.
DEFAULT_NEVER_QUARANTINE = [
    "/usr/*", "/bin/*", "/sbin/*", "/lib/*", "/lib64/*", "/lib32/*",
    "/boot/*", "/etc/*", "/var/lib/dpkg/*", "/var/lib/rpm/*", "/opt/*/lib/*",
]


@dataclass
class Config:
    # Filesystems to watch (fanotify) and sweep. Empty = every local disk.
    roots: list[str] = field(default_factory=list)
    # If set, only changes under these paths are acted on (the filesystems in
    # `roots` are still what is watched). Empty = everything not excluded.
    watch_paths: list[str] = field(default_factory=list)
    # Categories, each its own section in the GUI and its own stats:
    # {"downloads": [...], "plex": [...], "jellyfin": [...]}. Their folders are
    # scanned first and checked for fake media.
    categories: dict[str, list[str]] = field(default_factory=dict)
    # How strict a category is: "media" = a film/music library, where a
    # program has no business (quarantined); "downloads" = mixed content,
    # where programs and disk images are normal and only real tricks
    # (Movie.mp4.exe, a "video" that is a program) are quarantined.
    # Default: plex/jellyfin/emby/kodi are "media", everything else "downloads".
    category_modes: dict[str, str] = field(default_factory=dict)
    # Extra priority folders outside any category.
    priority_paths: list[str] = field(default_factory=list)
    # User data where the ransomware detector looks.
    data_paths: list[str] = field(default_factory=lambda: ["/home"])
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    soft_excludes: list[str] = field(default_factory=lambda: list(DEFAULT_SOFT_EXCLUDES))
    extra_excludes: list[str] = field(default_factory=list)
    never_quarantine: list[str] = field(default_factory=lambda: list(DEFAULT_NEVER_QUARANTINE))

    clamd_socket: str = "/run/lguard-clamd/clamd.sock"
    # Files up to this size are handed to the engine whole. Real media files
    # (video, audio) above media_partial_min, and anything above
    # full_scan_max, get only their head and tail scanned; a non-media file
    # checked that way is recorded as "partial", never as clean.
    full_scan_max: int = 2000 * 1024 * 1024
    media_partial_min: int = 384 * 1024 * 1024
    partial_chunk: int = 64 * 1024 * 1024
    # Every file gets a full SHA-256 (byte-by-byte inventory). >0 = files
    # above this size get a head/tail fingerprint instead (faster, weaker).
    hash_max: int = 0
    # Deep verification: bytes re-hashed per night, and the target age after
    # which every indexed file has been re-read at least once.
    verify_budget_bytes: int = 50 * 1024 ** 3
    verify_cycle_days: int = 30

    quarantine: bool = True
    quarantine_dir: str = os.path.join(STATE_DIR, "quarantine")
    # path-prefix -> command run after a file under it was quarantined
    # ("{path}" is replaced). E.g. Nextcloud files:scan.
    post_quarantine_hooks: dict[str, str] = field(default_factory=dict)

    # Ransomware detector
    ransom_window_s: int = 600
    ransom_suspect_files: int = 10
    ransom_rewrite_window_s: int = 300
    ransom_rewrite_files: int = 300
    # Programs whose rewrites are not counted. Only honoured for programs
    # installed in a system folder (a copy named "rsync" in /tmp is not rsync).
    ransom_ignore_exe: list[str] = field(default_factory=lambda: ["*/ffmpeg*", "*/rsync", "*/clamd"])
    # One program deleting this many known documents while writing as many
    # random-looking files (encrypt to a new name, delete the original).
    ransom_combo_files: int = 30
    # Suspend (SIGSTOP, undone with "lguard resume-process") the program that
    # raised the alarm: "untrusted" = only programs outside the system
    # folders, "always", "never".
    ransom_stop_process: str = "untrusted"
    # A pause from the app longer than this (or without an end) needs the
    # administrator password; no pause lasts longer than a day.
    pause_free_minutes: int = 180
    # Commands that freeze backups / sync when ransomware is suspected, and
    # the ones that undo it.
    freeze_commands: list[str] = field(default_factory=list)
    unfreeze_commands: list[str] = field(default_factory=list)

    # Notification command as an argument list; {title} {message} {priority}
    # are filled in. E.g. ["/usr/local/bin/my-phone-alert", "{priority}",
    # "{title}", "{message}"]
    notify_command: list[str] = field(default_factory=list)
    desktop_notify: bool = True

    language: str = "en"
    # Folders the user marked "report only" in the app (never quarantined).
    report_only: list[str] = field(default_factory=list)
    debounce_s: float = 20.0
    sweep_retro_days: int = 30

    def is_excluded(self, path: str) -> bool:
        for pat in self.excludes + self.extra_excludes:
            if fnmatch.fnmatchcase(path, pat):
                return True
        return False

    def is_soft_excluded(self, path: str) -> bool:
        """Churning data: skipped unless the file is a program."""
        for pat in self.soft_excludes:
            if fnmatch.fnmatchcase(path, pat):
                return True
        return False

    @staticmethod
    def is_incomplete(path: str) -> bool:
        return any(fnmatch.fnmatchcase(path, pat) for pat in INCOMPLETE)

    def mode_of(self, path: str) -> str:
        """"media" or "downloads" for a path in a priority folder."""
        name = self.category_of(path)
        if name is None:
            return "downloads"
        mode = self.category_modes.get(name)
        if mode in ("media", "downloads"):
            return mode
        return "media" if name.lower() in ("plex", "jellyfin", "emby", "kodi") else "downloads"

    def is_watched(self, path: str) -> bool:
        if not self.watch_paths:
            return True
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.watch_paths)

    @property
    def all_priority_paths(self) -> list[str]:
        out = list(self.priority_paths)
        for paths in self.categories.values():
            out += [p for p in paths if p not in out]
        return out

    def is_priority(self, path: str) -> bool:
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.all_priority_paths)

    def category_of(self, path: str) -> str | None:
        """Most specific category whose folder holds `path`."""
        best, best_len = None, -1
        for name, paths in self.categories.items():
            for p in paths:
                if (path == p or path.startswith(p.rstrip("/") + "/")) and len(p) > best_len:
                    best, best_len = name, len(p)
        return best

    def is_data(self, path: str) -> bool:
        return any(path == p or path.startswith(p.rstrip("/") + "/") for p in self.data_paths)

    def may_quarantine(self, path: str) -> bool:
        if not self.quarantine:
            return False
        return not any(fnmatch.fnmatchcase(path, p) for p in self.never_quarantine)


APP_DROPIN = "50-app.toml"
# Settings the desktop app may change (written to lguard.d/50-app.toml).
APP_KEYS = ("categories", "category_modes", "priority_paths", "extra_excludes", "report_only", "data_paths")


def dropin_dir(path: str = CONFIG_PATH) -> str:
    return os.path.join(os.path.dirname(path), "lguard.d")


def load(path: str = CONFIG_PATH) -> Config:
    """Main file first, then lguard.d/*.toml in name order; a later file
    replaces a key (and, for `categories`, one category at a time)."""
    cfg = Config()
    files = [path] if os.path.exists(path) else []
    d = dropin_dir(path)
    if os.path.isdir(d):
        files += [os.path.join(d, f) for f in sorted(os.listdir(d)) if f.endswith(".toml")]
    for fp in files:
        with open(fp, "rb") as f:
            data = tomllib.load(f)
        for key, value in data.items():
            if key == "report_only":            # app-level name for never_quarantine extras
                cfg.never_quarantine = list(cfg.never_quarantine) + [
                    p.rstrip("/") + "/*" for p in value if p.rstrip("/") + "/*" not in cfg.never_quarantine]
                cfg.report_only = list(value)
                continue
            if not hasattr(cfg, key):
                raise ValueError(f"{fp}: unknown setting {key!r}")
            if key in ("categories", "category_modes") and fp != path:
                merged = dict(getattr(cfg, key))
                merged.update(value)
                value = {k: v for k, v in merged.items() if v is not None}
            setattr(cfg, key, value)
    # "torrents" was the name of the downloads category up to 0.1.x
    for table in (cfg.categories, cfg.category_modes):
        if "torrents" in table:
            old = table.pop("torrents")
            if isinstance(old, list):
                table["downloads"] = old + [p for p in table.get("downloads", []) if p not in old]
            else:
                table.setdefault("downloads", old)
    return cfg


def _toml_str(s: str) -> str:
    if any(ord(ch) < 32 or ord(ch) == 127 for ch in s):
        raise ValueError(f"control character in {s!r}")
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_app_settings(values: dict, path: str = CONFIG_PATH) -> str:
    """Write the app-managed settings (categories, folders, exclusions)."""
    d = dropin_dir(path)
    os.makedirs(d, mode=0o755, exist_ok=True)
    lines = ["# Written by the Lguard app (Folders). Edit here or in the app;",
             "# the main /etc/lguard/lguard.toml is never changed by the app.", ""]
    for key in ("priority_paths", "extra_excludes", "report_only", "data_paths"):
        if values.get(key) is not None:
            lines.append(f"{key} = [" + ", ".join(_toml_str(p) for p in values[key]) + "]")
    if "categories" in values:
        lines += ["", "[categories]"]
        for name, paths in values["categories"].items():
            lines.append(f"{_toml_str(name)} = [" + ", ".join(_toml_str(p) for p in paths) + "]")
    if values.get("category_modes"):
        lines += ["", "[category_modes]"]
        for name, mode in values["category_modes"].items():
            lines.append(f"{_toml_str(name)} = {_toml_str(mode)}")
    text = "\n".join(lines) + "\n"
    tomllib.loads(text)                  # never leave a file the service cannot read
    out = os.path.join(d, APP_DROPIN)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)
    return out
