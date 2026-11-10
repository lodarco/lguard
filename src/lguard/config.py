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

# Never scanned: pseudo filesystems, caches that churn constantly, databases
# that are always open for writing, container layers (scanned as images are
# pointless: they are rewritten on every pull), our own state.
DEFAULT_EXCLUDES = [
    "/proc/*", "/sys/*", "/run/*", "/dev/pts/*", "/dev/mqueue/*",
    "/var/log/*", "/var/cache/*", "/var/tmp/systemd-private-*",
    "/var/lib/lguard/*", "/var/lib/clamav/*", "/var/lib/snapd/*", "/snap/*",
    "/var/lib/containers/*", "/var/lib/docker/*", "/var/lib/postgresql/*",
    "/var/lib/mysql/*", "/var/lib/systemd/coredump/*", "/var/lib/apt/lists/*",
    "/tmp/.mount_*",                       # AppImage FUSE mounts
    "*/.cache/*",
    "*/.local/share/containers/*",
    "*/.local/share/Trash/info/*",
    "*/google-chrome/*/Cache/*", "*/chromium/*/Cache/*", "*/Code Cache/*",
    "*/GPUCache/*", "*/Service Worker/CacheStorage/*",
    "*/.mozilla/firefox/*/cache2/*", "*/.mozilla/firefox/*/storage/*",
    "*/steamapps/shadercache/*", "*/steamapps/downloading/*",
    "*/.git/objects/*",
    "*/__pycache__/*",
    "*/appdata_*/preview/*",               # Nextcloud thumbnails
    "*.!qB", "*.part", "*.crdownload",     # incomplete downloads: scanned when finished
    "*.sqlite-wal", "*.sqlite-shm", "*.db-wal", "*.db-shm", "*-journal",
]

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
    # Media categories, each its own section in the GUI and its own stats:
    # {"torrents": [...], "plex": [...], "jellyfin": [...]}. Their folders are
    # scanned first, the fake-film heuristics apply and they get a weekly
    # full pass.
    categories: dict[str, list[str]] = field(default_factory=dict)
    # Extra priority folders outside any category.
    priority_paths: list[str] = field(default_factory=list)
    # User data where the ransomware detector looks.
    data_paths: list[str] = field(default_factory=lambda: ["/home"])
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    extra_excludes: list[str] = field(default_factory=list)
    never_quarantine: list[str] = field(default_factory=lambda: list(DEFAULT_NEVER_QUARANTINE))

    clamd_socket: str = "/run/lguard-clamd/clamd.sock"
    # Files up to this size are handed to clamd whole; above it only the
    # head and the tail are scanned (big videos).
    full_scan_max: int = 384 * 1024 * 1024
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
    ransom_ignore_exe: list[str] = field(default_factory=lambda: ["*/ffmpeg*", "*/rsync", "*/clamd"])
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
APP_KEYS = ("categories", "priority_paths", "extra_excludes", "report_only")


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
            if key == "categories" and fp != path:
                merged = dict(cfg.categories)
                merged.update(value)
                value = {k: v for k, v in merged.items() if v is not None}
            setattr(cfg, key, value)
    return cfg


def _toml_str(s: str) -> str:
    return '"' + s.replace("\\", "\\\\").replace('"', '\\"') + '"'


def write_app_settings(values: dict, path: str = CONFIG_PATH) -> str:
    """Write the app-managed settings (categories, folders, exclusions)."""
    d = dropin_dir(path)
    os.makedirs(d, mode=0o755, exist_ok=True)
    lines = ["# Written by the Lguard app (Folders). Edit here or in the app;",
             "# the main /etc/lguard/lguard.toml is never changed by the app.", ""]
    for key in ("priority_paths", "extra_excludes", "report_only"):
        if key in values:
            lines.append(f"{key} = [" + ", ".join(_toml_str(p) for p in values[key]) + "]")
    if "categories" in values:
        lines += ["", "[categories]"]
        for name, paths in values["categories"].items():
            lines.append(f"{_toml_str(name)} = [" + ", ".join(_toml_str(p) for p in paths) + "]")
    out = os.path.join(d, APP_DROPIN)
    tmp = out + ".tmp"
    with open(tmp, "w") as f:
        f.write("\n".join(lines) + "\n")
    os.chmod(tmp, 0o644)
    os.replace(tmp, out)
    return out
