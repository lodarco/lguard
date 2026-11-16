"""Find where download clients save to and where Plex / Jellyfin keep
their libraries, so the app can offer them ("Detected – Add")."""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3
import stat
import time

from .config import SYSTEM_DIRS


def _dirs(paths):
    out = []
    for p in paths:
        p = (p or "").strip().rstrip("/")
        if p and os.path.isabs(p) and os.path.isdir(p) and p not in out:
            out.append(p)
    return out


def _read(path: str, limit: int = 1 << 20) -> str:
    """The text of a settings file found in someone's home. It is read as
    root, and the owner decides what the name points at - so: no link is
    followed, only a regular file is read, and no more than `limit` bytes
    (a link to a device or a pipe would never end)."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return ""
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            return ""
        return os.read(fd, limit).decode("utf-8", "replace")
    except OSError:
        return ""
    finally:
        os.close(fd)


def _homes():
    return sorted(set(glob.glob("/home/*") + ["/root"]))


def qbittorrent() -> list[str]:
    confs = []
    for h in _homes():
        confs += glob.glob(f"{h}/.config/qBittorrent/qBittorrent.conf")
    # services started with --profile=DIR (qbittorrent-nox)
    for cmd in glob.glob("/proc/[0-9]*/cmdline"):
        try:
            args = open(cmd, "rb").read().split(b"\0")
        except OSError:
            continue
        if args and b"qbittorrent" in os.path.basename(args[0]):
            # Only the real program: any process can call itself qbittorrent
            # and name a folder of its choice.
            try:
                exe = os.readlink(os.path.dirname(cmd) + "/exe")
            except OSError:
                continue
            if not exe.startswith(SYSTEM_DIRS):
                continue
            for a in args:
                if a.startswith(b"--profile="):
                    prof = a.split(b"=", 1)[1].decode(errors="replace")
                    if os.path.isabs(prof):
                        confs += [os.path.join(prof, "qBittorrent/config/qBittorrent.conf"),
                                  os.path.join(prof, "qBittorrent/qBittorrent.conf")]
    found = []
    for c in confs:
        text = _read(c)
        found += re.findall(r"^(?:Session\\DefaultSavePath|Downloads\\SavePath|Session\\TempPath)=(.+)$",
                            text, re.M)
    return _dirs(found)


def transmission() -> list[str]:
    files = ["/var/lib/transmission-daemon/info/settings.json", "/etc/transmission-daemon/settings.json",
             "/var/lib/transmission/.config/transmission-daemon/settings.json"]
    for h in _homes():
        files += glob.glob(f"{h}/.config/transmission*/settings.json")
    found = []
    for f in files:
        try:
            d = json.loads(_read(f) or "{}")
            found += [d.get("download-dir"), d.get("incomplete-dir") if d.get("incomplete-dir-enabled") else None]
        except (ValueError, AttributeError):
            continue
    return _dirs(found)


def deluge() -> list[str]:
    found = []
    for h in _homes() + ["/var/lib/deluged"]:
        for f in glob.glob(f"{h}/.config/deluge/core.conf"):
            found += re.findall(r'"(?:download_location|move_completed_path)":\s*"([^"]+)"', _read(f))
    return _dirs(found)


def plex() -> list[str]:
    dbs = glob.glob("/var/lib/plexmediaserver/Library/Application Support/Plex Media Server/"
                    "Plug-in Support/Databases/com.plexapp.plugins.library.db")
    dbs += glob.glob("/var/snap/plexmediaserver/common/Library/Application Support/Plex Media Server/"
                     "Plug-in Support/Databases/com.plexapp.plugins.library.db")
    found = []
    for db in dbs:
        try:
            c = sqlite3.connect("file:" + db.replace(" ", "%20") + "?mode=ro&immutable=1", uri=True)
            found += [r[0] for r in c.execute("SELECT root_path FROM section_locations")]
            c.close()
        except sqlite3.Error:
            continue
    return _dirs(found)


def jellyfin() -> list[str]:
    found = []
    for base in ("/var/lib/jellyfin/root/default", "/var/lib/emby/root/default"):
        for f in glob.glob(f"{base}/*/options.xml"):
            found += re.findall(r"<Path>([^<]+)</Path>", _read(f))
        for f in glob.glob(f"{base}/*/*.mblink"):
            found.append(_read(f, 4096).strip())
    return _dirs(found)


def browser_downloads() -> list[str]:
    """Each user's Downloads folder (where browsers save)."""
    found = []
    for h in _homes():
        found.append(os.path.join(h, "Downloads"))
        m = re.search(r'^XDG_DOWNLOAD_DIR="(.+)"$', _read(f"{h}/.config/user-dirs.dirs", 65536), re.M)
        if m:
            found.append(m.group(1).replace("$HOME", h))
    return found


_cached: tuple[float, dict] = (0.0, {})


def suggestions() -> dict[str, list[str]]:
    """Looked up at most twice a minute, whoever asks how often."""
    global _cached
    if time.time() - _cached[0] > 30:
        _cached = (time.time(), {"downloads": _dirs(qbittorrent() + transmission() + deluge() + browser_downloads()),
                                 "plex": plex(), "jellyfin": jellyfin()})
    return _cached[1]
