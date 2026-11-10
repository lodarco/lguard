"""Find where torrent clients download to and where Plex / Jellyfin keep
their libraries, so the app can offer them ("Detected – Add")."""
from __future__ import annotations

import glob
import json
import os
import re
import sqlite3


def _dirs(paths):
    out = []
    for p in paths:
        p = (p or "").strip().rstrip("/")
        if p and os.path.isabs(p) and os.path.isdir(p) and p not in out:
            out.append(p)
    return out


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
            for a in args:
                if a.startswith(b"--profile="):
                    prof = a.split(b"=", 1)[1].decode(errors="replace")
                    confs += glob.glob(f"{prof}/qBittorrent/config/qBittorrent.conf")
                    confs += glob.glob(f"{prof}/qBittorrent/qBittorrent.conf")
    found = []
    for c in confs:
        try:
            text = open(c, errors="replace").read()
        except OSError:
            continue
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
            d = json.load(open(f))
            found += [d.get("download-dir"), d.get("incomplete-dir") if d.get("incomplete-dir-enabled") else None]
        except (OSError, ValueError):
            continue
    return _dirs(found)


def deluge() -> list[str]:
    found = []
    for h in _homes() + ["/var/lib/deluged"]:
        for f in glob.glob(f"{h}/.config/deluge/core.conf"):
            try:
                text = open(f, errors="replace").read()
                found += re.findall(r'"(?:download_location|move_completed_path)":\s*"([^"]+)"', text)
            except OSError:
                continue
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
            try:
                found += re.findall(r"<Path>([^<]+)</Path>", open(f, errors="replace").read())
            except OSError:
                continue
        for f in glob.glob(f"{base}/*/*.mblink"):
            try:
                found.append(open(f, errors="replace").read().strip())
            except OSError:
                continue
    return _dirs(found)


def suggestions() -> dict[str, list[str]]:
    return {"torrents": _dirs(qbittorrent() + transmission() + deluge()),
            "plex": plex(), "jellyfin": jellyfin()}
