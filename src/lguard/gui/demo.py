"""Canned answers in the shape of the real API, for `lguard-gui --demo`
(development and screenshots without a running service)."""
from __future__ import annotations

import time

NOW = time.time()
DAY = 86400


class Demo:
    def __init__(self):
        self.frozen = "no"
        self.quarantine = [
            {"id": "20261110-140212-3d3c3901", "path": "/srv/media/movies/Film.2026.1080p/Codec.Installer.exe",
             "signature": "Lguard.Media.Executable.pe", "size": 5004, "quarantined_at": NOW - 3 * 3600,
             "digest": "9f2981a7cc4d40a2a409dc895de64253acd819d7c0011c8e80b86fe899464e31"},
            {"id": "20261109-214011-1e529fdd", "path": "/home/alex/Downloads/download.com",
             "signature": "Eicar-Test-Signature", "size": 68, "quarantined_at": NOW - 20 * 3600,
             "digest": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"},
        ]

        self.held = [
            {"path": "/mnt/backup/old-pc/Program Files/Archiver/Uninstall.exe", "signature": "Win.Virus.Example-1",
             "digest": "5c1f0c6f3a1b0a57a0e6f0d3b1f9a5c2e4d7b8a9c0d1e2f3a4b5c6d7e8f90a1b", "ts": NOW - 5 * 3600,
             "size": 408624, "copies": 3,
             "detail": 'signed by "Example Software Ltd", unchanged since signing (publisher not verified)'},
        ]

    def call(self, method, **p):
        return getattr(self, "m_" + method)(**p)

    def m_status(self):
        return {"engine": "ClamAV 1.5.4", "signatures": 28179, "engine_ok": True, "realtime": True,
                "watched": ["/", "/home", "/srv", "/mnt/backup", "/dev/shm"],
                "files": 1842317, "counts": {"files": 1842317, "bytes": 1.52e12, "clean": 1842315},
                "last_sweep": NOW - 14 * 3600, "frozen": self.frozen, "quarantine": len(self.quarantine), "held": len(self.held),
                "key": "sealed (systemd-creds)", "history": {"entries": 4812, "head": "7e1c4f02a90b11d2"},
                "version": "demo", "scans": {"quick": True, "full": False}, "stopped": [], "rename_events": True,
                "categories": {"downloads": ["/srv/media/downloads", "/home/alex/Downloads"], "plex": ["/srv/media"],
                               "jellyfin": ["/srv/media"], "Work": ["/home/alex/Work"]},
                "verify": {"percent": 64}, "queue": 0, "current": [], "stats": {"scanned": 4116},
                "sweep": {"running": True, "phase": "media", "percent": 12, "seen": 211433, "bytes": 1.9e11,
                          "findings": 0, "current": "/srv/media/movies/Big.Buck.Bunny.2008.1080p.mkv"}}

    def m_start_sweep(self, full=False):
        return {"started": True}

    def m_pause_sweep(self, minutes=None):
        return {"paused": True}

    def m_resume_sweep(self):
        return {"paused": False}

    def m_set_folders(self, **kw):
        return self.m_get_folders()

    def m_get_folders(self):
        return {"categories": {"downloads": ["/srv/media/downloads", "/home/alex/Downloads"],
                               "plex": ["/srv/media/movies", "/srv/media/series", "/srv/media/kids"],
                               "jellyfin": [], "Work": ["/home/alex/Work"]},
                "category_modes": {"downloads": "downloads", "plex": "media", "jellyfin": "media", "Work": "downloads"},
                "data_paths": ["/home"],
                "priority_paths": [], "extra_excludes": ["/home/alex/Videos/render-cache/*"],
                "report_only": ["/home/alex/Games", "/home/alex/.steam"],
                "detected": {"downloads": ["/srv/media/downloads/incomplete"],
                             "jellyfin": ["/srv/media/movies", "/srv/media/series"]}}

    def m_daily(self, days=14):
        scanned = [5200, 12800, 2100, 400, 600, 5100, 2400, 300, 200, 400, 100, 300, 10900, 4116]
        cached = [30000 + i * 700 for i in range(14)]
        out = []
        for i in range(14):
            day = time.strftime("%Y-%m-%d", time.localtime(NOW - (13 - i) * DAY))
            out.append({"day": day, "scanned": scanned[i], "cached": cached[i], "bytes": 0, "findings": 0})
        return list(reversed(out))[:days]

    def m_findings(self, limit=200):
        return [
            {"ts": NOW - 3 * 3600, "path": self.quarantine[0]["path"], "level": "suspicious",
             "signature": "Lguard.Media.Executable.pe", "action": "quarantined",
             "quarantine_id": self.quarantine[0]["id"], "process": "/usr/lib/jellyfin/bin/jellyfin"},
            {"ts": NOW - 20 * 3600, "path": "/home/alex/Downloads/download.com", "level": "infected",
             "signature": "Eicar-Test-Signature", "action": "quarantined",
             "quarantine_id": "20261109-214011-1e529fdd", "process": "/usr/lib/firefox/firefox"},
        ]

    def m_events(self, limit=100):
        return [
            {"ts": NOW - 3 * 3600, "event": "finding", "detail": "Plex: program in the film library moved to quarantine (Codec.Installer.exe)"},
            {"ts": NOW - 5 * 3600, "event": "deep_verify", "detail": "41208 files, 51200 MiB, 0 mismatches"},
            {"ts": NOW - 8 * 3600, "event": "media_clean", "detail": "Downloads: Series.S02.1080p.WEB – 14 files clean"},
            {"ts": NOW - 14 * 3600, "event": "sweep_end", "detail": "4116 changed files scanned, full disk scan +50 GB"},
            {"ts": NOW - 14 * 3600 - 60, "event": "anchor", "detail": "history sealed in TPM"},
        ]

    def m_quarantine(self):
        return self.quarantine

    def m_category(self, name):
        if name != "downloads":
            return {"name": name, "mode": "media", "paths": self.m_status()["categories"].get(name, []), "items": [
                {"name": "Movies", "path": "/srv/media/movies", "files": 812, "bytes": 2.1e12, "changed": NOW - 2 * DAY, "findings": []},
                {"name": "Series", "path": "/srv/media/series", "files": 2310, "bytes": 1.4e12, "changed": NOW - DAY, "findings": []},
                {"name": "Kids", "path": "/srv/media/kids", "files": 421, "bytes": 3.2e11, "changed": NOW - 9 * DAY, "findings": []}]}
        return {"name": name, "mode": "downloads", "paths": ["/srv/media/downloads", "/home/alex/Downloads"], "items": [
            {"name": "Film.2026.1080p", "path": "x", "files": 3, "bytes": 2.1e9, "changed": NOW - 3 * 3600, "findings": []},
            {"name": "download.com", "path": "x", "files": 1, "bytes": 68, "changed": NOW - 20 * 3600,
             "findings": [self.m_findings()[1]]},
            {"name": "Series.S02.1080p.WEB", "path": "x", "files": 14, "bytes": 23.4e9, "changed": NOW - 8 * 3600, "findings": []},
            {"name": "Documentary.2025.720p", "path": "x", "files": 2, "bytes": 1.4e9, "changed": NOW - 1.3 * DAY, "findings": []},
            {"name": "Cartoon.Collection", "path": "x", "files": 41, "bytes": 12.8e9, "changed": NOW - 2.1 * DAY, "findings": []},
            {"name": "Album.FLAC", "path": "x", "files": 16, "bytes": 0.6e9, "changed": NOW - 3.3 * DAY, "findings": []}]}

    def m_restore(self, qid, trust=False):
        self.quarantine = [q for q in self.quarantine if q["id"] != qid]
        return {"restored_to": "demo"}

    def m_delete(self, qid):
        self.quarantine = [q for q in self.quarantine if q["id"] != qid]
        return {"deleted": qid}

    def m_unfreeze(self):
        self.frozen = "no"
        return []

    def m_held(self):
        return self.held

    def m_decide(self, digest, action):
        self.held = [h for h in self.held if h["digest"] != digest]
        return {}

    def m_trusted(self):
        return [{"digest": "3f79bb7b435b05321651daefd374cdc681dc06faa65e374e38337b88ca046dea",
                 "signature": "Win.Tool.Keygen-1", "note": "restored /home/alex/Games/tools/patcher.exe (uid 1000)",
                 "ts": NOW - 6 * DAY}]

    def m_untrust(self, digest):
        return {"untrusted": digest}

    def m_resume_process(self):
        return {"resumed": []}

    def m_scan(self, path):
        return {"queued": path}
