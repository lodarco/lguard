"""Freezing backups and sync when ransomware is suspected, and undoing it.

What "freeze" means is configured per host (freeze_commands): stop the timers
and clients that copy data onwards, so encrypted files cannot overwrite the
good copies. The state is remembered in the index so the GUI and `lguard
status` show it, and so it survives a restart.
"""
from __future__ import annotations

import subprocess
import time

from .config import Config
from .index import Index


def _run(cmds: list[str], log) -> list[str]:
    out = []
    for c in cmds:
        try:
            r = subprocess.run(c, shell=True, timeout=120, capture_output=True, text=True)
            out.append(f"{'ok' if r.returncode == 0 else 'FAIL ' + str(r.returncode)}: {c}")
        except Exception as e:
            out.append(f"FAIL {e}: {c}")
        log(out[-1])
    return out


def freeze(cfg: Config, index: Index, reason: str, log=print) -> bool:
    if not cfg.freeze_commands:
        index.event("freeze_skipped", reason)
        index.commit()
        return False
    res = _run(cfg.freeze_commands, log)
    index.meta_set("frozen", f"{time.strftime('%Y-%m-%d %H:%M')} {reason}")
    index.event("freeze", reason + " | " + "; ".join(res))
    index.commit()
    return True


def unfreeze(cfg: Config, index: Index, log=print):
    res = _run(cfg.unfreeze_commands, log)
    index.meta_set("frozen", "no")
    index.event("unfreeze", "; ".join(res))
    index.commit()
    return res


def is_frozen(index: Index) -> bool:
    v = index.meta_get("frozen", "no")
    return bool(v) and v != "no"
