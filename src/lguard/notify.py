"""Alerts: journal always, a configurable command (e.g. ntfy), desktop popups."""
from __future__ import annotations

import os
import pwd
import subprocess
import syslog

from .config import Config

_PRIO_SYSLOG = {"min": syslog.LOG_DEBUG, "low": syslog.LOG_INFO, "default": syslog.LOG_NOTICE,
                "high": syslog.LOG_WARNING, "urgent": syslog.LOG_CRIT}


# Users whose Lguard app is connected: it shows its own notification (with
# buttons), so the plain one is not sent to them as well. Set by the daemon.
skip_uids = lambda: set()        # noqa: E731


def _plain(text: str) -> str:
    """File names come from anyone; notification servers may read markup."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _desktop_users():
    """(uid, name) of users with a running session bus."""
    try:
        for name in os.listdir("/run/user"):
            if name.isdigit() and os.path.exists(f"/run/user/{name}/bus"):
                uid = int(name)
                if uid >= 1000:
                    try:
                        yield uid, pwd.getpwuid(uid).pw_name
                    except KeyError:
                        pass
    except FileNotFoundError:
        return


def notify(cfg: Config, title: str, message: str, priority: str = "default", covered: bool = False):
    """covered = the connected apps are told about this by an event of their
    own, so they do not need the plain desktop popup as well."""
    syslog.openlog("lguard", 0, syslog.LOG_DAEMON)
    syslog.syslog(_PRIO_SYSLOG.get(priority, syslog.LOG_NOTICE), f"{title}: {message}")

    if cfg.notify_command:
        args = [a.replace("{title}", title).replace("{message}", message).replace("{priority}", priority)
                for a in cfg.notify_command]
        try:
            subprocess.run(args, timeout=30, check=False,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            syslog.syslog(syslog.LOG_ERR, f"notify command failed: {e}")

    if cfg.desktop_notify and os.geteuid() == 0:
        urgency = {"urgent": "critical", "high": "critical", "min": "low", "low": "low"}.get(priority, "normal")
        skip = skip_uids() if covered else set()
        for uid, name in _desktop_users():
            if uid in skip:
                continue
            try:
                subprocess.run(
                    ["runuser", "-u", name, "--", "env",
                     f"DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{uid}/bus",
                     "notify-send", "-a", "Lguard", "-i", "security-high", "-u", urgency,
                     "--", _plain(title), _plain(message)],
                    timeout=10, check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except Exception:
                pass
