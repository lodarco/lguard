"""Alerts: journal always, a configurable command (e.g. ntfy), desktop popups."""
from __future__ import annotations

import os
import pwd
import subprocess
import syslog
import threading
import time

from .config import Config
from .i18n import t

_PRIO_SYSLOG = {"min": syslog.LOG_DEBUG, "low": syslog.LOG_INFO, "default": syslog.LOG_NOTICE,
                "high": syslog.LOG_WARNING, "urgent": syslog.LOG_CRIT}


# Users whose Lguard app is connected: it shows its own notification (with
# buttons), so the plain one is not sent to them as well. Set by the daemon.
skip_uids = lambda: set()        # noqa: E731


def safe(text: str) -> str:
    """Text that can always be printed and sent. A file name is bytes and
    need not be valid UTF-8; such bytes are shown as \\xNN instead of making
    the journal, the notification - or the thread writing them - fail."""
    try:
        return text.encode("utf-8", "surrogateescape").decode("utf-8", "backslashreplace")
    except UnicodeEncodeError:
        return text.encode("utf-8", "backslashreplace").decode("utf-8")


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


_sent: list[float] = []          # when the last alerts went out
_held_back = 0                   # how many were not sent since
_lock = threading.Lock()
WINDOW_S = 600


def _allow(cfg: Config, priority: str) -> tuple[bool, int]:
    """(send this one?, how many were held back before it). Urgent alerts
    (ransomware, Lguard itself failing) always go out."""
    global _held_back
    now = time.time()
    with _lock:
        while _sent and _sent[0] < now - WINDOW_S:
            _sent.pop(0)
        if priority != "urgent" and len(_sent) >= max(1, cfg.alert_burst):
            _held_back += 1
            return False, 0
        _sent.append(now)
        before, _held_back = _held_back, 0
        return True, before


def notify(cfg: Config, title: str, message: str, priority: str = "default", covered: bool = False):
    """covered = the connected apps are told about this by an event of their
    own, so they do not need the plain desktop popup as well."""
    title, message = safe(title), safe(message)
    ok, before = _allow(cfg, priority)
    if not ok:
        # Still in the journal and in the history; just not on the phone and the screen.
        try:
            syslog.openlog("lguard", 0, syslog.LOG_DAEMON)
            syslog.syslog(syslog.LOG_NOTICE, f"(alert not sent, too many at once) {title}: {message}".replace("\0", " "))
        except Exception:
            pass
        return
    if before:
        message += "\n" + t("alerts_held_back", n=before)
    try:
        syslog.openlog("lguard", 0, syslog.LOG_DAEMON)
        syslog.syslog(_PRIO_SYSLOG.get(priority, syslog.LOG_NOTICE), f"{title}: {message}".replace("\0", " "))
    except Exception:
        pass                     # the alert itself matters more than its copy in the journal

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
