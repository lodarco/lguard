"""Lguard desktop app.

  lguard-gui               open the window
  lguard-gui --background  run at login: tray icon, side notifications,
                           optional desktop widget; the window opens on demand
  lguard-gui --demo        canned data (development, screenshots)
"""
from __future__ import annotations

import argparse
import os
import shutil
import sys

from PySide6.QtCore import QObject, QProcess, QSettings, Qt, QTimer, Signal
from PySide6.QtGui import QAction, QGuiApplication
from PySide6.QtWidgets import (QApplication, QFrame, QHBoxLayout, QLabel, QMainWindow, QMenu, QPushButton,
                               QStackedWidget, QSystemTrayIcon, QVBoxLayout, QWidget)

from . import theme, tr
from .client import Client
from .pages import (BUILTIN, CategoryPage, FindingsPage, FoldersPage, HistoryPage, IntegrityPage, OverviewPage,
                    RansomwarePage, ScanPage, SettingsPage, human_int, progress_text)
from .tr import _
from .widgets import Card, IconLabel, Sparkline, icon, label

APP_ID = "io.github.lodarco.Lguard"
AUTOSTART_SYSTEM = "/etc/xdg/autostart/lguard.desktop"


# ------------------------------------------------------------------ notifications
class Notifier(QObject):
    """Side-of-screen notifications through the desktop's own notification
    service (GNOME, KDE, …) via notify-send, with action buttons; the
    clicked action comes back on stdout. Without notify-send: tray balloon."""

    def __init__(self, on_action, tray_getter=None):
        super().__init__()
        self.on_action = on_action
        self.tray_getter = tray_getter
        self.exe = shutil.which("notify-send")
        self.procs = []

    def send(self, title, body, urgency=1, actions=()):
        if not self.exe:
            tray = self.tray_getter() if self.tray_getter else None
            if tray:
                tray.showMessage(title, body)
            return
        args = ["-a", "Lguard", "-i", "lguard", "-u", ("low", "normal", "critical")[max(0, min(2, urgency))]]
        for key, text in actions:
            args.append(f"--action={key}={text}")
        if actions:
            args.append("--wait")
        args += [title, body]
        p = QProcess(self)
        p.finished.connect(lambda *_a, proc=p: self._done(proc))
        p.start(self.exe, args)
        self.procs.append(p)

    def _done(self, proc):
        key = bytes(proc.readAllStandardOutput()).decode(errors="replace").strip()
        if proc in self.procs:
            self.procs.remove(proc)
        if key:
            self.on_action(key)


# ------------------------------------------------------------------ desktop widget
class DesktopWidget(QWidget):
    def __init__(self, open_main):
        super().__init__(None, Qt.Tool | Qt.FramelessWindowHint | Qt.WindowStaysOnBottomHint)
        self.setAttribute(Qt.WA_TranslucentBackground)
        self.setWindowTitle("Lguard")
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        self.card = Card(padding=18, spacing=12)
        self.card.setStyleSheet("#Card { border-radius: 18px; }")
        outer.addWidget(self.card)
        top = QHBoxLayout()
        self.ic = IconLabel("shield-check", "success", 40, 1.8)
        top.addWidget(self.ic)
        t = QVBoxLayout()
        self.title = label(_("You are protected"), bold=True, size=16)
        self.sub = label("", "Dim")
        t.addWidget(self.title)
        t.addWidget(self.sub)
        top.addLayout(t, 1)
        self.card.lay.addLayout(top)
        row = QHBoxLayout()
        self.nums = []
        for name in ("Today", "Waiting", "Quarantine"):
            box = QFrame()
            box.setObjectName("StatBox")
            v = QVBoxLayout(box)
            v.setContentsMargins(10, 8, 10, 8)
            v.addWidget(label(_(name), "Dim"))
            n = label("–", bold=True, size=18)
            v.addWidget(n)
            self.nums.append(n)
            row.addWidget(box)
        self.card.lay.addLayout(row)
        self.progress = label("", "Dim", wrap=True)
        self.progress.hide()
        self.card.lay.addWidget(self.progress)
        self.spark = Sparkline()
        self.card.lay.addWidget(self.spark)
        b = QPushButton(_("Open Lguard"))
        b.setObjectName("Suggested")
        b.clicked.connect(open_main)
        self.card.lay.addWidget(b)
        self.setFixedWidth(330)

    def set_progress(self, t):
        if t:
            title, detail, pct, _cur = t
            self.progress.setText(f"{title} {pct}%" if pct is not None else title)
            self.progress.show()
        else:
            self.progress.hide()

    def update_status(self, st, daily):
        frozen = st.get("frozen", "no") not in ("no", "", None)
        self.ic.set("shield-alert" if frozen else "shield-check", "warning" if frozen else "success")
        self.title.setText(_("Attention needed") if frozen else _("You are protected"))
        self.sub.setText(_("Backups are frozen") if frozen else _("Real-time protection on {n} drives",
                                                                  n=len(st.get("watched", []))))
        today = daily[0]["scanned"] if daily else 0
        self.nums[0].setText(human_int(today))
        self.nums[1].setText(str(st.get("queue", 0)))
        self.nums[2].setText(str(st.get("quarantine", 0)))
        self.spark.set_data([d["scanned"] for d in reversed(daily)], [])


# ------------------------------------------------------------------ main window
class MainWindow(QMainWindow):
    NAV = [("overview", "Overview"), ("findings", "Findings & quarantine"),
           ("-", "Media"), ("downloads", "Downloads"), ("plex", "Plex"), ("jellyfin", "Jellyfin"),
           ("-", "Protection"), ("ransomware", "Ransomware shield"), ("integrity", "System integrity"),
           ("folders", "Folders"), ("scan", "Scan a folder"), ("history", "History"), ("settings", "Settings")]

    def __init__(self, client: Client, settings: QSettings, on_setting):
        super().__init__()
        self.client = client
        self.on_hidden = None
        self.setWindowTitle("Lguard")
        self.setWindowIcon(icon("shield-check", theme.current["accent"], 64))
        self.resize(1200, 820)
        root = QWidget()
        h = QHBoxLayout(root)
        h.setContentsMargins(0, 0, 0, 0)
        h.setSpacing(0)
        self.setCentralWidget(root)

        side = QFrame()
        side.setObjectName("Sidebar")
        side.setFixedWidth(250)
        sv = QVBoxLayout(side)
        sv.setContentsMargins(6, 0, 6, 0)
        sv.setSpacing(2)
        brand = QHBoxLayout()
        brand.setContentsMargins(8, 12, 8, 12)
        brand.addWidget(IconLabel("shield-check", "success", 20))
        brand.addWidget(label("Lguard", "SidebarTitle"), 1)
        sv.addLayout(brand)

        self.stack = QStackedWidget()
        self.pages = {
            "overview": OverviewPage(client), "findings": FindingsPage(client),
            "downloads": CategoryPage(client, "downloads"), "plex": CategoryPage(client, "plex"),
            "jellyfin": CategoryPage(client, "jellyfin"), "ransomware": RansomwarePage(client),
            "integrity": IntegrityPage(client), "folders": FoldersPage(client), "scan": ScanPage(client),
            "history": HistoryPage(client), "settings": SettingsPage(client, settings),
        }
        self.pages["settings"].changed.connect(on_setting)
        self.pages["folders"].categories_changed.connect(self.set_categories)
        self.sidebar = sv
        self.nav_buttons = {}
        for key, text in self.NAV:
            if key == "-":
                sv.addWidget(label(_(text), "SidebarSection"))
                continue
            b = QPushButton(_(text).replace("&", "&&"))
            b.setObjectName("Nav")
            b.setCheckable(True)
            b.clicked.connect(lambda _c=False, k=key: self.show_page(k))
            if key == "findings":
                bl = QHBoxLayout(b)
                bl.setContentsMargins(0, 0, 10, 0)
                bl.addStretch(1)
                self.badge = QLabel("")
                self.badge.setObjectName("Badge")
                self.badge.setFixedHeight(18)
                self.badge.hide()
                bl.addWidget(self.badge)
            sv.addWidget(b)
            self.nav_buttons[key] = b
            self.stack.addWidget(self.pages[key])
            if key == "jellyfin":
                self.custom_at = sv.count()       # own categories go right after Jellyfin
        sv.addStretch(1)
        self.foot = label("", "SidebarFoot", wrap=True)
        sv.addWidget(self.foot)
        h.addWidget(side)

        right = QVBoxLayout()
        right.setSpacing(0)
        header = QFrame()
        header.setObjectName("HeaderBar")
        header.setFixedHeight(48)
        hh = QHBoxLayout(header)
        hh.setContentsMargins(16, 0, 10, 0)
        self.header_title = label("", "HeaderTitle")
        hh.addStretch(1)
        hh.addWidget(self.header_title)
        hh.addStretch(1)
        self.scanning = label("", "Dim")
        hh.addWidget(self.scanning)
        self.scan_btn = QPushButton(_("Scan now"))
        self.scan_btn.setObjectName("Suggested")
        sm = QMenu(self.scan_btn)
        sm.addAction(_("Quick check (changed files)"), lambda: self.scan_now(False))
        sm.addAction(_("Full disk scan (every file)"), lambda: self.scan_now(True))
        sm.addSeparator()
        sm.addAction(_("Scan a folder…"), lambda: self.show_page("scan"))
        self.scan_btn.setMenu(sm)
        hh.addWidget(self.scan_btn)
        menu_btn = QPushButton()
        menu_btn.setIcon(icon("menu", theme.current["ink"], 16))
        menu_btn.setFlat(True)
        menu_btn.setToolTip("Menu")
        menu = QMenu(self)
        menu.addAction(_("Settings"), lambda: self.show_page("settings"))
        menu.addAction(_("About Lguard"), self.about)
        menu_btn.setMenu(menu)
        hh.addWidget(menu_btn)
        right.addWidget(header)
        right.addWidget(self.stack, 1)
        h.addLayout(right, 1)

        client.result.connect(self.on_result)
        client.failed.connect(self.on_failed)
        self.show_page("overview")

    def scan_now(self, full=False):
        self.scan_btn.setEnabled(False)
        self.scan_btn.setText(_("Scanning…"))
        self.client.request("win.sweep", "start_sweep", full=full)

    def set_categories(self, names):
        """Own categories from Folders get their own sidebar entry and page."""
        for name in names:
            if name in self.pages:
                continue
            page = CategoryPage(self.client, name)
            page.title = name
            self.pages[name] = page
            self.stack.addWidget(page)
            b = QPushButton(name.replace("&", "&&"))
            b.setObjectName("Nav")
            b.setCheckable(True)
            b.clicked.connect(lambda _c=False, k=name: self.show_page(k))
            self.sidebar.insertWidget(self.custom_at, b)
            self.custom_at += 1
            self.nav_buttons[name] = b
        for name in [k for k in self.pages if k not in names and k not in dict(self.NAV)]:
            self.nav_buttons.pop(name).deleteLater()
            self.stack.removeWidget(self.pages.pop(name))
            self.custom_at -= 1

    def closeEvent(self, e):
        """X hides the window; Lguard keeps running (tray, notifications)."""
        e.ignore()
        self.hide()
        if self.on_hidden:
            self.on_hidden()

    def update_status(self, st):
        from .pages import progress_text
        t = progress_text(st)
        running = bool((st.get("sweep") or {}).get("running"))
        if t:
            pct = t[2]
            self.scanning.setText(_("Scanning {pct}", pct=f"{pct}%" if pct is not None else "…"))
        else:
            self.scanning.setText("")
        self.scan_btn.setEnabled(not running)
        self.scan_btn.setText(_("Scanning…") if running else _("Scan now"))
        self.pages["overview"].on_result("app.status", st)

    def show_page(self, key):
        for k, b in self.nav_buttons.items():
            b.setChecked(k == key)
        page = self.pages[key]
        self.stack.setCurrentWidget(page)
        self.header_title.setText(_(page.title))
        page.refresh()

    def refresh_current(self):
        self.stack.currentWidget().refresh()
        self.client.request("win.status", "status")

    def on_result(self, tag, data):
        prefix = tag.split(".")[0]
        for page in self.pages.values():
            page.on_result(tag, data)
        if tag in ("win.status", "ov.status") and data.get("categories"):
            self.set_categories(list(BUILTIN) + [k for k in data["categories"] if k not in BUILTIN])
        if tag == "win.status" or tag == "ov.status":
            n = data.get("quarantine", 0)
            self.badge.setText(str(n))
            self.badge.setVisible(bool(n))
            self.foot.setText(f"{_('Signatures')} {data.get('signatures')}\n"
                              + (_("Key sealed in TPM 2.0") if "sealed" in data.get("key", "") else _("Key in protected file"))
                              + " · " + _("{n} history entries", n=data.get('history', {}).get('entries')))
        if prefix in ("fi", "rw") and tag.endswith(("action", "unfreeze")):
            self.refresh_current()

    def on_failed(self, tag, msg):
        if tag.startswith("fo."):
            self.pages["folders"].status.setText(msg)
            return
        if tag == "win.sweep":
            self.scan_btn.setEnabled(True)
            self.scan_btn.setText(_("Scan now"))
        if "not authorized" in msg:
            return
        self.foot.setText(_("Lguard service is not running") if "not reachable" in msg else msg)

    def about(self):
        from PySide6.QtWidgets import QMessageBox
        from lguard import __version__
        QMessageBox.about(self, "Lguard", f"Lguard {__version__}\n\nUses Qt {__import__('PySide6').QtCore.qVersion()} "
                                          "and PySide6 under the LGPLv3; you may replace them with your own builds. "
                                          "Licences: /opt/lguard/licenses")


class _Bridge(QObject):
    """Carries "show the window" from the single-instance thread to the UI thread."""
    show = Signal(str)


# ------------------------------------------------------------------ the app
class LguardApp:
    def __init__(self, args):
        self.args = args
        self.settings = QSettings("Lguard", "lguard")
        tr.set_language(self.settings.value("language") or os.environ.get("LGUARD_LANG") or "system")
        self.qapp = QApplication.instance()
        self.qapp.setApplicationName("Lguard")
        self.qapp.setDesktopFileName("lguard")
        self.qapp.setQuitOnLastWindowClosed(False)      # X hides; Quit is in the tray menu
        theme.apply(self.qapp, self.settings.value("theme", "system"))
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(lambda _s: self.retheme())
        except AttributeError:
            pass
        demo = None
        if args.demo:
            from .demo import Demo
            demo = Demo()
        self.client = Client(demo)
        self.client.event.connect(self.on_event)
        self.client.result.connect(self.on_result)
        self.window = None
        self.widget = None
        self.notifier = Notifier(self.on_notification_action, lambda: self.tray)
        self.tray = None
        self._tray_state = None
        if QSystemTrayIcon.isSystemTrayAvailable():
            self.tray = QSystemTrayIcon(icon("shield-check", theme.LIGHT["success"], 32))
            m = QMenu()
            self.tray_status = QAction("Lguard", m)
            self.tray_status.setEnabled(False)
            m.addAction(self.tray_status)
            m.addSeparator()
            m.addAction(QAction(_("Open Lguard"), m, triggered=self.open_main))
            self.tray_pause = QAction(_("Pause scan for 1 hour"), m,
                                      triggered=lambda: self.client.request("tr.pause", "pause_sweep", 600, minutes=60))
            self.tray_resume = QAction(_("Resume scan"), m,
                                       triggered=lambda: self.client.request("tr.resume", "resume_sweep"))
            m.addAction(self.tray_pause)
            m.addAction(self.tray_resume)
            m.addAction(QAction(_("Quick check now"), m,
                                triggered=lambda: self.client.request("tr.sweep", "start_sweep")))
            m.addAction(QAction(_("Scan a folder…"), m, triggered=lambda: self.open_main("scan")))
            m.addSeparator()
            m.addAction(QAction(_("Quit (protection keeps running)"), m, triggered=self.qapp.quit))
            self.tray.setContextMenu(m)
            self.tray.activated.connect(lambda r: self.open_main() if r == QSystemTrayIcon.Trigger else None)
            self.tray.setToolTip("Lguard")
            self.tray.show()
        if self.settings.value("widget", False, type=bool) or args.widget:
            self.show_widget(True)
        self.client.start_events()
        self.timer = QTimer()
        self.timer.timeout.connect(self.poll)
        self.timer.start(60_000)
        if not args.background:
            self.open_main(args.page)
        self.poll()

    # ---------------------------------------------------- windows
    def open_main(self, page=None):
        if self.window is None:
            self.window = MainWindow(self.client, self.settings, self.on_setting)
            self.window.on_hidden = self.window_hidden
        if page:
            self.window.show_page(page)
        self.window.show()
        self.window.raise_()
        self.window.activateWindow()

    def window_hidden(self):
        if not self.settings.value("told_background", False, type=bool):
            self.settings.setValue("told_background", True)
            where = _("the shield icon in the top bar") if self.tray else _("Lguard in your applications menu")
            self.notifier.send(_("Lguard keeps protecting you"),
                               _("The window is closed, protection keeps running. Open it again from {where}.",
                                 where=where), 1)

    def show_widget(self, on):
        if on and self.widget is None:
            self.widget = DesktopWidget(self.open_main)
            self.widget.show()
            self.poll()
        elif not on and self.widget:
            self.widget.close()
            self.widget = None

    def retheme(self):
        theme.apply(self.qapp)
        for w in (self.window, self.widget):
            if w:
                for child in w.findChildren(QWidget):
                    if hasattr(child, "refresh") and isinstance(child, QLabel):
                        child.refresh()
                w.update()
        if self.window:
            self.window.refresh_current()

    # ---------------------------------------------------- data
    def poll(self):
        self.client.request("app.status", "status")
        self.client.request("app.daily", "daily", days=14)

    def on_result(self, tag, data):
        if tag == "app.status":
            self._status = data
            from .pages import progress_text
            busy = progress_text(data) is not None
            want = 3_000 if busy else 60_000
            if self.timer.interval() != want:
                self.timer.setInterval(want)
            if self.window:
                self.window.update_status(data)
            if self.widget:
                self.widget.set_progress(progress_text(data))
            self.update_tray(data)
            if self.tray:
                t = progress_text(data)
                self.tray.setToolTip("Lguard" + (f" – {t[0]} {t[2]}%" if t and t[2] is not None else (f" – {t[0]}" if t else "")))
        elif tag == "app.daily":
            if self.widget and getattr(self, "_status", None):
                self.widget.update_status(self._status, data)

    def update_tray(self, st):
        if not self.tray:
            return
        t = progress_text(st)
        sw = st.get("sweep") or {}
        frozen = st.get("frozen", "no") not in ("no", "", None)
        if not st.get("realtime") or not st.get("engine_ok") or frozen:
            state, name, col, text = "alert", "shield-alert", theme.LIGHT["warning"] if not frozen else "#e01b24", \
                (_("Backups are frozen") if frozen else _("Protection is off"))
        elif t:
            state, name, col = "scan", "shield", theme.LIGHT["accent"]
            text = t[0] + (f" {t[2]}%" if t[2] is not None else "")
        else:
            state, name, col, text = "ok", "shield-check", "#26a269", _("You are protected")
        if state != self._tray_state:
            self.tray.setIcon(icon(name, col, 32))
            self._tray_state = state
        self.tray_status.setText(text)
        self.tray.setToolTip(f"Lguard – {text}")
        running = bool(sw.get("running"))
        paused = bool(sw.get("paused") or (st.get("sweep_control") or {}).get("paused"))
        self.tray_pause.setVisible(running and not paused)
        self.tray_resume.setVisible(running and paused)

    def on_event(self, ev):
        kind = ev.get("event")
        notify = self.settings.value("notifications", True, type=bool)
        if kind == "finding" and notify:
            cat = ev.get("category")
            title = (_("Fake media") if (ev.get("signature") or "").startswith(("Lguard.Media", "Lguard.Torrent"))
                     else _("Virus"))
            title += " – " + (_("Quarantined") if ev.get("action") == "quarantined" else ev.get("verdict", ""))
            body = os.path.basename(ev.get("path", "")) + (f"  ({_(cat.capitalize())})" if cat else "")
            self.notifier.send(title, body, 1, [("default", _("Show details"))])
        elif kind == "ransom_alarm":
            self.notifier.send(_("Ransomware stopped"), ev.get("body", ""), 2,
                               [("default", _("Show details")), ("unfreeze", _("Unfreeze backups"))])
        if self.window:
            self.window.refresh_current()
        self.poll()

    def on_notification_action(self, key):
        if key == "unfreeze":
            self.open_main("ransomware")
            self.client.request("rw.unfreeze", "unfreeze", 600)
        else:
            self.open_main("findings")

    # ---------------------------------------------------- settings
    def on_setting(self, key, value):
        self.settings.setValue(key, value)
        if key == "theme":
            theme.apply(self.qapp, value)
            self._rebuild()
        elif key == "language":
            tr.set_language(value)
            self._rebuild()
        elif key == "widget":
            self.show_widget(bool(value))
        elif key == "autostart":
            set_autostart(bool(value))

    def _rebuild(self):
        if self.window:
            cur = self.window.stack.currentWidget()
            key = next(k for k, p in self.window.pages.items() if p is cur)
            geo = self.window.geometry()
            self.window.close()
            self.window.deleteLater()
            self.window = None
            self.open_main(key)
            self.window.setGeometry(geo)
        if self.widget:
            self.show_widget(False)
            self.show_widget(True)


def set_autostart(on: bool):
    """Per-user override of the system-wide autostart entry."""
    d = os.path.join(os.environ.get("XDG_CONFIG_HOME", os.path.expanduser("~/.config")), "autostart")
    path = os.path.join(d, "lguard.desktop")
    if on:
        if os.path.exists(path):
            os.unlink(path)
        return
    os.makedirs(d, exist_ok=True)
    with open(path, "w") as f:
        f.write("[Desktop Entry]\nType=Application\nName=Lguard\nExec=lguard-gui --background\nHidden=true\n")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="lguard-gui")
    ap.add_argument("--background", action="store_true", help="tray, notifications and widget only")
    ap.add_argument("--demo", action="store_true", help="canned data, no service needed")
    ap.add_argument("--widget", action="store_true", help="show the desktop widget")
    ap.add_argument("--page", default=None)
    ap.add_argument("--screenshot", metavar="DIR", help="(dev) save every page as PNG and exit")
    ap.add_argument("--theme", choices=["light", "dark", "system"])
    args = ap.parse_args(argv)
    QApplication.setAttribute(Qt.AA_ShareOpenGLContexts)
    qapp = QApplication(sys.argv[:1])
    # one Lguard per user: a second start just shows the running one
    # (plain Unix socket in the abstract namespace; no extra libraries)
    import socket as _socket
    name = f"\0lguard-gui-{os.getuid()}" + ("-demo" if args.demo else "")
    if not args.screenshot:
        probe = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            probe.connect(name)
            probe.sendall(b"show " + (args.page or "-").encode() + (b" bg" if args.background else b"") + b"\n")
            probe.close()
            return 0
        except OSError:
            probe.close()
    app = LguardApp(args)
    bridge = _Bridge()
    bridge.show.connect(lambda page: app.open_main(page or None))
    if not args.screenshot:
        srv = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
        try:
            srv.bind(name)
            srv.listen(4)

            def serve():
                while True:
                    c, _a = srv.accept()
                    msg = c.recv(256).decode(errors="replace").split()
                    c.close()
                    if msg and msg[0] == "show" and "bg" not in msg:
                        bridge.show.emit(msg[1] if len(msg) > 1 and msg[1] != "-" else "")
            import threading
            threading.Thread(target=serve, daemon=True, name="single-instance").start()
        except OSError:
            pass
    if args.theme:
        app.on_setting("theme", args.theme)
    if args.screenshot:
        QTimer.singleShot(400, lambda: screenshots(app, args.screenshot))
    return qapp.exec()


def screenshots(app: LguardApp, out_dir: str):
    os.makedirs(out_dir, exist_ok=True)
    keys = [k for k, _t in MainWindow.NAV if k != "-"]
    mode = "dark" if theme.is_dark() else "light"

    def shoot(i=0):
        if i < len(keys):
            app.window.show_page(keys[i])
            QTimer.singleShot(300, lambda: (app.window.grab().save(f"{out_dir}/{mode}-{keys[i]}.png"), shoot(i + 1)))
        else:
            if app.widget:
                app.widget.adjustSize()
                app.widget.grab().save(f"{out_dir}/{mode}-widget.png")
            app.qapp.quit()
    shoot()


if __name__ == "__main__":
    sys.exit(main())
