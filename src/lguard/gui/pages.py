"""The app's pages (one per sidebar entry)."""
from __future__ import annotations

import time

from PySide6.QtCore import Qt, Signal
import os

from PySide6.QtWidgets import (QComboBox, QFileDialog, QFrame, QGridLayout, QHBoxLayout, QHeaderView,
                               QLabel, QMessageBox, QProgressBar, QPushButton, QScrollArea, QSizePolicy,
                               QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget)

from . import theme
from .tr import _
from .widgets import BarChart, Card, Dot, IconLabel, Switch, label


# ------------------------------------------------------------------ helpers
def human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1000 or unit == "TB":
            return f"{n:.0f} {unit}" if unit in ("B", "KB") else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def human_int(n) -> str:
    return f"{int(n):,}"


def when(ts) -> str:
    if not ts:
        return "–"
    d = time.time() - float(ts)
    lt = time.localtime(float(ts))
    if d < 86400 and lt.tm_mday == time.localtime().tm_mday:
        return time.strftime("%H:%M", lt)
    if d < 2 * 86400:
        return time.strftime(_("Yesterday") + " %H:%M", lt)
    return time.strftime("%d %b %H:%M", lt)


def kind_of(signature: str) -> tuple[str, str]:
    """(label, colour key) for a finding, in words people understand."""
    s = signature or ""
    if s.startswith("Lguard.Torrent"):
        return _("Fake movie"), "warning"
    if s.startswith("Lguard."):
        return _("Suspicious"), "warning"
    return _("Virus"), "destructive_text"


def explain(signature: str) -> str:
    s = signature or ""
    if "Torrent.Executable" in s:
        return _("A program hidden in a movie or series download. Movies never need one.")
    if "DoubleExtension" in s:
        return _("The name pretends to be a video or document but ends in a program extension.")
    if "FakeVideo" in s:
        return _("Named like a video, but the file is really a program or an archive.")
    if "DiskImage" in s:
        return _("A disk image inside a media download – often used to hide installers.")
    return _("Matches a known threat: {s}", s=s)


def clear(layout):
    while layout.count():
        it = layout.takeAt(0)
        if it.widget():
            it.widget().deleteLater()
        elif it.layout():
            clear(it.layout())


class Page(QScrollArea):
    title = ""

    def __init__(self, client):
        super().__init__()
        self.client = client
        self.setWidgetResizable(True)
        self.setFrameShape(QFrame.NoFrame)
        body = QWidget()
        body.setObjectName("Content")
        self.setWidget(body)
        self.v = QVBoxLayout(body)
        self.v.setContentsMargins(32, 26, 32, 26)
        self.v.setSpacing(18)

    def refresh(self):
        pass

    def on_result(self, tag, data):
        pass


PHASES = {
    "media": "Checking Torrents, Plex and Jellyfin…",
    "drives": "Checking your drives…",
    "signatures": "Re-checking risky files with new virus signatures…",
    "fulldisk": "Full disk scan…",
}


def progress_text(st: dict) -> tuple[str, str, int | None, str] | None:
    """(title, detail, percent or None, current file) while anything is being scanned."""
    sw = st.get("sweep") or {}
    ctl = st.get("sweep_control") or {}
    if sw.get("running") and ctl.get("paused") and not sw.get("paused"):
        return _("Pausing after the current file…"), _("{n} files checked · {size}", n=human_int(sw.get("seen", 0)),
                                                         size=human_bytes(sw.get("bytes", 0))), sw.get("percent"), sw.get("current") or ""
    if sw.get("running") and sw.get("paused"):
        ra = sw.get("resume_at")
        title = _("Scan paused – resumes at {t}", t=time.strftime("%H:%M", time.localtime(ra))) if ra \
            else _("Scan paused")
        return title, _("{n} files checked · {size}", n=human_int(sw.get("seen", 0)),
                        size=human_bytes(sw.get("bytes", 0))), sw.get("percent"), ""
    if sw.get("running"):
        pct = sw.get("percent")
        if sw.get("phase") == "fulldisk":
            pct = sw.get("percent_budget")
        detail = _("{n} files checked · {size}", n=human_int(sw.get("seen", 0)), size=human_bytes(sw.get("bytes", 0)))
        if sw.get("findings"):
            detail += " · " + _("{n} findings", n=sw["findings"])
        return _(PHASES.get(sw.get("phase"), "Checking your drives…")), detail, pct, sw.get("current") or ""
    q = st.get("queue", 0)
    cur = st.get("current") or []
    if q or cur:
        return _("Checking new files…"), _("{n} waiting", n=q), None, (cur[0] if cur else "")
    return None


class ScanBanner(Card):
    def __init__(self, client=None):
        super().__init__(padding=16, spacing=6)
        self.client = client
        top = QHBoxLayout()
        self.icon = IconLabel("shield", "accent", 22)
        top.addWidget(self.icon)
        self.title = label("", bold=True, size=15)
        top.addWidget(self.title, 1)
        self.pct = label("", bold=True, size=15)
        top.addWidget(self.pct)
        from PySide6.QtWidgets import QMenu
        self.pause_btn = QPushButton(_("Pause"))
        m = QMenu(self.pause_btn)
        for text, minutes in ((_("For 30 minutes"), 30), (_("For 1 hour"), 60), (_("For 3 hours"), 180),
                              (_("Until tonight (22:00)"), "night"), (_("Until I resume"), None)):
            m.addAction(text, lambda mins=minutes: self.pause(mins))
        self.pause_btn.setMenu(m)
        self.resume_btn = QPushButton(_("Resume"))
        self.resume_btn.setObjectName("Suggested")
        self.resume_btn.clicked.connect(lambda: self.client and self.client.request("bn.resume", "resume_sweep"))
        top.addWidget(self.pause_btn)
        top.addWidget(self.resume_btn)
        self.lay.addLayout(top)
        self.bar = QProgressBar()
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(8)
        self.lay.addWidget(self.bar)
        self.detail = label("", "Dim")
        self.lay.addWidget(self.detail)
        self.now = label("", "Dim")
        self.now.setStyleSheet("font-family: monospace; font-size: 12px;")
        self.lay.addWidget(self.now)
        self.first = label(_("first_scan_note"), "Dim", wrap=True)
        self.lay.addWidget(self.first)
        self.hide()

    def pause(self, minutes):
        if minutes == "night":
            lt = time.localtime()
            tonight = time.mktime((lt.tm_year, lt.tm_mon, lt.tm_mday, 22, 0, 0, 0, 0, -1))
            if tonight <= time.time():
                tonight += 86400
            minutes = max(1, int((tonight - time.time()) / 60))
        if self.client:
            self.client.request("bn.pause", "pause_sweep", minutes=minutes)

    def update_from(self, st: dict):
        t = progress_text(st)
        sw = st.get("sweep") or {}
        running = bool(sw.get("running"))
        paused = bool(sw.get("paused") or (st.get("sweep_control") or {}).get("paused"))
        self.pause_btn.setVisible(running and not paused)
        self.resume_btn.setVisible(running and paused)
        if not t:
            self.hide()
            return
        title, detail, pct, cur = t
        self.title.setText(title)
        self.detail.setText(detail)
        self.pct.setText(f"{pct}%" if pct is not None else "")
        if pct is None:
            self.bar.setRange(0, 0)            # busy
        else:
            self.bar.setRange(0, 100)
            self.bar.setValue(pct)
        self.now.setText(_("Now: {file}", file=self.now.fontMetrics().elidedText(cur, Qt.ElideMiddle, 700)) if cur else "")
        self.first.setVisible(not st.get("last_sweep") and bool((st.get("sweep") or {}).get("running")))
        self.show()


# ------------------------------------------------------------------ overview
class OverviewPage(Page):
    title = "Overview"
    navigate = Signal(str)

    def __init__(self, client):
        super().__init__(client)
        hero = QVBoxLayout()
        hero.setAlignment(Qt.AlignHCenter)
        self.hero_icon = IconLabel("shield-check", "success", 80, 1.5)
        self.hero_title = label(_("You are protected"), "Hero")
        self.hero_sub = label("", "Dim")
        for w in (self.hero_icon, self.hero_title, self.hero_sub):
            hero.addWidget(w, 0, Qt.AlignHCenter)
        self.v.addLayout(hero)
        self.banner = ScanBanner(client)
        self.v.addWidget(self.banner)

        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = {}
        for i, key in enumerate(("Files protected", "Scanned today", "In quarantine", "Full disk scan")):
            card = Card(padding=16, spacing=2)
            name = label(_(key), "Dim")
            big = label("–", "Big")
            sub = label("", "Dim")
            for w in (name, big, sub):
                card.lay.addWidget(w)
            grid.addWidget(card, 0, i)
            self.tiles[key] = (big, sub)
        self.v.addLayout(grid)

        row = QHBoxLayout()
        row.setSpacing(12)
        chart_card = Card()
        head = QHBoxLayout()
        head.addWidget(label(_("Files scanned per day"), "CardTitle"))
        head.addWidget(label(_("last 14 days"), "Dim"))
        head.addStretch(1)
        chart_card.lay.addLayout(head)
        self.chart = BarChart()
        self.chart.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        chart_card.lay.addWidget(self.chart, 1)
        row.addWidget(chart_card, 2)

        self.modules = Card(padding=0, spacing=0)
        for name, sub in (("Real-time protection", None), ("Torrents", "checked as soon as a download finishes"),
                          ("Plex and Jellyfin", "libraries checked every week"),
                          ("Ransomware shield", "freezes backups if files get encrypted"),
                          ("Full disk scan", "every file re-checked once a month")):
            r = QFrame()
            r.setObjectName("Row")
            h = QHBoxLayout(r)
            h.setContentsMargins(16, 10, 16, 10)
            t = QVBoxLayout()
            t.setSpacing(0)
            t.addWidget(label(_(name)))
            sublabel = label(_(sub) if sub else "", "Dim")
            if name == "Real-time protection":
                self.rt_sub = sublabel
            t.addWidget(sublabel)
            h.addLayout(t, 1)
            sw = Switch(True)
            sw.setEnabled(False)
            sw.setToolTip(_("Change in Settings"))
            h.addWidget(sw)
            self.modules.lay.addWidget(r)
        row.addWidget(self.modules, 1, Qt.AlignTop)
        self.v.addLayout(row)

        self.activity = Card(padding=0, spacing=0)
        self.v.addWidget(self.activity)
        self.v.addStretch(1)

    def refresh(self):
        self.client.request("ov.status", "status")
        self.client.request("ov.daily", "daily", days=14)
        self.client.request("ov.events", "events", limit=6)

    def on_result(self, tag, d):
        if tag in ("ov.status", "app.status"):
            self.banner.update_from(d)
        if tag == "ov.status":
            n = len(d.get("watched", []))
            frozen = d.get("frozen", "no") not in ("no", "", None)
            if not d.get("realtime") or not d.get("engine_ok"):
                self.hero_icon.set("shield-alert", "destructive_text")
                self.hero_title.setText(_("Protection is off"))
            elif frozen or d.get("quarantine"):
                self.hero_icon.set("shield-alert" if frozen else "shield-check", "warning" if frozen else "success")
                self.hero_title.setText(_("Attention needed") if frozen else _("You are protected"))
            else:
                self.hero_icon.set("shield-check", "success")
                self.hero_title.setText(_("You are protected"))
            self.hero_sub.setText(_("Real-time protection on {n} drives", n=n) + " · "
                                  + _("last nightly check {when}", when=when(d.get("last_sweep"))))
            self.rt_sub.setText(_("{n} drives watched", n=n))
            c = d.get("counts") or {}
            self.tiles["Files protected"][0].setText(human_int(d.get("files", 0)))
            self.tiles["Files protected"][1].setText(human_bytes(c.get("bytes", 0)))
            self.tiles["In quarantine"][0].setText(str(d.get("quarantine", 0)))
            col = theme.current["destructive_text"] if d.get("quarantine") else theme.current["ink"]
            self.tiles["In quarantine"][0].setStyleSheet(f"color: {col};")
            pct = (d.get("verify") or {}).get("percent")
            self.tiles["Full disk scan"][0].setText(f"{pct}%" if pct is not None else "–")
            self.tiles["Full disk scan"][1].setText(_("of this month's cycle"))
        elif tag == "ov.daily":
            days = list(reversed(d))
            self.chart.set_data([x["scanned"] for x in days], [x["day"][-2:].lstrip("0") for x in days],
                                [f"{x['day']}: {human_int(x['scanned'])} scanned, {human_int(x['cached'])} unchanged" for x in days])
            if days:
                self.tiles["Scanned today"][0].setText(human_int(days[-1]["scanned"]))
                self.tiles["Scanned today"][1].setText(_("{n} unchanged", n=human_int(days[-1]["cached"])))
        elif tag == "ov.events":
            clear(self.activity.lay)
            title = label(_("Recent activity"), "CardTitle")
            title.setContentsMargins(16, 12, 16, 6)
            self.activity.lay.addWidget(title)
            for e in d:
                r = QFrame()
                r.setObjectName("Row")
                h = QHBoxLayout(r)
                h.setContentsMargins(16, 9, 16, 9)
                bad = e.get("event") in ("finding", "ransom_alarm", "tamper_record", "tamper_content", "tamper_rollback")
                h.addWidget(Dot("destructive_text" if bad else "success"))
                t = label(when(e["ts"]), "Dim")
                t.setFixedWidth(90)
                h.addWidget(t)
                h.addWidget(label(e.get("detail") or e.get("event"), wrap=True), 1)
                self.activity.lay.addWidget(r)


# ------------------------------------------------------------------ findings
class FindingsPage(Page):
    title = "Findings & quarantine"

    def __init__(self, client):
        super().__init__(client)
        self.mode = "quarantine"
        tabs = QFrame()
        tabs.setObjectName("TabBox")
        th = QHBoxLayout(tabs)
        th.setContentsMargins(3, 3, 3, 3)
        th.setSpacing(2)
        self.tab_buttons = {}
        for key, text in (("quarantine", "In quarantine"), ("all", "All findings"), ("trusted", "Trusted")):
            b = QPushButton(_(text).replace("&", "&&"))
            b.setObjectName("Tab")
            b.setCheckable(True)
            b.setChecked(key == self.mode)
            b.clicked.connect(lambda _c=False, k=key: self.set_mode(k))
            th.addWidget(b)
            self.tab_buttons[key] = b
        top = QHBoxLayout()
        top.addWidget(tabs)
        top.addStretch(1)
        self.v.addLayout(top)
        self.heading = label("", "Hero")
        self.v.addWidget(self.heading)
        self.list = QVBoxLayout()
        self.list.setSpacing(12)
        self.v.addLayout(self.list)
        note = label(_("quarantine_note"), "Dim", wrap=True)
        self.v.addWidget(note)
        self.v.addStretch(1)
        self.findings = []

    def set_mode(self, mode):
        self.mode = mode
        for k, b in self.tab_buttons.items():
            b.setChecked(k == mode)
        self.refresh()

    def refresh(self):
        self.client.request("fi.findings", "findings", limit=300)
        if self.mode == "quarantine":
            self.client.request("fi.quarantine", "quarantine")

    def on_result(self, tag, d):
        if tag == "fi.findings":
            self.findings = d
            if self.mode != "quarantine":
                rows = [f for f in d if (self.mode == "all") or "trusted" in (f.get("action") or "")]
                self.render(rows, quarantine=False)
        elif tag == "fi.quarantine" and self.mode == "quarantine":
            self.render(d, quarantine=True)
        elif tag.startswith("fi.action"):
            self.refresh()

    def render(self, rows, quarantine: bool):
        clear(self.list)
        if quarantine:
            self.heading.setText(_("{n} files in quarantine", n=len(rows)) if rows else _("Nothing in quarantine"))
        else:
            self.heading.setText(f"{len(rows)}")
        procs = {f.get("quarantine_id"): f.get("process") for f in self.findings}
        for r in rows:
            sig = r.get("signature", "")
            kind, colour = kind_of(sig)
            card = Card(padding=18, spacing=4)
            h = QHBoxLayout()
            h.setSpacing(14)
            h.addWidget(IconLabel("warning", colour, 32, 1.8), 0, Qt.AlignTop)
            t = QVBoxLayout()
            t.setSpacing(4)
            name_row = QHBoxLayout()
            nm = label(r["path"].rsplit("/", 1)[-1], bold=True, size=16)
            name_row.addWidget(nm)
            k = label(kind + self._category_suffix(r["path"]), bold=True, size=12)
            k.setStyleSheet(f"color: {theme.current[colour]};")
            name_row.addWidget(k)
            name_row.addStretch(1)
            t.addLayout(name_row)
            t.addWidget(label(explain(sig), wrap=True))
            p = label(r["path"], "Dim", wrap=True)
            p.setStyleSheet("font-family: monospace; font-size: 12px;")
            t.addWidget(p)
            proc = procs.get(r.get("id")) or r.get("process")
            meta = when(r.get("quarantined_at") or r.get("ts"))
            if proc:
                meta += " · " + proc.rsplit("/", 1)[-1]
            if r.get("size") is not None:
                meta += " · " + human_bytes(r["size"])
            t.addWidget(label(meta, "Dim"))
            h.addLayout(t, 1)
            if quarantine:
                btns = QHBoxLayout()
                b1 = QPushButton(_("Restore"))
                b2 = QPushButton(_("Restore & trust").replace("&", "&&"))
                b3 = QPushButton(_("Delete"))
                b3.setObjectName("Destructive")
                qid = r["id"]
                b1.clicked.connect(lambda _c=False, q=qid: self.client.request("fi.action", "restore", 600, qid=q))
                b2.clicked.connect(lambda _c=False, q=qid: self.client.request("fi.action", "restore", 600, qid=q, trust=True))
                b3.clicked.connect(lambda _c=False, q=qid, n=r["path"]: self.confirm_delete(q, n))
                for b in (b1, b2, b3):
                    btns.addWidget(b)
                h.addLayout(btns)
            card.lay.addLayout(h)
            self.list.addWidget(card)

    def _category_suffix(self, path):
        for cat in ("torrents", "plex", "jellyfin"):
            if f"/{cat}" in path.lower():
                return f" · {_(cat.capitalize())}"
        return ""

    def confirm_delete(self, qid, path):
        if QMessageBox.question(self, _("Delete"), f"{path}\n\n" + _("Delete this file forever?")) == QMessageBox.Yes:
            self.client.request("fi.action", "delete", 600, qid=qid)


# ------------------------------------------------------------------ media category
class CategoryPage(Page):
    def __init__(self, client, name: str):
        super().__init__(client)
        self.name = name
        self.title = name.capitalize()
        grid = QGridLayout()
        grid.setSpacing(12)
        self.tiles = []
        for i in range(3):
            card = Card(spacing=2)
            a, b, c = label("", "Dim"), label("–", "Big"), label("", "Dim", wrap=True)
            for w in (a, b, c):
                card.lay.addWidget(w)
            grid.addWidget(card, 0, i)
            self.tiles.append((a, b, c))
        self.v.addLayout(grid)
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels([_("Download") if name == "torrents" else _("Folder"),
                                              _("Finished"), _("Files"), _("Result")])
        self.table.verticalHeader().hide()
        self.table.setShowGrid(False)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.setSelectionMode(QTableWidget.NoSelection)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        self.table.horizontalHeader().setDefaultAlignment(Qt.AlignLeft | Qt.AlignVCenter)
        card = Card(padding=0)
        card.lay.addWidget(self.table)
        self.v.addWidget(card)
        if name == "torrents":
            info = Card()
            info.lay.addWidget(label(_("What Lguard checks in every download"), "CardTitle"))
            for line in ("• every file against known viruses",
                         "• programs hidden in movies or series (.exe, .scr, .lnk, .msi…) – quarantined even if no virus is known yet",
                         "• tricks like “Movie.mp4.exe” and “videos” that are really programs or archives"):
                info.lay.addWidget(label(_(line), wrap=True))
            self.v.addWidget(info)
        self.v.addStretch(1)

    def refresh(self):
        self.client.request(f"cat.{self.name}", "category", name=self.name)

    def on_result(self, tag, d):
        if tag != f"cat.{self.name}":
            return
        paths = d.get("paths") or []
        items = d.get("items") or []
        month = [i for i in items if time.time() - i["changed"] < 31 * 86400]
        bad = [i for i in items if i["findings"]]
        self.tiles[0][0].setText(_("Download folder") if self.name == "torrents" else _("Folder"))
        self.tiles[0][1].setText(self.tiles[0][1].fontMetrics().elidedText(paths[0], Qt.ElideLeft, 260)
                                 if paths else "–")
        self.tiles[0][1].setStyleSheet("font-size: 15px; font-family: monospace;")
        self.tiles[0][2].setText(", ".join(paths[1:]) if len(paths) > 1 else
                                 (_("checked as soon as a download finishes") if self.name == "torrents"
                                  else _("libraries checked every week")) if paths
                                 else _("No folder set for {name}", name=self.title))
        self.tiles[1][0].setText(_("This month"))
        self.tiles[1][1].setText(_("{n} downloads", n=len(month)) if self.name == "torrents" else _("{n} folders changed", n=len(month)))
        self.tiles[1][2].setText(_("{n} files · {size}", n=sum(i['files'] for i in month), size=human_bytes(sum(i['bytes'] for i in month))))
        self.tiles[2][0].setText(_("Stopped"))
        self.tiles[2][1].setText(f"{len(bad)}")
        self.tiles[2][1].setStyleSheet(f"color: {theme.current['warning' if bad else 'ink']};")
        self.tiles[2][2].setText(_("fake movies or viruses"))
        self.table.setRowCount(len(items))
        for r, i in enumerate(items):
            res = (_("Fake movie") + " – " + _("Quarantined")) if i["findings"] else _("Clean")
            vals = [i["name"], when(i["changed"]), f"{i['files']} · {human_bytes(i['bytes'])}", res]
            for c, v in enumerate(vals):
                it = QTableWidgetItem(v)
                if c == 3:
                    f = it.font()
                    f.setBold(True)
                    it.setFont(f)
                    it.setForeground(Qt.GlobalColor.white)
                    from PySide6.QtGui import QColor
                    it.setForeground(QColor(theme.current["warning" if i["findings"] else "success"]))
                self.table.setItem(r, c, it)
        self.table.resizeColumnsToContents()
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.Stretch)
        rows_h = sum(self.table.rowHeight(r) for r in range(self.table.rowCount()))
        self.table.setFixedHeight(self.table.horizontalHeader().height() + rows_h + 4)


# ------------------------------------------------------------------ ransomware
class RansomwarePage(Page):
    title = "Ransomware shield"

    def __init__(self, client):
        super().__init__(client)
        self.card = Card(padding=20)
        self.icon = IconLabel("lock", "success", 48, 1.8)
        self.head = label("", "Hero")
        self.sub = label("", "Dim", wrap=True)
        self.btn = QPushButton(_("Unfreeze backups"))
        self.btn.setObjectName("Suggested")
        self.btn.clicked.connect(lambda: self.client.request("rw.unfreeze", "unfreeze", 600))
        row = QHBoxLayout()
        row.addWidget(self.icon)
        t = QVBoxLayout()
        t.addWidget(self.head)
        t.addWidget(self.sub)
        row.addLayout(t, 1)
        row.addWidget(self.btn)
        self.card.lay.addLayout(row)
        self.v.addWidget(self.card)
        explain = Card()
        explain.lay.addWidget(label(_("How it works"), "CardTitle"))
        explain.lay.addWidget(label(_("ransom_explain"), wrap=True))
        self.v.addWidget(explain)
        self.v.addStretch(1)

    def refresh(self):
        self.client.request("rw.status", "status")

    def on_result(self, tag, d):
        if tag == "rw.status":
            frozen = d.get("frozen", "no") not in ("no", "", None)
            self.icon.set("lock", "destructive_text" if frozen else "success")
            self.head.setText(_("Backups are frozen") if frozen else _("No ransomware activity"))
            self.sub.setText(d.get("frozen") if frozen else _("Your documents look normal."))
            self.btn.setVisible(frozen)
        elif tag == "rw.unfreeze":
            self.refresh()


# ------------------------------------------------------------------ integrity
class IntegrityPage(Page):
    title = "System integrity"

    def __init__(self, client):
        super().__init__(client)
        self.card = Card(padding=0, spacing=0)
        self.v.addWidget(self.card)
        self.v.addWidget(label(_("integrity_explain"), "Dim", wrap=True))
        self.v.addStretch(1)

    def refresh(self):
        self.client.request("in.status", "status")

    def on_result(self, tag, d):
        if tag != "in.status":
            return
        clear(self.card.lay)
        key = d.get("key", "")
        rows = [(_("Engine"), f"{d.get('engine')}", "success" if d.get("engine_ok") else "destructive_text"),
                (_("Signatures"), f"{d.get('signatures')}", "success"),
                (_("Inventory key"), _("Sealed to this computer (TPM)") if "sealed" in key else
                 _("Protected file (older system)"), "success" if "sealed" in key else "warning"),
                (_("History entries"), _("{n} · intact", n=d.get('history', {}).get('entries')), "success"),
                (_("Files protected"), human_int(d.get("files", 0)), "success")]
        for name, value, colour in rows:
            r = QFrame()
            r.setObjectName("Row")
            h = QHBoxLayout(r)
            h.setContentsMargins(16, 12, 16, 12)
            h.addWidget(Dot(colour))
            h.addWidget(label(name), 1)
            h.addWidget(label(value, "Dim"))
            self.card.lay.addWidget(r)


# ------------------------------------------------------------------ scan a folder
class ScanPage(Page):
    title = "Scan a folder"

    def __init__(self, client):
        super().__init__(client)
        card = Card(padding=24)
        card.lay.addWidget(IconLabel("folder", "accent", 48, 1.6), 0, Qt.AlignHCenter)
        card.lay.addWidget(label(_("Check any folder or file right now"), "Hero"), 0, Qt.AlignHCenter)
        card.lay.addWidget(label(_("scan_explain"), "Dim", wrap=True), 0, Qt.AlignHCenter)
        b = QPushButton(_("Choose folder…"))
        b.setObjectName("Suggested")
        b.clicked.connect(self.choose)
        card.lay.addWidget(b, 0, Qt.AlignHCenter)
        self.status = label("", "Dim")
        card.lay.addWidget(self.status, 0, Qt.AlignHCenter)
        self.v.addWidget(card)
        self.v.addStretch(1)

    def choose(self):
        path = QFileDialog.getExistingDirectory(self, _("Scan a folder"))
        if path:
            self.status.setText(_("Scanning {path}", path=path))
            self.client.request("sc.scan", "scan", 600, path=path)

    def on_result(self, tag, d):
        if tag == "sc.scan":
            self.status.setText(_("Queued: {path} – results appear under Findings.", path=d.get('queued')))


# ------------------------------------------------------------------ history
class HistoryPage(Page):
    title = "History"

    def __init__(self, client):
        super().__init__(client)
        self.card = Card(padding=0, spacing=0)
        self.v.addWidget(self.card)
        self.v.addStretch(1)

    def refresh(self):
        self.client.request("hi.events", "events", limit=200)

    def on_result(self, tag, d):
        if tag != "hi.events":
            return
        clear(self.card.lay)
        for e in d:
            r = QFrame()
            r.setObjectName("Row")
            h = QHBoxLayout(r)
            h.setContentsMargins(16, 9, 16, 9)
            t = label(when(e["ts"]), "Dim")
            t.setFixedWidth(110)
            h.addWidget(t)
            h.addWidget(label(e.get("event", ""), bold=True))
            h.addWidget(label(e.get("detail") or "", wrap=True), 1)
            self.card.lay.addWidget(r)


# ------------------------------------------------------------------ folders
BUILTIN = ("torrents", "plex", "jellyfin")


class FoldersPage(Page):
    """Which folders are Torrents / Plex / Jellyfin / your own categories,
    which are not scanned at all, and where Lguard only reports."""
    title = "Folders"
    categories_changed = Signal(list)

    def __init__(self, client):
        super().__init__(client)
        self.data = None
        self.v.addWidget(label(_("folders_intro"), "Dim", wrap=True))
        self.body = QVBoxLayout()
        self.body.setSpacing(14)
        self.v.addLayout(self.body)
        bar = QHBoxLayout()
        newcat = QPushButton(_("+ New category"))
        newcat.clicked.connect(self.new_category)
        bar.addWidget(newcat)
        bar.addStretch(1)
        self.status = label("", "Dim")
        bar.addWidget(self.status)
        self.discard = QPushButton(_("Discard changes"))
        self.discard.clicked.connect(self.refresh)
        self.save = QPushButton(_("Save"))
        self.save.setObjectName("Suggested")
        self.save.clicked.connect(self.do_save)
        bar.addWidget(self.discard)
        bar.addWidget(self.save)
        self.v.addLayout(bar)
        self.v.addStretch(1)
        self.set_dirty(False)

    def set_dirty(self, dirty):
        self.dirty = dirty
        self.save.setEnabled(dirty)
        self.discard.setEnabled(dirty)
        if dirty:
            self.status.setText(_("Unsaved changes"))

    def refresh(self):
        self.client.request("fo.get", "get_folders", 60)

    def on_result(self, tag, d):
        if tag in ("fo.get", "fo.save"):
            self.data = {"categories": {k: list(v) for k, v in d["categories"].items()},
                         "priority_paths": list(d.get("priority_paths") or []),
                         "extra_excludes": [p[:-2] if p.endswith("/*") else p for p in d.get("extra_excludes") or []],
                         "report_only": list(d.get("report_only") or []),
                         "detected": d.get("detected") or {}}
            for b in BUILTIN:
                self.data["categories"].setdefault(b, [])
            self.render()
            self.set_dirty(False)
            if tag == "fo.save":
                self.status.setText(_("Saved – applied at once"))
            self.categories_changed.emit(list(self.data["categories"]))

    def render(self):
        clear(self.body)
        d = self.data
        names = list(BUILTIN) + sorted(k for k in d["categories"] if k not in BUILTIN)
        for name in names:
            self.body.addWidget(self.section(_(name.capitalize()) if name in BUILTIN else name,
                                             d["categories"][name], d["detected"].get(name, []),
                                             removable=name not in BUILTIN,
                                             key=("cat", name)))
        self.body.addWidget(self.section(_("Not scanned"), d["extra_excludes"], [], key=("extra_excludes",),
                                         hint=_("Folders Lguard never scans, e.g. scratch or render folders.")))
        self.body.addWidget(self.section(_("Report only"), d["report_only"], [], key=("report_only",),
                                         hint=_("Findings here are reported but never moved, e.g. games.")))

    def _list(self, key):
        return self.data["categories"][key[1]] if key[0] == "cat" else self.data[key[0]]

    def section(self, title, paths, detected, key, removable=False, hint=None):
        card = Card(padding=16, spacing=6)
        head = QHBoxLayout()
        head.addWidget(label(title, "CardTitle"), 1)
        if removable:
            rm = QPushButton(_("Remove category"))
            rm.clicked.connect(lambda: self.remove_category(key[1]))
            head.addWidget(rm)
        card.lay.addLayout(head)
        if hint:
            card.lay.addWidget(label(hint, "Dim", wrap=True))
        if not paths:
            card.lay.addWidget(label(_("No folders yet"), "Dim"))
        for p in paths:
            r = QHBoxLayout()
            kind = "folder" if os.path.isdir(p) or not os.path.exists(p) else "file"
            r.addWidget(IconLabel("folder" if kind == "folder" else "shield", "dim", 16))
            lb = label(p)
            lb.setStyleSheet("font-family: monospace;")
            r.addWidget(lb, 1)
            x = QPushButton("✕")
            x.setToolTip(_("Remove"))
            x.setFixedWidth(34)
            x.clicked.connect(lambda _c=False, path=p: self.remove(key, path))
            r.addWidget(x)
            card.lay.addLayout(r)
        for p in detected:
            if p in paths:
                continue
            r = QHBoxLayout()
            r.addWidget(label(_("Detected:"), "Dim"))
            lb = label(p, "Dim")
            lb.setStyleSheet("font-family: monospace;")
            r.addWidget(lb, 1)
            a = QPushButton(_("Add"))
            a.clicked.connect(lambda _c=False, path=p: self.add(key, path))
            r.addWidget(a)
            card.lay.addLayout(r)
        btns = QHBoxLayout()
        af = QPushButton(_("Add folder…"))
        af.clicked.connect(lambda: self.pick(key, folder=True))
        btns.addWidget(af)
        if key[0] == "cat":
            add_file = QPushButton(_("Add file…"))
            add_file.clicked.connect(lambda: self.pick(key, folder=False))
            btns.addWidget(add_file)
        btns.addStretch(1)
        card.lay.addLayout(btns)
        return card

    def pick(self, key, folder):
        if folder:
            p = QFileDialog.getExistingDirectory(self, _("Add folder…"))
            paths = [p] if p else []
        else:
            paths, _f = QFileDialog.getOpenFileNames(self, _("Add file…"))
        for p in paths:
            self.add(key, p)

    def add(self, key, path):
        lst = self._list(key)
        if path and path not in lst:
            lst.append(path)
            self.render()
            self.set_dirty(True)

    def remove(self, key, path):
        lst = self._list(key)
        if path in lst:
            lst.remove(path)
            self.render()
            self.set_dirty(True)

    def new_category(self):
        from PySide6.QtWidgets import QInputDialog
        name, ok = QInputDialog.getText(self, _("+ New category"), _("Name (e.g. Downloads, Work):"))
        name = (name or "").strip()
        if ok and name and self.data is not None and name not in self.data["categories"]:
            self.data["categories"][name] = []
            self.render()
            self.set_dirty(True)

    def remove_category(self, name):
        if self.data and name in self.data["categories"]:
            del self.data["categories"][name]
            self.render()
            self.set_dirty(True)

    def do_save(self):
        d = self.data
        self.status.setText(_("Saving… (asks for your password)"))
        self.client.request("fo.save", "set_folders", 600, categories=d["categories"],
                            priority_paths=d["priority_paths"], extra_excludes=d["extra_excludes"],
                            report_only=d["report_only"])


# ------------------------------------------------------------------ settings
class SettingsPage(Page):
    title = "Settings"
    changed = Signal(str, object)

    def __init__(self, client, settings):
        super().__init__(client)
        self.settings = settings
        card = Card(padding=0, spacing=0)

        def row(title, widget):
            r = QFrame()
            r.setObjectName("Row")
            h = QHBoxLayout(r)
            h.setContentsMargins(16, 10, 16, 10)
            h.addWidget(label(title), 1)
            h.addWidget(widget)
            card.lay.addWidget(r)

        lang = QComboBox()
        for code, name in (("system", _("Follow system")), ("en", "English"), ("de", "Deutsch"), ("es", "Español")):
            lang.addItem(name, code)
        lang.setCurrentIndex(max(0, lang.findData(settings.value("language", "system"))))
        lang.currentIndexChanged.connect(lambda _i: self.changed.emit("language", lang.currentData()))
        row(_("Language"), lang)

        th = QComboBox()
        for code, name in (("system", _("Follow system")), ("light", _("Light")), ("dark", _("Dark"))):
            th.addItem(name, code)
        th.setCurrentIndex(max(0, th.findData(settings.value("theme", "system"))))
        th.currentIndexChanged.connect(lambda _i: self.changed.emit("theme", th.currentData()))
        row(_("Theme"), th)

        for key, title, default in (("autostart", "Start at login", True), ("widget", "Show desktop widget", False),
                                    ("notifications", "Notifications", True)):
            sw = Switch(settings.value(key, default, type=bool))
            sw.toggled.connect(lambda v, k=key: self.changed.emit(k, v))
            row(_(title), sw)
        self.v.addWidget(card)
        self.v.addStretch(1)
