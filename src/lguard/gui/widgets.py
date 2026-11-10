"""Small building blocks: cards, a GNOME-style switch, the bar chart (drawn by
hand with QPainter; Qt Charts is GPL-only and not used), icons from inline SVG."""
from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QLinearGradient, QPainter, QPen, QPixmap
from PySide6.QtSvg import QSvgRenderer
from PySide6.QtWidgets import QAbstractButton, QFrame, QLabel, QSizePolicy, QVBoxLayout, QWidget

from . import theme

SVG = {
    "shield": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/>',
    "shield-check": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M8.5 12l2.5 2.5 4.5-5"/>',
    "shield-alert": '<path d="M12 3l8 3v6c0 4.5-3.4 8.3-8 9-4.6-.7-8-4.5-8-9V6l8-3z"/><path d="M12 8v5M12 16h.01"/>',
    "warning": '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9L2.5 17.5A2 2 0 0 0 4.2 20.5h15.6a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
    "lock": '<rect x="5" y="11" width="14" height="9" rx="2"/><path d="M8 11V8a4 4 0 0 1 8 0v3"/>',
    "menu": '<path d="M4 6h16M4 12h16M4 18h16"/>',
    "folder": '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>',
}


def icon_pixmap(name: str, color: str, size: int = 24, stroke: float = 2.0) -> QPixmap:
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="{color}" '
           f'stroke-width="{stroke}" stroke-linecap="round" stroke-linejoin="round">{SVG[name]}</svg>')
    ratio = 2
    pm = QPixmap(size * ratio, size * ratio)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    QSvgRenderer(QByteArray(svg.encode())).render(p)
    p.end()
    pm.setDevicePixelRatio(ratio)
    return pm


MARK_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="t" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2c2c2e"/><stop offset="1" stop-color="#0a0a0b"/></linearGradient><linearGradient id="l" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7fb3ff"/><stop offset="1" stop-color="#3d72d8"/></linearGradient><linearGradient id="r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f75f5f"/><stop offset="1" stop-color="#d93025"/></linearGradient></defs><path d="M64 7l49 18v35c0 29-20 52-49 60-29-8-49-31-49-60V25z" fill="url(#t)" stroke="url(#r)" stroke-width="7" stroke-linejoin="round"/><path d="M45 33h21v37h21v21H45z" fill="url(#l)" stroke="url(#l)" stroke-width="5" stroke-linejoin="round"/></svg>'''
LOGO_SVG = '''<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 128 128"><defs><linearGradient id="t" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#2c2c2e"/><stop offset="1" stop-color="#0a0a0b"/></linearGradient><linearGradient id="l" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#7fb3ff"/><stop offset="1" stop-color="#3d72d8"/></linearGradient><linearGradient id="r" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#f75f5f"/><stop offset="1" stop-color="#d93025"/></linearGradient></defs><path d="M64 5l35 12.5v24.5c0 20.5-14.5 37-35 43-20.5-6-35-22.5-35-43V17.5z" fill="url(#t)" stroke="url(#r)" stroke-width="5.5" stroke-linejoin="round"/><path d="M51 23h14v26h15v14H51z" fill="url(#l)" stroke="url(#l)" stroke-width="4" stroke-linejoin="round"/><g fill="none" stroke="#ee4f4a" stroke-width="3.4" stroke-linecap="round" stroke-linejoin="round"><circle cx="26.5" cy="107.0" r="7.0"/><path d="M33.5 100.0V117.0a7.0 7.0 0 0 1 -12.0 4.5"/><path d="M39.5 100.0V107.0a7.0 7.0 0 0 0 14.0 0V100.0M53.5 100.0V114.0"/><circle cx="66.5" cy="107.0" r="7.0"/><path d="M73.5 100.0V114.0"/><path d="M79.5 100.0V114.0M79.5 107.0a7.0 7.0 0 0 1 9 -6.5"/><circle cx="101.5" cy="107.0" r="7.0"/><path d="M108.5 92.0V114.0"/></g></svg>'''


def logo_pixmap(size: int = 24, full: bool | None = None) -> QPixmap:
    """The Lguard logo, one picture: a red shield with a bold blue L, and
    "guard" in thinner red letters under it. Below 40 px the word would be
    unreadable, so small sizes show the shield with the L alone."""
    if full is None:
        full = size >= 40
    ratio = 2
    pm = QPixmap(size * ratio, size * ratio)
    pm.fill(Qt.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.Antialiasing)
    QSvgRenderer(QByteArray((LOGO_SVG if full else MARK_SVG).encode())).render(p)
    p.end()
    pm.setDevicePixelRatio(ratio)
    return pm


def logo_icon() -> QIcon:
    ic = QIcon()
    for size in (16, 24, 32, 48, 64, 128):
        ic.addPixmap(logo_pixmap(size))
    return ic


class Pulse:
    """A soft glow that breathes around a widget: "this can be used now"."""

    def __init__(self, widget, color_key: str = "accent"):
        from PySide6.QtCore import QEasingCurve, QVariantAnimation
        from PySide6.QtWidgets import QGraphicsDropShadowEffect
        self.color_key = color_key
        self.fx = QGraphicsDropShadowEffect(widget)
        self.fx.setOffset(0, 0)
        widget.setGraphicsEffect(self.fx)
        self.anim = QVariantAnimation(widget)
        self.anim.setDuration(1800)
        self.anim.setStartValue(0.0)
        self.anim.setKeyValueAt(0.5, 1.0)
        self.anim.setEndValue(0.0)
        self.anim.setEasingCurve(QEasingCurve.InOutSine)
        self.anim.setLoopCount(-1)
        self.anim.valueChanged.connect(self._step)
        self.set_active(False)

    def _step(self, v):
        col = QColor(theme.current[self.color_key])
        col.setAlpha(int(70 + 170 * float(v)))
        self.fx.setColor(col)
        self.fx.setBlurRadius(6 + 16 * float(v))

    def set_active(self, on: bool):
        if on and self.anim.state() != self.anim.State.Running:
            self.fx.setEnabled(True)
            self.anim.start()
        elif not on:
            self.anim.stop()
            self.fx.setEnabled(False)


class PulseBar(QWidget):
    """Progress as a filled bar. It never runs on its own: the fill shows
    the real percentage and breathes only while something is being scanned;
    paused or idle, it stands still."""

    def __init__(self, height: int = 8):
        super().__init__()
        from PySide6.QtCore import QEasingCurve, QVariantAnimation
        self.setFixedHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        self.value = None            # 0..100, or None when there is no percentage
        self.glow = 0.0
        self.anim = QVariantAnimation(self)
        self.anim.setDuration(1600)
        self.anim.setStartValue(0.0)
        self.anim.setKeyValueAt(0.5, 1.0)
        self.anim.setEndValue(0.0)
        self.anim.setEasingCurve(QEasingCurve.InOutSine)
        self.anim.setLoopCount(-1)
        self.anim.valueChanged.connect(self._step)

    def _step(self, v):
        self.glow = float(v)
        self.update()

    def set(self, value, active: bool):
        self.value = None if value is None else max(0, min(100, int(value)))
        if active and self.anim.state() != self.anim.State.Running:
            self.anim.start()
        elif not active and self.anim.state() == self.anim.State.Running:
            self.anim.stop()
            self.glow = 0.0
        self.update()

    def paintEvent(self, _ev):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        r = self.height() / 2
        p.setBrush(QColor(theme.current["track"]))
        p.drawRoundedRect(QRectF(0, 0, self.width(), self.height()), r, r)
        active = self.anim.state() == self.anim.State.Running
        if self.value is None and not active:
            p.end()
            return
        base = QColor(theme.current["accent"] if active else theme.current["dim"])
        peak = QColor(theme.current["accent_hover"])
        g = self.glow
        col = QColor(int(base.red() + (peak.red() - base.red()) * g),
                     int(base.green() + (peak.green() - base.green()) * g),
                     int(base.blue() + (peak.blue() - base.blue()) * g))
        if self.value is None:
            col.setAlpha(int(60 + 120 * g))      # no percentage: the whole bar breathes
            w = self.width()
        else:
            col.setAlpha(int(170 + 85 * g) if active else 150)
            w = max(self.height(), self.width() * self.value / 100) if self.value else 0
        p.setBrush(col)
        p.drawRoundedRect(QRectF(0, 0, w, self.height()), r, r)
        p.end()


class MatrixSidebar(QFrame):
    """The sidebar, with a faint red "digital rain" behind the navigation:
    columns of characters that fade towards their tail. It is a still
    picture (the same on every start), drawn once per size and theme."""

    CHARS = "01<>/\\{}[]#$%&*+=:;LGUARD0123456789"
    CELL_W, CELL_H = 14, 15

    def __init__(self):
        super().__init__()
        self.setObjectName("Sidebar")
        self._cache = None
        self._key = None

    def _rain(self) -> QPixmap:
        import random
        ratio = self.devicePixelRatioF()
        pm = QPixmap(int(self.width() * ratio), int(self.height() * ratio))
        pm.setDevicePixelRatio(ratio)
        pm.fill(Qt.transparent)
        p = QPainter(pm)
        f = QFont(theme.MONO)
        f.setStyleHint(QFont.Monospace)
        f.setPixelSize(12)
        f.setBold(True)
        p.setFont(f)
        rnd = random.Random(7)                     # fixed: the same picture every time
        dark = theme.is_dark()
        peak = 46 if dark else 30                  # alpha of the brightest character (of 255)
        red = (255, 64, 64) if dark else (200, 30, 30)
        rows = self.height() // self.CELL_H + 1
        for col in range(self.width() // self.CELL_W + 1):
            x = col * self.CELL_W + 2
            y = rnd.randrange(-rows, rows)
            while y < rows:
                length = rnd.randrange(5, 18)
                for i in range(length):
                    row = y + i
                    if 0 <= row < rows:
                        # tail fades in from nothing, the last character is the brightest
                        a = int(peak * ((i + 1) / length) ** 1.6)
                        p.setPen(QColor(*red, a if i < length - 1 else min(255, int(peak * 1.7))))
                        p.drawText(x, row * self.CELL_H + 12, rnd.choice(self.CHARS))
                y += length + rnd.randrange(3, 14)
        p.end()
        return pm

    def paintEvent(self, ev):
        super().paintEvent(ev)                     # the themed background and border
        key = (self.width(), self.height(), theme.is_dark())
        if key != self._key:
            self._key, self._cache = key, self._rain()
        p = QPainter(self)
        p.drawPixmap(0, 0, self._cache)
        p.end()


def icon(name: str, color: str, size: int = 24) -> QIcon:
    return QIcon(icon_pixmap(name, color, size))


class IconLabel(QLabel):
    def __init__(self, name: str, color_key: str, size: int = 24, stroke: float = 2.0):
        super().__init__()
        self.name, self.color_key, self.sz, self.stroke = name, color_key, size, stroke
        self.setFixedSize(size, size)
        self.refresh()

    def set(self, name: str, color_key: str):
        self.name, self.color_key = name, color_key
        self.refresh()

    def refresh(self):
        self.setPixmap(icon_pixmap(self.name, theme.current[self.color_key], self.sz, self.stroke))


class Card(QFrame):
    def __init__(self, parent=None, padding=16, spacing=8):
        super().__init__(parent)
        self.setObjectName("Card")
        self.lay = QVBoxLayout(self)
        self.lay.setContentsMargins(padding, padding - 2, padding, padding - 2)
        self.lay.setSpacing(spacing)


def label(text="", obj=None, wrap=False, size=None, bold=False) -> QLabel:
    lb = QLabel(text)
    if obj:
        lb.setObjectName(obj)
    lb.setWordWrap(wrap)
    if size or bold:
        f = lb.font()
        if size:
            f.setPixelSize(size)
        if bold:
            f.setWeight(QFont.Bold)
        lb.setFont(f)
    lb.setTextInteractionFlags(Qt.TextSelectableByMouse)
    return lb


class Switch(QAbstractButton):
    """GNOME-style on/off switch."""
    def __init__(self, checked=True, parent=None):
        super().__init__(parent)
        self.setCheckable(True)
        self.setChecked(checked)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(44, 24)

    def sizeHint(self):
        return QSize(44, 24)

    def paintEvent(self, _):
        c = theme.current
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(c["accent"] if self.isChecked() else c["track"]))
        p.drawRoundedRect(QRectF(0, 1, 44, 22), 11, 11)
        p.setBrush(QColor("#ffffff"))
        x = 22 + 2 if self.isChecked() else 2
        p.drawEllipse(QRectF(x, 3, 18, 18))


class Dot(QWidget):
    def __init__(self, color_key: str, size=8):
        super().__init__()
        self.color_key = color_key
        self.setFixedSize(size, size)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setPen(Qt.NoPen)
        p.setBrush(QColor(theme.current[self.color_key]))
        p.drawEllipse(self.rect())


class BarChart(QWidget):
    """Bars with day labels; the last bar highlighted. Values in any unit."""
    hovered = Signal(int)

    def __init__(self, height=170):
        super().__init__()
        self.values: list[float] = []
        self.labels: list[str] = []
        self.setMinimumHeight(height)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Minimum)
        self.setMouseTracking(True)

    def set_data(self, values, labels, tooltips=None):
        self.values, self.labels = list(values), list(labels)
        self.tooltips = tooltips or []
        self.update()

    def mouseMoveEvent(self, e):
        if not self.values:
            return
        i = int(e.position().x() / max(1, self.width()) * len(self.values))
        if 0 <= i < len(self.tooltips):
            self.setToolTip(self.tooltips[i])

    def paintEvent(self, _):
        c = theme.current
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        n = len(self.values)
        base = h - 20
        p.setPen(QColor(c["dim"]))
        if not n:
            return
        f = p.font()
        f.setPixelSize(11)
        p.setFont(f)
        gap = 8
        bw = (w - gap * (n - 1)) / n
        top = max(self.values) or 1
        for i, v in enumerate(self.values):
            x = i * (bw + gap)
            bh = max(3, (v / top) * (base - 6))
            # the logo's colours: bars in the blue of the L, today's bar
            # brighter and framed in the red of the shield
            rect = QRectF(x, base - bh, bw, bh)
            grad = QLinearGradient(0, base - bh, 0, base)
            today = i == n - 1
            grad.setColorAt(0, QColor(c["logo_blue_hi"]))
            grad.setColorAt(1, QColor(c["logo_blue"]))
            p.setOpacity(1.0 if today else 0.78)
            p.setPen(QPen(QColor(c["logo_red"]), 1.6) if today else Qt.NoPen)
            p.setBrush(grad)
            p.drawRoundedRect(rect, 4, 4)
            p.setOpacity(1.0)
            p.setPen(QColor(c["dim"]))
            if i < len(self.labels):
                p.drawText(QRectF(x - 4, base + 4, bw + 8, 16), Qt.AlignHCenter | Qt.AlignTop, self.labels[i])
        line = QColor(c["logo_red"])
        line.setAlpha(110)
        p.setPen(line)
        p.drawLine(0, int(base) + 1, w, int(base) + 1)


class Sparkline(BarChart):
    def __init__(self):
        super().__init__(height=40)
        self.setMinimumHeight(40)

    def paintEvent(self, _):
        c = theme.current
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        n = len(self.values)
        if not n:
            return
        gap = 3
        bw = (self.width() - gap * (n - 1)) / n
        top = max(self.values) or 1
        p.setPen(Qt.NoPen)
        grad = QLinearGradient(0, 0, 0, self.height())
        grad.setColorAt(0, QColor(c["logo_blue_hi"]))
        grad.setColorAt(1, QColor(c["logo_blue"]))
        p.setBrush(grad)
        for i, v in enumerate(self.values):
            bh = max(3, v / top * self.height())
            p.drawRoundedRect(QRectF(i * (bw + gap), self.height() - bh, bw, bh), 2, 2)
