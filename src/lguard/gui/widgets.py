"""Small building blocks: cards, a GNOME-style switch, the bar chart (drawn by
hand with QPainter; Qt Charts is GPL-only and not used), icons from inline SVG."""
from __future__ import annotations

from PySide6.QtCore import QByteArray, QRectF, QSize, Qt, Signal
from PySide6.QtGui import QColor, QFont, QIcon, QPainter, QPixmap
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
            p.setPen(Qt.NoPen)
            p.setBrush(QColor(c["bar_now"] if i == n - 1 else c["bar"]))
            p.drawRoundedRect(QRectF(x, base - bh, bw, bh), 4, 4)
            p.setPen(QColor(c["dim"]))
            if i < len(self.labels):
                p.drawText(QRectF(x - 4, base + 4, bw + 8, 16), Qt.AlignHCenter | Qt.AlignTop, self.labels[i])
        p.setPen(QColor(c["sep"]))
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
        p.setBrush(QColor(c["accent"]))
        for i, v in enumerate(self.values):
            bh = max(3, v / top * self.height())
            p.drawRoundedRect(QRectF(i * (bw + gap), self.height() - bh, bw, bh), 2, 2)
