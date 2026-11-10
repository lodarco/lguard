"""Native look: Adwaita-like colours on Qt's Fusion style, light or dark,
following the desktop's colour scheme (or the user's choice)."""
from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QGuiApplication, QPalette

LIGHT = dict(
    win="#fafafb", side="#ebebed", header="#ffffff", view="#fafafb", card="#ffffff",
    card_edge="rgba(0,0,0,0.08)", ink="#1f1f24", dim="#5c5c66", sep="rgba(0,0,6,0.09)",
    row_sel="rgba(0,0,6,0.09)", row_hover="rgba(0,0,6,0.05)", btn="rgba(0,0,6,0.08)", btn_hover="rgba(0,0,6,0.13)",
    accent="#3584e4", accent_text="#1c71d8", success="#1b7f4c", warning="#8a5c00", destructive="#c01c28",
    destructive_text="#c01c28", bar="#99c1f1", bar_now="#1c71d8", track="#e3e3e7", toast="#fafafb",
)
DARK = dict(
    win="#242424", side="#2e2e32", header="#303030", view="#1e1e1e", card="#2c2c2e",
    card_edge="rgba(255,255,255,0.06)", ink="#ffffff", dim="#adadb5", sep="rgba(255,255,255,0.09)",
    row_sel="rgba(255,255,255,0.10)", row_hover="rgba(255,255,255,0.06)", btn="rgba(255,255,255,0.10)", btn_hover="rgba(255,255,255,0.15)",
    accent="#3584e4", accent_text="#78aeed", success="#8ff0a4", warning="#f8e45c", destructive="#c01c28",
    destructive_text="#ff7b63", bar="#62a0ea", bar_now="#99c1f1", track="#3a3a3e", toast="#2e2e32",
)

_mode = "system"
current = dict(LIGHT)


def system_is_dark() -> bool:
    hints = QGuiApplication.styleHints()
    try:
        return hints.colorScheme() == Qt.ColorScheme.Dark
    except AttributeError:
        return QGuiApplication.palette().color(QPalette.Window).lightness() < 128


def is_dark() -> bool:
    return _mode == "dark" or (_mode == "system" and system_is_dark())


def apply(app, mode: str | None = None):
    global _mode, current
    if mode:
        _mode = mode
    current.clear()
    current.update(DARK if is_dark() else LIGHT)
    c = current
    pal = QPalette()
    pal.setColor(QPalette.Window, QColor(c["win"]))
    pal.setColor(QPalette.WindowText, QColor(c["ink"]))
    pal.setColor(QPalette.Base, QColor(c["card"]))
    pal.setColor(QPalette.AlternateBase, QColor(c["view"]))
    pal.setColor(QPalette.Text, QColor(c["ink"]))
    pal.setColor(QPalette.Button, QColor(c["header"]))
    pal.setColor(QPalette.ButtonText, QColor(c["ink"]))
    pal.setColor(QPalette.Highlight, QColor(c["accent"]))
    pal.setColor(QPalette.HighlightedText, QColor("#ffffff"))
    pal.setColor(QPalette.PlaceholderText, QColor(c["dim"]))
    pal.setColor(QPalette.ToolTipBase, QColor(c["card"]))
    pal.setColor(QPalette.ToolTipText, QColor(c["ink"]))
    pal.setColor(QPalette.Link, QColor(c["accent_text"]))
    app.setStyle("Fusion")
    app.setPalette(pal)
    app.setStyleSheet(stylesheet())


def stylesheet() -> str:
    c = current
    return f"""
    QWidget {{ color: {c['ink']}; }}
    #Sidebar {{ background: {c['side']}; border-right: 1px solid {c['sep']}; }}
    #SidebarTitle {{ font-weight: 700; font-size: 15px; padding: 0 6px; }}
    #SidebarSection {{ color: {c['dim']}; font-size: 12px; font-weight: 700; padding: 12px 12px 2px 12px; }}
    #SidebarFoot {{ color: {c['dim']}; font-size: 12px; padding: 8px 14px 12px 14px; }}
    QPushButton#Nav {{ text-align: left; padding: 8px 12px; border: none; border-radius: 6px;
                       background: transparent; font-size: 14px; font-weight: 400; }}
    QPushButton#Nav:hover {{ background: {c['row_hover']}; }}
    QPushButton#Nav:checked {{ background: {c['row_sel']}; font-weight: 600; }}
    #HeaderBar {{ background: {c['header']}; border-bottom: 1px solid {c['sep']}; }}
    #HeaderTitle {{ font-weight: 700; font-size: 15px; }}
    #Content {{ background: {c['view']}; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: {c['view']}; border: none; }}
    #Card {{ background: {c['card']}; border: 1px solid {c['card_edge']}; border-radius: 12px; }}
    #CardTitle {{ font-weight: 700; font-size: 15px; }}
    #Dim {{ color: {c['dim']}; }}
    #Big {{ font-size: 24px; font-weight: 800; }}
    #Hero {{ font-size: 26px; font-weight: 800; }}
    #Row {{ border-bottom: 1px solid {c['sep']}; }}
    #Badge {{ background: {c['destructive']}; color: #ffffff; border-radius: 9px; padding: 0 7px;
              font-size: 12px; font-weight: 700; }}
    #StatBox {{ background: {c['btn']}; border-radius: 10px; }}
    QHeaderView::section:horizontal {{ qproperty-defaultAlignment: AlignLeft; }}
    QPushButton {{ background: {c['btn']}; border: none; border-radius: 6px; padding: 7px 14px;
                   font-weight: 700; color: {c['ink']}; }}
    QPushButton:hover {{ background: {c['btn_hover']}; }}
    QPushButton#Suggested {{ background: {c['accent']}; color: #ffffff; }}
    QPushButton#Suggested:hover {{ background: #1c71d8; }}
    QPushButton#Destructive {{ background: {c['destructive']}; color: #ffffff; }}
    QPushButton#Destructive:hover {{ background: #a51d2d; }}
    QPushButton#Tab {{ background: transparent; padding: 5px 14px; }}
    QPushButton#Tab:checked {{ background: {c['card']}; font-weight: 700; }}
    #TabBox {{ background: {c['btn']}; border-radius: 8px; }}
    QCheckBox::indicator {{ width: 40px; height: 22px; border-radius: 11px; background: {c['track']}; }}
    QCheckBox::indicator:checked {{ background: {c['accent']}; }}
    QComboBox {{ background: {c['btn']}; border: none; border-radius: 6px; padding: 6px 10px; }}
    QTableWidget {{ background: {c['card']}; border: none; gridline-color: transparent; }}
    QHeaderView::section {{ background: {c['card']}; color: {c['dim']}; border: none;
                            border-bottom: 1px solid {c['sep']}; padding: 8px; font-weight: 700; }}
    QTableWidget::item {{ border-bottom: 1px solid {c['sep']}; padding: 6px; }}
    QToolTip {{ background: {c['card']}; color: {c['ink']}; border: 1px solid {c['sep']}; }}
    """
