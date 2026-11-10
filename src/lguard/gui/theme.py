"""The Lguard look: neutral near-black with a steel sheen in the dark
theme, clean white on cool grey in the light one, one blue accent, Inter for
text and Cascadia Mono for paths. The theme follows the desktop's colour
scheme, or the user's choice."""
from __future__ import annotations

import os

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont, QFontDatabase, QGuiApplication, QPalette

# Plain colours: used from Python as well as in the stylesheet.
LIGHT = dict(
    win="#f5f7fa", side="#ffffff", header="#ffffff", view="#f5f7fa", card="#ffffff",
    card_edge="#dfe3eb", ink="#202124", dim="#5f6368", sep="#dfe3eb",
    row_sel="rgba(61,114,216,0.10)", row_hover="#f0f2f6", btn="#f0f2f6", btn_hover="#e6e9ef", btn_edge="#cfd5e1",
    accent="#3d72d8", accent_hover="#3363c2", accent_text="#3d72d8", success="#188038", warning="#8a6200",
    destructive="#d93025", destructive_hover="#b3261e", destructive_text="#d93025",
    bar="#9db8ec", bar_now="#3d72d8", track="#e6e9ef", toast="#ffffff",
)
DARK = dict(
    win="#0a0a0b", side="#1c1c1e", header="#1c1c1e", view="#0a0a0b", card="#1c1c1e",
    card_edge="#38383a", ink="#e8e8ea", dim="#a1a1a6", sep="#38383a",
    row_sel="rgba(90,155,255,0.18)", row_hover="rgba(255,255,255,0.05)", btn="#2c2c2e", btn_hover="#38383a",
    btn_edge="#48484a",
    accent="#5a9bff", accent_hover="#7fb3ff", accent_text="#5a9bff", success="#3ecf6e", warning="#f7c948",
    destructive="#e14b4b", destructive_hover="#f75f5f", destructive_text="#f75f5f",
    bar="#3f6fbf", bar_now="#7fb3ff", track="#2c2c2e", toast="#1c1c1e",
)
# Surfaces as the stylesheet paints them. Dark gets the steel gradients;
# light stays flat.
_GRAD = "qlineargradient(x1:0, y1:0, x2:0, y2:1, {})"
SURFACES = {
    "dark": dict(
        side=_GRAD.format("stop:0 #1c1c1e, stop:1 #151517"),
        header=_GRAD.format("stop:0 #242426, stop:0.5 #1c1c1e, stop:1 #111113"),
        header_edge="#000000",
        card=_GRAD.format("stop:0 #242426, stop:1 #1c1c1e"),
        btn=_GRAD.format("stop:0 #38383a, stop:1 #242426"),
        btn_hover=_GRAD.format("stop:0 #48484a, stop:1 #2c2c2e"),
        on_accent="#ffffff",
    ),
    "light": dict(side="#ffffff", header="#ffffff", header_edge="#dfe3eb", card="#ffffff",
                  btn="#f0f2f6", btn_hover="#e6e9ef", on_accent="#ffffff"),
}

SANS = "Inter Variable"
MONO = "Cascadia Mono"
MONO_CSS = f"font-family: '{MONO}', 'DejaVu Sans Mono', monospace;"
_fonts_loaded = False


def load_fonts():
    """The bundled faces (SIL Open Font License, shipped unmodified), so the
    app looks the same on every desktop."""
    global _fonts_loaded
    if _fonts_loaded:
        return
    _fonts_loaded = True
    here = os.path.dirname(os.path.abspath(__file__))
    for d in (os.environ.get("LGUARD_FONTS"), "/opt/lguard/gui/fonts",
              os.path.join(here, "..", "..", "..", "packaging", "gui", "fonts")):
        if d and os.path.isdir(d):
            for f in sorted(os.listdir(d)):
                if f.endswith((".woff2", ".ttf", ".otf")):
                    QFontDatabase.addApplicationFont(os.path.join(d, f))
            return


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
    load_fonts()
    app.setStyle("Fusion")
    app.setPalette(pal)
    if SANS in QFontDatabase.families():
        f = QFont(SANS)
        f.setPointSizeF(10.5)
        app.setFont(f)
    app.setStyleSheet(stylesheet())


def stylesheet() -> str:
    c = current
    g = SURFACES["dark" if is_dark() else "light"]
    return f"""
    QWidget {{ color: {c['ink']}; }}
    #Sidebar {{ background: {g['side']}; border-right: 1px solid {c['sep']}; }}
    #SidebarTitle {{ font-weight: 700; font-size: 15px; padding: 0 6px; }}
    #SidebarSection {{ color: {c['dim']}; font-size: 11px; font-weight: 700; padding: 14px 12px 3px 12px; }}
    #SidebarFoot {{ color: {c['dim']}; font-size: 12px; padding: 8px 14px 12px 14px; }}
    QPushButton#Nav {{ text-align: left; padding: 7px 12px; border: 1px solid transparent; border-radius: 5px;
                       background: transparent; font-size: 14px; font-weight: 500; }}
    QPushButton#Nav:hover {{ background: {c['row_hover']}; }}
    QPushButton#Nav:checked {{ background: {c['row_sel']}; color: {c['accent_text']}; font-weight: 600; }}
    #HeaderBar {{ background: {g['header']}; border-bottom: 1px solid {g['header_edge']}; }}
    #HeaderTitle {{ font-weight: 700; font-size: 15px; }}
    #Content {{ background: {c['view']}; }}
    QScrollArea, QScrollArea > QWidget > QWidget {{ background: {c['view']}; border: none; }}
    #Card {{ background: {g['card']}; border: 1px solid {c['card_edge']}; border-radius: 8px; }}
    #CardTitle {{ font-weight: 700; font-size: 15px; }}
    #Dim {{ color: {c['dim']}; }}
    #Big {{ font-size: 24px; font-weight: 700; }}
    #Hero {{ font-size: 24px; font-weight: 700; }}
    #Row {{ border-bottom: 1px solid {c['sep']}; }}
    #Badge {{ background: {c['destructive']}; color: #ffffff; border-radius: 9px; padding: 0 7px;
              font-size: 12px; font-weight: 700; }}
    #StatBox {{ background: {c['btn']}; border: 1px solid {c['card_edge']}; border-radius: 8px; }}
    QHeaderView::section:horizontal {{ qproperty-defaultAlignment: AlignLeft; }}
    QPushButton {{ background: {g['btn']}; border: 1px solid {c['btn_edge']}; border-radius: 5px;
                   padding: 6px 14px; font-weight: 600; color: {c['ink']}; }}
    QPushButton:hover {{ background: {g['btn_hover']}; border-color: {c['accent']}; }}
    QPushButton:disabled {{ color: {c['dim']}; }}
    QPushButton#Suggested {{ background: {c['accent']}; border: 1px solid {c['accent']};
                             color: {g['on_accent']}; font-weight: 700; }}
    QPushButton#Suggested:hover {{ background: {c['accent_hover']}; border-color: {c['accent_hover']}; }}
    QPushButton#Destructive {{ background: {c['destructive']}; border: 1px solid {c['destructive']}; color: #ffffff; }}
    QPushButton#Destructive:hover {{ background: {c['destructive_hover']}; border-color: {c['destructive_hover']}; }}
    QPushButton#Tab {{ background: transparent; border: 1px solid transparent; padding: 5px 14px; }}
    QPushButton#Tab:checked {{ background: {c['card']}; border: 1px solid {c['card_edge']};
                               color: {c['accent_text']}; font-weight: 700; }}
    #TabBox {{ background: {c['btn']}; border: 1px solid {c['card_edge']}; border-radius: 7px; }}
    QCheckBox::indicator {{ width: 40px; height: 22px; border-radius: 11px; background: {c['track']}; }}
    QCheckBox::indicator:checked {{ background: {c['accent']}; }}
    QComboBox {{ background: {g['btn']}; border: 1px solid {c['btn_edge']}; border-radius: 5px; padding: 5px 10px; }}
    QComboBox:hover {{ border-color: {c['accent']}; }}
    QComboBox QAbstractItemView {{ background: {c['card']}; border: 1px solid {c['card_edge']};
                                   selection-background-color: {c['accent']}; selection-color: #ffffff; }}
    QMenu {{ background: {c['card']}; border: 1px solid {c['card_edge']}; padding: 4px; }}
    QMenu::item {{ padding: 6px 18px; border-radius: 4px; }}
    QMenu::item:selected {{ background: {c['row_sel']}; color: {c['ink']}; }}
    QProgressBar {{ background: {c['track']}; border: none; border-radius: 4px; }}
    QProgressBar::chunk {{ background: {c['accent']}; border-radius: 4px; }}
    QTableWidget {{ background: transparent; border: none; gridline-color: transparent; }}
    QHeaderView::section {{ background: transparent; color: {c['dim']}; border: none;
                            border-bottom: 1px solid {c['sep']}; padding: 8px; font-weight: 700; }}
    QTableWidget::item {{ border-bottom: 1px solid {c['sep']}; padding: 6px; }}
    QToolTip {{ background: {c['card']}; color: {c['ink']}; border: 1px solid {c['sep']}; }}
    QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
    QScrollBar::handle:vertical {{ background: {c['btn_edge']}; border-radius: 3px; min-height: 30px; }}
    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
    QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical {{ background: transparent; }}
    """
