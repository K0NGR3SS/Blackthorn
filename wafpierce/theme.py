"""Centralized visual theme for the WAFPierce GUI.

A single source of truth for the application's look: a modern, neutral
dark palette (slate surfaces with an indigo accent) plus one comprehensive
Qt stylesheet that restyles every common widget consistently.

Usage::

    from wafpierce.theme import PALETTE, apply_theme
    apply_theme(app)            # global QSS on the QApplication

The palette is also exported so individual widgets that need bespoke,
per-state styling (progress bars, status legends, etc.) can stay in sync
with the rest of the UI instead of hard-coding colours.
"""

from __future__ import annotations


# --- Palette -------------------------------------------------------------
# Modern neutral dark: graphite/slate surfaces, restrained indigo accent.
PALETTE = {
    # Backgrounds / surfaces (darkest -> lightest)
    "window": "#0e1116",     # app background
    "sidebar": "#0a0d12",    # left navigation rail
    "surface": "#12161d",    # main content area
    "card": "#161b23",       # raised cards / panels
    "input": "#1a212b",      # input fields, list rows
    "input_alt": "#1f2731",  # hover / alternate rows
    "elevated": "#222b37",   # pressed / elevated controls

    # Borders / dividers
    "border": "#262f3b",
    "border_subtle": "#1c232d",

    # Text
    "text": "#e6eaf0",
    "text_muted": "#9aa5b5",
    "text_faint": "#6b7585",
    "text_inverse": "#0b0e12",

    # Accent (indigo)
    "accent": "#6366f1",
    "accent_hover": "#777bf2",
    "accent_active": "#4f52d6",
    "accent_soft": "rgba(99, 102, 241, 0.14)",
    "accent_softer": "rgba(99, 102, 241, 0.08)",

    # Semantic
    "success": "#22c55e",
    "success_dim": "#15331f",
    "warning": "#f59e0b",
    "danger": "#ef4444",
    "danger_dim": "#3a1d1d",
    "info": "#38bdf8",

    # Status (target queue)
    "status_queued": "#2a3340",
    "status_running": "#6366f1",
    "status_done": "#15331f",
    "status_error": "#7f1d1d",
}

# Preferred UI / monospace font stacks (Qt resolves the first available).
UI_FONT = '"Segoe UI", "Inter", -apple-system, "Helvetica Neue", Arial, sans-serif'
MONO_FONT = '"JetBrains Mono", "Cascadia Code", "Fira Code", Consolas, "DejaVu Sans Mono", monospace'


def stylesheet() -> str:
    """Return the global application stylesheet."""
    p = PALETTE
    return f"""
/* ============================ BASE ============================ */
QWidget {{
    background-color: {p['window']};
    color: {p['text']};
    font-family: {UI_FONT};
    font-size: 13px;
}}
QMainWindow, QDialog {{ background-color: {p['window']}; }}

QToolTip {{
    background-color: {p['card']};
    color: {p['text']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 5px 8px;
}}

/* ============================ LABELS ============================ */
QLabel {{ background: transparent; color: {p['text']}; }}
QLabel:disabled {{ color: {p['text_faint']}; }}

/* ===================== INPUTS / SPINBOXES ===================== */
QLineEdit, QPlainTextEdit, QTextEdit,
QSpinBox, QDoubleSpinBox, QComboBox {{
    background-color: {p['input']};
    color: {p['text']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 7px 10px;
    selection-background-color: {p['accent']};
    selection-color: #ffffff;
}}
QPlainTextEdit, QTextEdit {{ font-family: {MONO_FONT}; }}
QLineEdit:focus, QPlainTextEdit:focus, QTextEdit:focus,
QSpinBox:focus, QDoubleSpinBox:focus, QComboBox:focus {{
    border: 1px solid {p['accent']};
}}
QLineEdit:disabled, QSpinBox:disabled, QDoubleSpinBox:disabled, QComboBox:disabled {{
    color: {p['text_faint']};
    background-color: {p['surface']};
}}
QLineEdit::placeholder {{ color: {p['text_faint']}; }}

QSpinBox::up-button, QDoubleSpinBox::up-button,
QSpinBox::down-button, QDoubleSpinBox::down-button {{
    width: 16px; border: none; background: transparent;
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background-color: {p['card']};
    color: {p['text']};
    border: 1px solid {p['border']};
    selection-background-color: {p['accent_soft']};
    selection-color: {p['text']};
    outline: none;
}}

/* ============================ BUTTONS ============================ */
QPushButton {{
    background-color: {p['input']};
    color: {p['text']};
    border: 1px solid {p['border']};
    border-radius: 6px;
    padding: 8px 16px;
    font-weight: 600;
}}
QPushButton:hover {{ background-color: {p['input_alt']}; border-color: {p['accent']}; }}
QPushButton:pressed {{ background-color: {p['elevated']}; }}
QPushButton:disabled {{ background-color: {p['surface']}; color: {p['text_faint']}; border-color: {p['border_subtle']}; }}

/* Primary (accent) button: set objectName('PrimaryButton') */
QPushButton#PrimaryButton {{
    background-color: {p['accent']};
    color: #ffffff;
    border: 1px solid {p['accent']};
}}
QPushButton#PrimaryButton:hover {{ background-color: {p['accent_hover']}; border-color: {p['accent_hover']}; }}
QPushButton#PrimaryButton:pressed {{ background-color: {p['accent_active']}; }}
QPushButton#PrimaryButton:disabled {{ background-color: {p['surface']}; color: {p['text_faint']}; border-color: {p['border_subtle']}; }}

/* Danger button: set objectName('DangerButton') */
QPushButton#DangerButton {{ color: #ffffff; background-color: {p['danger']}; border-color: {p['danger']}; }}
QPushButton#DangerButton:hover {{ background-color: #f25555; }}
QPushButton#DangerButton:disabled {{ background-color: {p['surface']}; color: {p['text_faint']}; border-color: {p['border_subtle']}; }}

/* ============================ CHECKBOX ============================ */
QCheckBox {{ spacing: 8px; background: transparent; }}
QCheckBox::indicator {{
    width: 16px; height: 16px;
    border: 1px solid {p['border']};
    border-radius: 5px;
    background-color: {p['input']};
}}
QCheckBox::indicator:hover {{ border-color: {p['accent']}; }}
QCheckBox::indicator:checked {{
    background-color: {p['accent']};
    border-color: {p['accent']};
}}

/* ===================== TREE / LIST / TABLE ===================== */
QTreeWidget, QTreeView, QListWidget, QListView, QTableWidget, QTableView {{
    background-color: {p['surface']};
    color: {p['text']};
    border: 1px solid {p['border']};
    border-radius: 10px;
    outline: none;
    alternate-background-color: {p['card']};
}}
QTreeWidget::item, QListWidget::item {{
    padding: 6px 4px;
    border-radius: 6px;
}}
QTreeWidget::item:hover, QListWidget::item:hover {{ background-color: {p['accent_softer']}; }}
QTreeWidget::item:selected, QListWidget::item:selected {{
    background-color: {p['accent_soft']};
    color: {p['text']};
}}
QHeaderView::section {{
    background-color: {p['card']};
    color: {p['text_muted']};
    border: none;
    border-bottom: 1px solid {p['border']};
    padding: 8px 10px;
    font-weight: 600;
}}
QTreeWidget::branch {{ background: transparent; }}

/* ============================ PROGRESS ============================ */
QProgressBar {{
    border: 1px solid {p['border']};
    border-radius: 7px;
    background-color: {p['input']};
    text-align: center;
    color: {p['text']};
    font-weight: 600;
}}
QProgressBar::chunk {{
    border-radius: 6px;
    background-color: qlineargradient(x1:0, y1:0, x2:1, y2:0,
        stop:0 {p['accent_active']}, stop:1 {p['accent']});
}}

/* ============================ SCROLLBARS ============================ */
QScrollBar:vertical {{ background: transparent; width: 11px; margin: 2px; }}
QScrollBar::handle:vertical {{ background: {p['elevated']}; border-radius: 5px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {p['accent']}; }}
QScrollBar:horizontal {{ background: transparent; height: 11px; margin: 2px; }}
QScrollBar::handle:horizontal {{ background: {p['elevated']}; border-radius: 5px; min-width: 28px; }}
QScrollBar::handle:horizontal:hover {{ background: {p['accent']}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; background: none; border: none; }}
QScrollBar::add-page, QScrollBar::sub-page {{ background: none; }}
QScrollArea#PageScroll {{
    background-color: {p['surface']};
    border: none;
}}
QScrollArea#PageScroll > QWidget > QWidget {{ background-color: {p['surface']}; }}

/* ============================ TABS ============================ */
QTabWidget::pane {{ border: 1px solid {p['border']}; border-radius: 10px; background: {p['surface']}; top: -1px; }}
QTabBar::tab {{
    background: transparent;
    color: {p['text_muted']};
    padding: 9px 16px;
    margin-right: 4px;
    border: none;
    border-bottom: 2px solid transparent;
}}
QTabBar::tab:hover {{ color: {p['text']}; }}
QTabBar::tab:selected {{ color: {p['text']}; border-bottom: 2px solid {p['accent']}; }}

/* ============================ MENUS ============================ */
QMenu {{
    background-color: {p['card']};
    color: {p['text']};
    border: 1px solid {p['border']};
    border-radius: 8px;
    padding: 4px;
}}
QMenu::item {{ padding: 7px 22px; border-radius: 6px; }}
QMenu::item:selected {{ background-color: {p['accent_soft']}; }}
QMenuBar {{ background: {p['window']}; }}
QMenuBar::item:selected {{ background: {p['accent_soft']}; }}

/* ============================ GROUPBOX ============================ */
QGroupBox {{
    border: 1px solid {p['border']};
    border-radius: 8px;
    margin-top: 14px;
    padding-top: 8px;
    font-weight: 600;
}}
QGroupBox::title {{ subcontrol-origin: margin; left: 12px; padding: 0 6px; color: {p['text_muted']}; }}

/* ======================== APP SHELL ========================= */
/* Left navigation rail */
QFrame#Sidebar {{
    background-color: {p['sidebar']};
    border: none;
    border-right: 1px solid {p['border_subtle']};
}}
QFrame#Sidebar QLabel {{ background: transparent; }}
QScrollArea#SidebarScroll {{
    background-color: {p['sidebar']};
    border: none;
}}
QScrollArea#SidebarScroll > QWidget > QWidget,
QFrame#SidebarNavBody {{ background-color: {p['sidebar']}; }}
QScrollArea#SidebarScroll QScrollBar:vertical {{ width: 7px; margin: 2px 0; }}
QScrollArea#SidebarScroll QScrollBar::handle:vertical {{
    background-color: {p['elevated']};
    border-radius: 3px;
    min-height: 24px;
}}
QLabel#BrandName {{ color: {p['text']}; font-size: 17px; font-weight: 800; letter-spacing: 0.5px; }}
QLabel#BrandTag {{ color: {p['accent']}; font-family: {MONO_FONT}; font-size: 10px; letter-spacing: 1px; }}
QLabel#NavSection {{ color: {p['text_faint']}; font-size: 10px; font-weight: 700; letter-spacing: 1.5px; }}
QLabel#SidebarVersion {{ color: {p['text_faint']}; font-family: {MONO_FONT}; font-size: 11px; }}

/* Nav items */
QPushButton#NavButton {{
    background: transparent;
    color: {p['text_muted']};
    border: none;
    border-radius: 8px;
    padding: 9px 12px;
    text-align: left;
    font-weight: 600;
    font-size: 13px;
}}
QPushButton#NavButton:hover {{ background-color: {p['accent_softer']}; color: {p['text']}; }}
QPushButton#NavButton:pressed {{ background-color: {p['accent_soft']}; }}
QPushButton#NavButton[active="true"] {{
    background-color: {p['accent_soft']};
    color: {p['text']};
}}

/* Main content area + cards */
QWidget#Content {{ background-color: {p['surface']}; }}
QFrame#Card {{
    background-color: {p['card']};
    border: 1px solid {p['border']};
    border-radius: 8px;
}}
QLabel#PageTitle {{ font-size: 20px; font-weight: 800; color: {p['text']}; }}
QLabel#FieldLabel {{ color: {p['text_muted']}; font-size: 12px; font-weight: 600; }}
QFrame#DashboardPill {{
    background-color: {p['input']};
    border: 1px solid {p['border_subtle']};
    border-radius: 6px;
}}
"""


def apply_theme(app) -> None:
    """Apply the global stylesheet to a QApplication."""
    try:
        app.setStyleSheet(stylesheet())
    except Exception:
        pass
