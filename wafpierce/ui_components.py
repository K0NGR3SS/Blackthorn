"""Small GUI primitives shared across Blackthorn pages.

The helpers deliberately avoid importing Qt so their role semantics remain
testable in headless environments.
"""

from __future__ import annotations


BUTTON_OBJECT_NAMES = {
    'primary': 'PrimaryButton',
    'secondary': 'SecondaryButton',
    'quiet': 'QuietButton',
    'danger': 'DangerButton',
    'results': 'ResultsButton',
}

DISCLOSURE_OBJECT_NAME = 'DisclosureButton'
DISCLOSURE_CLOSED_GLYPH = '▸'
DISCLOSURE_OPEN_GLYPH = '▾'


def style_button(
    button,
    role: str = 'secondary',
    *,
    text: str | None = None,
    accessible_name: str | None = None,
    tooltip: str | None = None,
):
    """Apply one of the product's restrained button roles to a Qt-like button."""
    if role not in BUTTON_OBJECT_NAMES:
        raise ValueError(f'Unknown button role: {role}')
    button.setObjectName(BUTTON_OBJECT_NAMES[role])
    if text is not None:
        button.setText(text)
    if accessible_name or text:
        button.setAccessibleName(accessible_name or text)
    if tooltip:
        button.setToolTip(tooltip)
    return button


def disclosure_text(label: str, expanded: bool) -> str:
    """Return a consistent visible label for expandable sections."""
    glyph = DISCLOSURE_OPEN_GLYPH if expanded else DISCLOSURE_CLOSED_GLYPH
    return f'{glyph} {str(label).strip()}'


def set_disclosure_state(button, label: str, expanded: bool):
    """Update the visible and accessible state of a disclosure button."""
    expanded = bool(expanded)
    button.setProperty('expanded', 'true' if expanded else 'false')
    button.setText(disclosure_text(label, expanded))
    action = 'Hide' if expanded else 'Show'
    state = 'expanded' if expanded else 'collapsed'
    button.setAccessibleName(f'{action} {label}')
    button.setAccessibleDescription(
        f'Expandable section, currently {state}.'
    )
    button.setToolTip(f'{action} {label.lower()}')
    return button


def style_disclosure_button(button, label: str, *, expanded: bool = False):
    """Make a button unambiguously control an expandable section."""
    button.setObjectName(DISCLOSURE_OBJECT_NAME)
    button.setCheckable(True)
    button.setChecked(bool(expanded))
    return set_disclosure_state(button, label, expanded)
