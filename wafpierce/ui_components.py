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
