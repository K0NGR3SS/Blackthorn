import re
from pathlib import Path

from wafpierce.ui_components import (
    BUTTON_OBJECT_NAMES,
    DISCLOSURE_OBJECT_NAME,
    disclosure_text,
    set_disclosure_state,
    style_button,
    style_disclosure_button,
)
from wafpierce.theme import PALETTE, asset_path, contrast_ratio, stylesheet
from wafpierce.gui import PRIMARY_NAV_ITEMS, WORKBENCH_GROUPS, WORKBENCH_ITEMS


class _Button:
    def setObjectName(self, value):
        self.object_name = value

    def setText(self, value):
        self.text = value

    def setAccessibleName(self, value):
        self.accessible_name = value

    def setToolTip(self, value):
        self.tooltip = value

    def setCheckable(self, value):
        self.checkable = value

    def setChecked(self, value):
        self.checked = value

    def setProperty(self, key, value):
        if not hasattr(self, 'properties'):
            self.properties = {}
        self.properties[key] = value

    def setAccessibleDescription(self, value):
        self.accessible_description = value


def test_button_roles_are_explicit_and_accessible():
    button = style_button(
        _Button(),
        'primary',
        text='Start scan',
        tooltip='Begin testing the queued targets',
    )

    assert button.object_name == 'PrimaryButton'
    assert button.accessible_name == 'Start scan'
    assert button.tooltip.startswith('Begin testing')
    assert set(BUTTON_OBJECT_NAMES) == {
        'primary', 'secondary', 'quiet', 'danger', 'results'
    }


def test_unknown_button_role_fails_fast():
    try:
        style_button(_Button(), 'sparkly')
        assert False, 'expected unknown role to fail'
    except ValueError:
        pass


def test_disclosure_buttons_expose_collapsed_and_expanded_state():
    button = style_disclosure_button(
        _Button(), 'Advanced scan controls', expanded=False
    )

    assert button.object_name == DISCLOSURE_OBJECT_NAME
    assert button.checkable is True
    assert button.checked is False
    assert button.text == '▸ Advanced scan controls'
    assert button.properties['expanded'] == 'false'
    assert button.accessible_name == 'Show Advanced scan controls'
    assert 'collapsed' in button.accessible_description

    set_disclosure_state(button, 'Advanced scan controls', True)
    assert button.text == '▾ Advanced scan controls'
    assert button.properties['expanded'] == 'true'
    assert button.accessible_name == 'Hide Advanced scan controls'
    assert 'expanded' in button.accessible_description
    assert disclosure_text('Options', False) == '▸ Options'


def test_theme_uses_restrained_brass_without_decorative_gradients():
    css = stylesheet()

    assert PALETTE['accent'] == '#c99a45'
    assert 'qlineargradient' not in css
    assert 'QPushButton#QuietButton' in css
    assert 'QPushButton#ResultsButton[hasResults="true"]' in css
    assert 'QPushButton#DisclosureButton' in css
    assert 'QComboBox::drop-down' in css
    assert 'QComboBox::down-arrow' in css
    assert 'chevron-down.svg' in css
    assert 'border-left: 1px solid' in css
    assert 'QTreeWidget::branch:closed:has-children' in css


def test_tree_chevrons_keep_the_mark_small_inside_qt_branch_canvas():
    for name in ('chevron-right-muted.svg', 'chevron-down-muted.svg'):
        svg = Path(asset_path(name)).read_text(encoding='utf-8')
        assert 'viewBox="0 0 24 24"' in svg
        path_data = re.search(r'<path d="([^"]+)"', svg).group(1)
        coordinates = [float(value) for value in re.findall(r'\d+(?:\.\d+)?', path_data)]
        xs, ys = coordinates[::2], coordinates[1::2]
        assert max(xs) - min(xs) <= 8
        assert max(ys) - min(ys) <= 8


def test_core_theme_contrast_meets_wcag_aa():
    assert contrast_ratio(PALETTE['text'], PALETTE['window']) >= 4.5
    assert contrast_ratio(PALETTE['text_muted'], PALETTE['surface']) >= 4.5
    assert contrast_ratio(PALETTE['text_inverse'], PALETTE['accent']) >= 4.5


def test_primary_navigation_tracks_the_six_step_workflow():
    assert [label for _key, label in PRIMARY_NAV_ITEMS] == [
        'Scope & scan', 'Discover', 'Automation', 'Browser', 'Analyze', 'Report'
    ]
    assert len({key for key, _label in PRIMARY_NAV_ITEMS}) == 6
    assert len({key for _label, key in WORKBENCH_ITEMS}) == len(WORKBENCH_ITEMS)


def test_workbench_navigation_is_grouped_and_uses_task_focused_names():
    assert [name for name, _items in WORKBENCH_GROUPS] == [
        'REQUEST TESTING',
        'AUTOMATED TESTING',
        'INTEGRATIONS',
        'OPERATIONS',
    ]
    assert tuple(
        item
        for _name, items in WORKBENCH_GROUPS
        for item in items
    ) == WORKBENCH_ITEMS
    labels = {key: label for label, key in WORKBENCH_ITEMS}
    assert labels['repeater'] == 'Request lab'
    assert labels['fuzzer'] == 'Content discovery'
    assert labels['sqli'] == 'SQLi automation'
    assert labels['tools'] == 'Tool manager'
    assert {'live', 'timeline', 'schedule'}.isdisjoint(labels)
