from wafpierce.ui_components import BUTTON_OBJECT_NAMES, style_button
from wafpierce.theme import PALETTE, contrast_ratio, stylesheet
from wafpierce.gui import PRIMARY_NAV_ITEMS, WORKBENCH_ITEMS


class _Button:
    def setObjectName(self, value):
        self.object_name = value

    def setText(self, value):
        self.text = value

    def setAccessibleName(self, value):
        self.accessible_name = value

    def setToolTip(self, value):
        self.tooltip = value


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


def test_theme_uses_restrained_brass_without_decorative_gradients():
    css = stylesheet()

    assert PALETTE['accent'] == '#c99a45'
    assert 'qlineargradient' not in css
    assert 'QPushButton#QuietButton' in css
    assert 'QPushButton#ResultsButton[hasResults="true"]' in css


def test_core_theme_contrast_meets_wcag_aa():
    assert contrast_ratio(PALETTE['text'], PALETTE['window']) >= 4.5
    assert contrast_ratio(PALETTE['text_muted'], PALETTE['surface']) >= 4.5
    assert contrast_ratio(PALETTE['text_inverse'], PALETTE['accent']) >= 4.5


def test_primary_navigation_tracks_the_five_step_workflow():
    assert [label for _key, label in PRIMARY_NAV_ITEMS] == [
        'Scope & scan', 'Discover', 'Test plan', 'Analyze', 'Report'
    ]
    assert len({key for key, _label in PRIMARY_NAV_ITEMS}) == 5
    assert len({key for _label, key in WORKBENCH_ITEMS}) == len(WORKBENCH_ITEMS)
