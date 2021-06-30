import click
import string

from hypothesis import given
from hypothesis.strategies import text, lists, integers
import pytest

from pierone.validators import validate_team

@given(
    lower_case_letter=text(string.ascii_lowercase, min_size=1, max_size=1),
    upper_case_letters=text(string.ascii_uppercase, min_size=1),
    lower_case_letters=text(string.ascii_lowercase, min_size=10),
    digits=text(string.digits, min_size=10),
)
def test_validate_team(lower_case_letter, upper_case_letters, lower_case_letters, digits):
    assert validate_team(None, None, lower_case_letters) == lower_case_letters
    assert validate_team(None, None, lower_case_letter + digits) == lower_case_letter + digits

    with pytest.raises(click.BadParameter):
        # Team names need at least two chars
        validate_team(None, None, lower_case_letter)

    with pytest.raises(click.BadParameter):
        # Team names cannot start with a digit
        validate_team(None, None, digits + lower_case_letter)

    with pytest.raises(click.BadParameter):
        # Team names cannot contain upper case chars
        validate_team(None, None, upper_case_letters)
