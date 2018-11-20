import click
import string

from hypothesis import given
from hypothesis.strategies import text, lists, integers, one_of, deferred
import pytest

from pierone.validators import validate_incident_id, validate_team

@given(
    valid_incident_number=integers(0, 100000),
    invalid_incident_id=text(string.ascii_letters)
)
def test_validate_incident_id(valid_incident_number, invalid_incident_id):
    valid_incident_id = "INC-{}".format(valid_incident_number)
    assert validate_incident_id(None, None, valid_incident_id) == valid_incident_id
    with pytest.raises(click.BadParameter):
        validate_incident_id(None, None, invalid_incident_id)

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