"""
Functions to validate input
"""

import re

import click

INCIDENT_PATTERN = re.compile(r'^INC-\d+$')

TEAM_PATTERN_STR = r'[a-z][a-z0-9-]+'
TEAM_PATTERN = re.compile(r'^{}$'.format(TEAM_PATTERN_STR))


def validate_incident_id(ctx, param, value):
    if not INCIDENT_PATTERN.match(value):
        msg = "{!r} doesn't follow the pattern INC-0000.".format(value)
        raise click.BadParameter(msg)
    return value


def validate_team(ctx, param, value):
    if not TEAM_PATTERN.match(value):
        msg = "{!r} doesn't satisfy regular expression pattern {!r}".format(value, TEAM_PATTERN_STR)
        raise click.BadParameter(msg)
    return value