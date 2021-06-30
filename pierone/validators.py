"""
Functions to validate input
"""

import re

import click

INCIDENT_PATTERN = re.compile(r"^INC-\d+$")

TEAM_PATTERN_STR = r"[a-z][a-z0-9_-]+"
TEAM_PATTERN = re.compile(r"^{}$".format(TEAM_PATTERN_STR))


def validate_team(ctx, param, value):
    if not TEAM_PATTERN.match(value):
        msg = "{!r} doesn't satisfy regular expression pattern {!r}".format(
            value, TEAM_PATTERN_STR
        )
        raise click.BadParameter(msg)
    return value
