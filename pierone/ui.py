"""
Functions to display things nicely.
"""

import click
from .utils import get_registry


def format_full_image_name(url: str, team: str, artifact: str, tag: str) -> str:
    """
    Returns a formatted string with the full image name.
    """
    registry = get_registry(url)
    image = click.style("{}/{}/{}:{}".format(registry, team, artifact, tag), underline=True)
    return image


def markdown_2_cli(original: str) -> list:
    """
    Gets a markdown string and returns a list of formatted lines using ANSI styles and unicode.
    """
    result = []
    for line in original.splitlines():
        if line.startswith('# '):
            result.append(click.style(line[2:], bold=True, underline=True))
        elif line.startswith('## '):
            result.append(click.style(line[3:], bold=True))
        elif line.startswith('- [x]'):
            result.append('☑ ' + line[6:])
        elif line.startswith('- [ ]'):
            result.append('☐ ' + line[6:])
        else:
            result.append(line.replace('Gandalf', '🧙 Gandalf'))
    return result
