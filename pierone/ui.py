"""
Functions to display things nicely.
"""

import click
from .utils import get_registry
from .types import DockerImage


def format_full_image_name(image: DockerImage) -> str:
    """
    Returns a formatted string with the full image name.
    """
    registry = get_registry(image.registry)  # make sure registry doesn't have http
    full_name = "/".join((registry, image.team, image.artifact))
    if image.tag:
        full_name += ":{}".format(image.tag)

    image = click.style(full_name, underline=True)
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
