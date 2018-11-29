"""
Functions to display things nicely.
"""

import collections
import shutil

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


def markdown_2_cli(original: str) -> str:
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
    return '\n'.join(result)


class DetailsBox:

    def __init__(self):
        self._max_key_size = 1
        self._sections = collections.OrderedDict()
        self._line_size, _ = shutil.get_terminal_size((100, 42))

    def _print_header(self, title):
        click.secho(title.ljust(self._line_size), reverse=True)

    def _print_key_value(self, key: str, value):
        click.echo("{key:<{key_size}} ┃ {value}".format(
            key=key, value=value, key_size=self._max_key_size)
        )

    def set(self, section: str, key: str, value):
        if section not in self._sections:
            self._sections[section] = collections.OrderedDict()
        self._sections[section][key] = value
        self._max_key_size = max(self._max_key_size, len(key))

    def render(self):
        for section, entries in self._sections.items():
            self._print_header(section)
            for key, value in entries.items():
                lines = str(value).splitlines() or [""]  # make sure we always have 1 "line"
                self._print_key_value(key, lines.pop(0))
                for line in lines:
                    self._print_key_value("", line)
