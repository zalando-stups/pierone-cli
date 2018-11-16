"""
Minimal Markdown to ANSI converter to display Compliance reports
"""

import click


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
