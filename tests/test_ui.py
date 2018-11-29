import string

from hypothesis import given, assume
from hypothesis.strategies import text

from pierone.ui import markdown_2_cli, format_full_image_name
from pierone.api import DockerImage


def test_format_full_image_name():
    expected = "\x1b[4mpierone.example.org/team/image:tag\x1b[0m"
    image_with_http = DockerImage("https://pierone.example.org", "team", "image", "tag")
    image_simple =DockerImage("pierone.example.org", "team", "image", "tag")
    assert format_full_image_name(image_with_http) == expected
    assert format_full_image_name(image_simple) == expected


def test_format_full_image_name_without_tag():
    expected = "\x1b[4mpierone.example.org/team/image\x1b[0m"
    image_with_http = DockerImage("https://pierone.example.org", "team", "image", None)
    image_simple =DockerImage("pierone.example.org", "team", "image", None)
    assert format_full_image_name(image_with_http) == expected
    assert format_full_image_name(image_simple) == expected

@given(original=text(string.ascii_letters+string.digits+'/n', min_size=10))
def test_unformatted(original: str):
    assert markdown_2_cli(original) == original

@given(original=text(string.ascii_letters+string.digits+'/n', min_size=10))
def test_h1(original: str):
    BOLD_UNDERLINED = "\x1b[1m\x1b[4m"
    RESET = "\x1b[0m"
    markdown = "# " + original
    formatted = markdown_2_cli(markdown)
    lines = formatted.splitlines()
    h1 = lines.pop(0)
    first_original_line = original.splitlines()[0]

    assert h1.startswith(BOLD_UNDERLINED)
    assert h1.endswith(RESET)
    assert first_original_line in h1
    for line in lines:
        assert not line.startswith(BOLD_UNDERLINED)

@given(original=text(string.ascii_letters+string.digits+'/n', min_size=10))
def test_h2(original):
    BOLD_UNDERLINED = "\x1b[1m\x1b[4m"
    BOLD = "\x1b[1m"
    RESET = "\x1b[0m"
    markdown = "## " + original
    formatted = markdown_2_cli(markdown)
    lines = formatted.splitlines()
    h2 = lines.pop(0)
    first_original_line = original.splitlines()[0]

    assert h2.startswith(BOLD)
    assert not h2.startswith(BOLD_UNDERLINED)
    assert h2.endswith(RESET)
    assert first_original_line in h2
    for line in lines:
        assert not line.startswith(BOLD_UNDERLINED)


def test_checkbox():
    assert markdown_2_cli("- [x] Checked\n- [ ] Unchecked") == "☑ Checked\n☐ Unchecked"
