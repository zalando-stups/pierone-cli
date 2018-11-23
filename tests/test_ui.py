from pierone.ui import markdown_2_cli, format_full_image_name
from pierone.api import DockerImage


def test_format_full_image_name():
    expected = "\x1b[4mpierone.example.org/team/image:tag\x1b[0m"
    image_with_http = DockerImage("https://pierone.example.org", "team", "image", "tag")
    image_simple =DockerImage("pierone.example.org", "team", "image", "tag")
    assert format_full_image_name(image_with_http) == expected
    assert format_full_image_name(image_simple) == expected


def test_unformatted():
    assert markdown_2_cli("abc\ndef") == ["abc", "def"]


def test_h1():
    assert markdown_2_cli("# abc") == ["\x1b[1m\x1b[4mabc\x1b[0m"]


def test_h2():
    assert markdown_2_cli("## abc") == ["\x1b[1mabc\x1b[0m"]


def test_checkbox():
    assert markdown_2_cli("- [x] Checked\n- [ ] Unchecked") == ["☑ Checked", "☐ Unchecked"]
