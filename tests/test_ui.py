from pierone.ui import markdown_2_cli, format_full_image_name


def test_format_full_image_name():
    expected = "\x1b[4mpierone.example.org/team/image:tag\x1b[0m"
    assert format_full_image_name("https://pierone.example.org", "team", "image", "tag") == expected
    assert format_full_image_name("pierone.example.org", "team", "image", "tag") == expected

def test_unformatted():
    assert markdown_2_cli("abc\ndef") == ["abc", "def"]

def test_h1():
    assert markdown_2_cli("# abc") == ["\x1b[1m\x1b[4mabc\x1b[0m"]

def test_h2():
    assert markdown_2_cli("## abc") == ["\x1b[1mabc\x1b[0m"]


def test_checkbox():
    assert markdown_2_cli("- [x] Checked\n- [ ] Unchecked") == ["☑ Checked", "☐ Unchecked"]
