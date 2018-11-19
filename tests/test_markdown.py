from pierone.markdown import markdown_2_cli

def test_unformatted():
    assert markdown_2_cli("abc\ndef") == ["abc", "def"]

def test_h1():
    assert markdown_2_cli("# abc") == ["\x1b[1m\x1b[4mabc\x1b[0m"]

def test_h2():
    assert markdown_2_cli("## abc") == ["\x1b[1mabc\x1b[0m"]


def test_checkbox():
    assert markdown_2_cli("- [x] Checked\n- [ ] Unchecked") == ["☑ Checked", "☐ Unchecked"]
