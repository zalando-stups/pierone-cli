from pierone.utils import get_registry

def test_get_registry():
    assert get_registry("https://pierone.example.org") == "pierone.example.org"
    assert get_registry("pierone.example.org") == "pierone.example.org"