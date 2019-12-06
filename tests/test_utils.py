import os

from hypothesis import given, assume
from hypothesis.strategies import text, lists, integers
from unittest.mock import patch

from pierone.utils import KNOWN_USERS, get_registry, get_user_friendly_user_name, get_docker_config_path

def test_get_registry():
    assert get_registry("https://pierone.example.org") == "pierone.example.org"
    assert get_registry("pierone.example.org") == "pierone.example.org"

@given(random_user_name=text(min_size=10))
def test_get_user_friendly_user_name_random(random_user_name):
    assume(random_user_name not in KNOWN_USERS)
    assert get_user_friendly_user_name(random_user_name) == random_user_name

def test_get_user_friendly_user_name_cdp():
    CDP_USER_NAMES = [
        "credprov-cdp-controller-proxy-credentials-cdp_proxy-token",
        "credprov-cdp-controller-proxy_pierone-token"
    ]
    for user_name in CDP_USER_NAMES:
        assert get_user_friendly_user_name(user_name) ==  "[CDP]"

def test_get_docker_config_path_default():
    assert get_docker_config_path('config.json') == os.path.expanduser('~/.docker/config.json')

@patch.dict('os.environ', {'DOCKER_CONFIG': '/etc/docker'})
def test_get_docker_config_path_environment_override():
    assert get_docker_config_path('config.json') == '/etc/docker/config.json'
