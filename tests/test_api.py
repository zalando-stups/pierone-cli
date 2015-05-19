import os
from mock import MagicMock
import yaml
from pierone.api import docker_login


def test_docker_login(monkeypatch):
    response = MagicMock()
    response.json.return_value = {'access_token': '12377'}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    token = docker_login('https://pierone.example.org', 'services', 'mytok',
                         'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    path = os.path.expanduser('~/.dockercfg')
    with open(path) as fd:
        data = yaml.safe_load(fd)
    assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('https://pierone.example.org')


