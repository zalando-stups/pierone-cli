import json
import os
from mock import MagicMock
import yaml
from pierone.api import docker_login


def test_docker_login(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    response = MagicMock()
    response.json.return_value = {'access_token': '12377'}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    token = docker_login('https://pierone.example.org', 'services', 'mytok',
                         'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    path = os.path.expanduser('~/.dockercfg')
    with open(path) as fd:
        data = yaml.safe_load(fd)
    assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('https://pierone.example.org')


def test_keep_dockercfg_entries(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    response = MagicMock()
    response.json.return_value = {'access_token': '12377'}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    path = os.path.expanduser('~/.dockercfg')

    key = 'https://old.example.org'
    existing_data = {
        key: {
            'auth': 'abc123',
            'email': 'jdoe@example.org'
        }
    }
    with open(path, 'w') as fd:
        json.dump(existing_data, fd)

    token = docker_login('https://pierone.example.org', 'services', 'mytok',
                         'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    with open(path) as fd:
        data = yaml.safe_load(fd)
    assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('https://pierone.example.org')
    assert existing_data.get(key) == data.get(key)

