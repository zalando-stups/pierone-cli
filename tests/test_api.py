import json
import os
from unittest.mock import MagicMock
import yaml
from pierone.api import docker_login, DockerImage, get_latest_tag


def test_docker_login(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    response = MagicMock()
    response.status_code = 200
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
    response.status_code = 200
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


def test_get_latest_tag(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [{'created': '2015-06-01T14:12:03.276+0000',
                                   'created_by': 'foobar',
                                   'name': '0.17'},
                                  {'created': '2015-06-11T15:27:34.672+0000',
                                   'created_by': 'foobar',
                                   'name': '0.18'},
                                  {'created': '2015-06-11T16:13:29.152+0000',
                                   'created_by': 'foobar',
                                   'name': '0.22'},
                                  {'created': '2015-06-11T15:36:55.033+0000',
                                   'created_by': 'foobar',
                                   'name': '0.19'},
                                  {'created': '2015-06-11T15:45:50.225+0000',
                                   'created_by': 'foobar',
                                   'name': '0.20'},
                                  {'created': '2015-06-11T15:51:49.307+0000',
                                   'created_by': 'foobar',
                                   'name': '0.21'}]
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(token_name, image)

    assert data == '0.22'
