import json
import os
from unittest.mock import MagicMock
import yaml
from pierone.api import docker_login, DockerImage, get_latest_tag, Unauthorized, image_exists
import pytest


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

    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
    assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')


def test_keep_dockercfg_entries(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'access_token': '12377'}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    path = os.path.expanduser('~/.docker/config.json')

    key = 'https://old.example.org'
    existing_data = {
        key: {
            'auth': 'abc123',
            'email': 'jdoe@example.org'
        }
    }
    os.makedirs(os.path.dirname(path))
    with open(path, 'w') as fd:
        json.dump(existing_data, fd)

    token = docker_login('https://pierone.example.org', 'services', 'mytok',
                         'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    with open(path) as fd:
        data = yaml.safe_load(fd)
    assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('auths', {}).get('https://pierone.example.org')
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
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(token_name, image)

    assert data == '0.22'


def test_get_latest_tag_IOException(monkeypatch):
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
    monkeypatch.setattr('pierone.api.session.get', MagicMock(side_effect=Exception(IOError), return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(token_name, image)

    assert data is None


def test_get_latest_tag_non_json(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = None
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(token_name, image)

    assert data is None


def test_unauthorized(monkeypatch):
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value=None))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    with pytest.raises(Unauthorized) as excinfo:
        get_latest_tag(token_name, image)
    assert 'Unauthorized: token missing or invalid' in str(excinfo.value)

    with pytest.raises(Unauthorized) as excinfo:
        image_exists(token_name, image)
    assert 'Unauthorized: token missing or invalid' in str(excinfo.value)


def test_image_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    data = image_exists(token_name, image)

    assert data is True


def test_image_exists_IOException(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(side_effect=Exception(IOError), return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    data = image_exists(token_name, image)

    assert data is False


def test_image_exists_but_other_version(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(token_name, image)

    assert data is False


def test_image_not_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 404
    response.json.return_value = {}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    token_name = 'dummy'
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(token_name, image)

    assert data is False
