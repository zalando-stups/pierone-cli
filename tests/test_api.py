import json
import os
from unittest.mock import MagicMock, ANY

import yaml
from pierone.api import (DockerImage, docker_login, get_image_tag,
                         get_image_tags, get_latest_tag, image_exists)

import requests.exceptions


def test_docker_login(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'access_token': '12377'}
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    docker_login('https://pierone.example.org', 'services', 'mytok',
                 'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')


def test_docker_login_service_token(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('tokens.get', lambda x: '12377')
    docker_login('https://pierone.example.org', None, 'mytok', 'myuser', 'mypass', 'https://token.example.org')
    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'b2F1dGgyOjEyMzc3', 'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')


@pytest.mark.parametrize(
    "status_code",
    [
        (400),
        (404),
        (500),
        (502),
        (700),  # nonsense status code that should be handled all the same
    ])
def test_docker_login_error(monkeypatch, status_code):
    mock_get = MagicMock()
    response = MagicMock()
    response.status_code = status_code
    mock_get.side_effect = requests.exceptions.HTTPError(response=response)
    monkeypatch.setattr('tokens.get', mock_get)

    mock_action = MagicMock()
    mock_action.side_effect = SystemExit(1)
    monkeypatch.setattr('pierone.api.Action.fatal_error', mock_action)
    with pytest.raises(SystemExit):
        docker_login('https://pierone.example.org', None, 'mytok', 'myuser', 'mypass', 'https://token.example.org')
    mock_action.assert_called_once_with(ANY)
    call = mock_action.call_args[0]
    argument = call[0]  # type: str
    assert argument.startswith("Authentication Failed")
    assert str(status_code) in argument
    if 400 <= status_code < 500:
        assert "Client Error" in argument
    if 500 <= status_code < 600:
        assert "Server Error" in argument


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

    docker_login('https://pierone.example.org', 'services', 'mytok',
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
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(image)

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
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(image)

    assert data is None


def test_get_latest_tag_non_json(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = None
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(image)

    assert data is None


def test_image_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    data = image_exists(image)

    assert data is True


def test_image_exists_IOException(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(side_effect=Exception(IOError), return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    data = image_exists(image)

    assert data is False


def test_image_exists_but_other_version(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(image)

    assert data is False


def test_image_not_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 404
    response.json.return_value = {}
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(image, 'tok123')

    assert data is False


def test_get_image_tags(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [{'created': '2015-06-01T14:12:03.276+0000',
                                   'created_by': 'foobar',
                                   'name': '0.17'}]
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)

    image_tags = get_image_tags(image)
    tag = image_tags[0]

    assert tag['team'] == 'foo'
    assert tag['artifact'] == 'bar'
    assert tag['tag'] == '0.17'
    assert tag['created_by'] == 'foobar'
    assert tag['severity_fix_available'] == 'TOO_OLD'
    assert tag['severity_no_fix_available'] == 'TOO_OLD'


def test_get_image_tag(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [{'created': '2015-06-01T14:12:03.276+0000',
                                   'created_by': 'foobar',
                                   'name': '0.17'},
                                  {'created': '2015-06-11T16:13:29.152+0000',
                                   'created_by': 'foobar',
                                   'name': '0.22'}]
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.22')

    tag = get_image_tag(image)

    assert tag['team'] == 'foo'
    assert tag['artifact'] == 'bar'
    assert tag['tag'] == '0.22'
    assert tag['created_by'] == 'foobar'
    assert tag['severity_fix_available'] == 'TOO_OLD'
    assert tag['severity_no_fix_available'] == 'TOO_OLD'


def test_get_image_tag_that_does_not_exist(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [{'created': '2015-06-01T14:12:03.276+0000',
                                   'created_by': 'foobar',
                                   'name': '0.17'}]
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='1.22')

    assert get_image_tag(image) is None
