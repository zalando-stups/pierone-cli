import json
import os
from unittest.mock import MagicMock, ANY

import yaml
import pytest
from pierone.api import docker_login, docker_login_with_iid, PierOne, get_latest_tag, image_exists
from pierone.exceptions import ArtifactNotFound
from pierone.types import DockerImage

import requests.exceptions


@pytest.fixture(autouse=True)
def valid_pierone_url(monkeypatch):
    response = MagicMock()
    response.text = 'Pier One API'
    monkeypatch.setattr('requests.get', lambda *args, **kw: response)


@pytest.fixture(autouse=True)
def mock_get_token(monkeypatch):
    monkeypatch.setattr('pierone.api.get_token', MagicMock(return_value="12377"))


@pytest.fixture()
def not_found_response():
    not_found_response = MagicMock(status_code=404)
    not_found_response.raise_for_status.side_effect = requests.HTTPError(response=MagicMock(status_code=404))
    not_found_response.return_value = not_found_response
    return not_found_response

@pytest.fixture()
def error_response():
    error_response = MagicMock(status_code=500)
    error_response.raise_for_status.side_effect = requests.HTTPError(response=MagicMock(status_code=500))
    error_response.return_value = error_response
    return error_response


def test_docker_login(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.get_token', MagicMock(return_value='12377'))
    docker_login('https://pierone.example.org', 'services', 'mytok',
                 'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'b2F1dGgyOjEyMzc3',
                'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')

def test_docker_login_with_credsstore(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    path = os.path.expanduser('~/.docker/config.json')
    os.makedirs(os.path.dirname(path))
    with open(path, 'w') as fd:
        json.dump({
            "auths": {
                "https://pierone.stups.zalan.do": {
                    "auth": "xxx",
                    "email": "no-mail-required@example.org"
                }
            },
            "credsStore": "osxkeychain"
        }, fd)
    docker_login('https://pierone.example.org', 'services', 'mytok',
                 'myuser', 'mypass', 'https://token.example.org', use_keyring=False)
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'b2F1dGgyOjEyMzc3',
                'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')
        assert 'credsStore' not in data


def test_docker_login_service_token(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('tokens.get', lambda x: '12377')
    docker_login('https://pierone.example.org', None, 'mytok', 'myuser', 'mypass', 'https://token.example.org')
    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'b2F1dGgyOjEyMzc3',
                'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')


def test_docker_login_with_iid(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser',
                        lambda x: x.replace('~', str(tmpdir)))
    metaservice = MagicMock()
    metaservice.text = '''TG9yZW0gaXBzdW0gZG9sb3Igc2l0IGFtZXQsIGNvbnNldGV0dXIgc2FkaXBzY2luZyBlbGl0ciwg
c2VkIGRpYW0gbm9udW15IGVpcm1vZCB0ZW1wb3IgaW52aWR1bnQgdXQgbGFib3JlIGV0IGRvbG9y
ZSBtYWduYSBhbGlxdXlhbSBlcmF0LCBzZWQgZGlhbSB2b2x1cHR1YS4gQXQgdmVybyBlb3MgZXQg
YWNjdXNhbSBldCBqdXN0byBkdW8gZG9sb3JlcyBldCBlYSByZWJ1bS4gU3RldCBjbGl0YSBrYXNk
IGd1YmVyZ3Jlbiwgbm8gc2VhIHRha2ltYXRhIHNhbmN0dXMgZXN0IExvcmVtIGlwc3VtIGRvbG9y
IHNpdCBhbWV0LiBMb3JlbSBpcHN1bSBkb2xvciBzaXQgYW1ldCwgY29uc2V0ZXR1ciBzYWRpcHNj
aW5nIGVsaXRyLCBzZWQgZGlhbSBub251bXkgZWlybW9kIHRlbXBvciBpbnZpZHVudCB1dCBsYWJv
cmUgZXQgZG9sb3JlIG1hZ25hIGFsaXF1eWFtIGVyYXQsIHNlZCBkaWFtIHZvbHVwdHVhLiBBdCB2
ZXJvIGVvcyBldCBhY2N1c2FtIGV0IGp1c3RvIGR1byBkb2xvcmVzIGV0IGVhIHJlYnVtLiBTdGV0
IGNsaXRhIGthc2QgZ3ViZXJncmVuLCBubyBzZWEgdGFraW1hdGEgc2FuY3R1cyBlc3QgTG9yZW0g
aXBzdW0gZG9sb3Igc2l0IGFtZXQuCg=='''
    monkeypatch.setattr('pierone.api.request',
                        MagicMock(return_value=metaservice))
    docker_login_with_iid('https://pierone.example.org')
    path = os.path.expanduser('~/.docker/config.json')
    with open(path) as fd:
        data = yaml.safe_load(fd)
        assert {'auth': 'aW5zdGFuY2UtaWRlbnRpdHktZG9jdW1lbnQ6VEc5eVpXMGdhWEJ6ZFcwZ1pHOXNiM0lnYzJsMElH'
                'RnRaWFFzSUdOdmJuTmxkR1YwZFhJZ2MyRmthWEJ6WTJsdVp5QmxiR2wwY2l3ZwpjMlZrSUdScFlX'
                'MGdibTl1ZFcxNUlHVnBjbTF2WkNCMFpXMXdiM0lnYVc1MmFXUjFiblFnZFhRZ2JHRmliM0psSUdW'
                'MElHUnZiRzl5ClpTQnRZV2R1WVNCaGJHbHhkWGxoYlNCbGNtRjBMQ0J6WldRZ1pHbGhiU0IyYjJ4'
                'MWNIUjFZUzRnUVhRZ2RtVnlieUJsYjNNZ1pYUWcKWVdOamRYTmhiU0JsZENCcWRYTjBieUJrZFc4'
                'Z1pHOXNiM0psY3lCbGRDQmxZU0J5WldKMWJTNGdVM1JsZENCamJHbDBZU0JyWVhOawpJR2QxWW1W'
                'eVozSmxiaXdnYm04Z2MyVmhJSFJoYTJsdFlYUmhJSE5oYm1OMGRYTWdaWE4wSUV4dmNtVnRJR2x3'
                'YzNWdElHUnZiRzl5CklITnBkQ0JoYldWMExpQk1iM0psYlNCcGNITjFiU0JrYjJ4dmNpQnphWFFn'
                'WVcxbGRDd2dZMjl1YzJWMFpYUjFjaUJ6WVdScGNITmoKYVc1bklHVnNhWFJ5TENCelpXUWdaR2xo'
                'YlNCdWIyNTFiWGtnWldseWJXOWtJSFJsYlhCdmNpQnBiblpwWkhWdWRDQjFkQ0JzWVdKdgpjbVVn'
                'WlhRZ1pHOXNiM0psSUcxaFoyNWhJR0ZzYVhGMWVXRnRJR1Z5WVhRc0lITmxaQ0JrYVdGdElIWnZi'
                'SFZ3ZEhWaExpQkJkQ0IyClpYSnZJR1Z2Y3lCbGRDQmhZMk4xYzJGdElHVjBJR3AxYzNSdklHUjFi'
                'eUJrYjJ4dmNtVnpJR1YwSUdWaElISmxZblZ0TGlCVGRHVjAKSUdOc2FYUmhJR3RoYzJRZ1ozVmla'
                'WEpuY21WdUxDQnVieUJ6WldFZ2RHRnJhVzFoZEdFZ2MyRnVZM1IxY3lCbGMzUWdURzl5WlcwZwph'
                'WEJ6ZFcwZ1pHOXNiM0lnYzJsMElHRnRaWFF1Q2c9PQ==',
                'email': 'no-mail-required@example.org'} == data.get('auths').get('https://pierone.example.org')


def test_keep_dockercfg_entries(monkeypatch, tmpdir):
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.get_token', MagicMock(return_value='12377'))
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
        assert {'auth': 'b2F1dGgyOjEyMzc3',
                'email': 'no-mail-required@example.org'} == data.get('auths', {}).get('https://pierone.example.org')
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
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(image)

    assert data == '0.22'


def test_get_latest_tag_IOException(monkeypatch):
    monkeypatch.setattr('pierone.api.session.request', MagicMock(side_effect=IOError))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    try:
        get_latest_tag(image)
        assert False
    except IOError as e:
        pass  # Expected


def test_get_latest_tag_non_json(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = None
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = get_latest_tag(image)

    assert data is None


def test_image_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    data = image_exists(image)

    assert data is True


def test_image_exists_IOException(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.request', MagicMock(side_effect=IOError(), return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='0.2')
    try:
        image_exists(image)
        assert False
    except IOError as e:
        pass  # Expected


def test_image_exists_but_other_version(monkeypatch):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {'0.1': 'chksum',
                                  '0.2': 'chksum'}
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(image)

    assert data is False


def test_image_not_exists(monkeypatch):
    response = MagicMock()
    response.status_code = 404
    response.json.return_value = {}
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag='latest')
    data = image_exists(image, 'tok123')

    assert data is False


def test_get_image_tags(not_found_response, error_response):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = [{'created': '2015-06-01T14:12:03.276+0000',
                                   'created_by': 'foobar',
                                   'name': '0.17'}]
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)
    api = PierOne('registry')
    api.session.request = MagicMock(return_value=response)
    image_tags = api.get_image_tags(image)
    tag = image_tags[0]

    assert tag['team'] == 'foo'
    assert tag['artifact'] == 'bar'
    assert tag['tag'] == '0.17'
    assert tag['created_by'] == 'foobar'

    api.session.request = MagicMock(return_value=not_found_response)
    with pytest.raises(ArtifactNotFound):
        api.get_image_tags(image)

    api.session.request = MagicMock(return_value=error_response)
    with pytest.raises(requests.HTTPError):
        api.get_image_tags(image)


def test_get_tag_info(not_found_response, error_response):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "artifact": "test",
        "created": "2018-08-27T13:15:28.968Z",
        "created_by": "credprov-cdp-controller-proxy_pierone-token",
        "image": "sha256:2ee6f0b4d7313903fdf3d326dacfc4c711da339ab3a12ccdd78e18e17daa6eb1",
        "name": "pr-1-1",
        "status": "test_status",
        "status_reason_details": "test_status",
        "status_reason_summary": "test_status",
        "status_received_at": "2018-08-27T13:15:28.968Z"
    }

    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)
    api = PierOne('registry')
    api.session.request = MagicMock(return_value=response)
    details = api.get_tag_info(image)

    assert details['artifact'] == 'test'
    assert details['created_by'] == '[CDP]'

    api.session.request = MagicMock(return_value=not_found_response)
    with pytest.raises(ArtifactNotFound):
        api.get_tag_info(image)

    api.session.request = MagicMock(return_value=error_response)
    with pytest.raises(requests.HTTPError):
        api.get_tag_info(image)


def test_get_scm_source(not_found_response, error_response):
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = {
        "author": "ckent",
        "created": "2038-11-06T14:58:58.792Z",
        "revision": "6e6bb8c5a95ebb8b447b5516c292467d098c2a758",
        "status": "",
        "url": "git:git@github.bus.zalan.do:continuous-delivery/cdp-builder.git",
        "valid": True
    }


    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)
    api = PierOne('registry')
    api.session.request = MagicMock(return_value=response)
    details = api.get_scm_source(image)

    assert details['author'] == 'ckent'
    assert details['valid'] == True

    api.session.request = MagicMock(return_value=not_found_response)
    with pytest.raises(ArtifactNotFound):
        api.get_scm_source(image)

    api.session.request = MagicMock(return_value=error_response)
    with pytest.raises(requests.HTTPError):
        api.get_scm_source(image)

def test_get_artifacts():
    response = MagicMock()
    response.status_code = 200
    response.json.return_value = ["pierone", "piertwo", "pierthree"]

    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)
    api = PierOne('registry')
    api.session.request = MagicMock(return_value=response)
    assert api.get_artifacts(image) == ["pierone", "piertwo", "pierthree"]


def test_mark_production_ready(not_found_response, error_response):
    image = DockerImage(registry='registry', team='foo', artifact='bar', tag=None)
    api = PierOne('registry')
    api.session.post = MagicMock()
    api.mark_production_ready(image, "INC-42")
    api.session.post.assert_called_once_with(
        'https://registry/teams/foo/artifacts/bar/tags/None/production-ready',
        json={'incident_id': 'INC-42'}
    )

    api.session.post = MagicMock(return_value=not_found_response)
    with pytest.raises(ArtifactNotFound):
        api.mark_production_ready(image, "INC-42")

    api.session.post = MagicMock(return_value=error_response)
    with pytest.raises(requests.HTTPError):
        api.mark_production_ready(image, "INC-42")