import json
import os
import re
from unittest.mock import MagicMock

import pytest
from click.testing import CliRunner
from pierone.cli import cli
from requests import RequestException, HTTPError


@pytest.fixture(autouse=True)
def valid_pierone_url(monkeypatch):
    response = MagicMock()
    response.text = 'Pier One API'
    monkeypatch.setattr('requests.get', lambda *args, **kw: response)


@pytest.fixture()
def mock_pierone_api(monkeypatch):
    api = MagicMock(name="PierOne")
    api.return_value = api

    api.get_artifacts = MagicMock(return_value=['app1', 'app2'])

    tags = [
        {
            'tag': '1.0',
            'team': 'foo',
            'artifact': 'app1',
            'severity_fix_available': 'TOO_OLD',
            'severity_no_fix_available': 'TOO_OLD',
            'created_by': 'myuser',
            'created': '2015-08-01T08:14:59.432Z'
        },
        {
            'tag': '1.1',
            'team': 'foo',
            'artifact': 'app1',
            'severity_fix_available': 'NO_CVES_FOUND',
            'severity_no_fix_available': 'NO_CVES_FOUND',
            'created_by': 'myuser',
            'created': '2015-08-02T08:14:59.432Z'
        },
        {
            'tag': '2.0',
            'team': 'foo',
            'artifact': 'app1',
            'severity_fix_available': 'NO_CVES_FOUND',
            'severity_no_fix_available': 'NO_CVES_FOUND',
            'created_by': 'myuser',
            'created': '2016-06-20T08:14:59.432Z'
        },
    ]
    api.get_image_tags = MagicMock(return_value=tags)

    api.get_scm_source = MagicMock(return_value={'url': 'git:somerepo', 'revision': 'myrev123'})

    monkeypatch.setattr('pierone.api.PierOne', api)
    monkeypatch.setattr('pierone.cli.PierOne', api)
    return api

def test_version(monkeypatch):
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)
        assert 'Pier One CLI' in result.output


def test_login(monkeypatch, tmpdir):
    runner = CliRunner()

    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('shutil.which', lambda x: x)

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        assert 'Storing Docker client configuration' in result.output
        with open(os.path.join(str(tmpdir), '.docker/config.json')) as fd:
            data = json.load(fd)
        assert data['auths'] == {}
        assert data['credHelpers'] == {'pieroneurl': 'pierone'}


def test_login_update_config(monkeypatch, tmpdir):
    runner = CliRunner()

    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('shutil.which', lambda x: x)

    with runner.isolated_filesystem():
        os.makedirs(os.path.join(str(tmpdir), ".docker"))
        with open(os.path.join(str(tmpdir), '.docker/config.json'), 'w') as fd:
            fd.write(json.dumps({
                'auths': {
                    'https://pieroneurl': {
                        "auth": "abcd"
                    }
                }
            }))

        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        assert 'Storing Docker client configuration' in result.output
        with open(os.path.join(str(tmpdir), '.docker/config.json')) as fd:
            data = json.load(fd)
        assert data['auths'] == {}
        assert data['credHelpers'] == {'pieroneurl': 'pierone'}


def test_login_given_url_option(monkeypatch, tmpdir):
    runner = CliRunner()

    config = {}

    def store(data, section):
        config.update(**data)

    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})
    monkeypatch.setattr('stups_cli.config.store_config', store)
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('shutil.which', lambda x: x)

    with runner.isolated_filesystem():
        runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        assert config == {'url': 'https://pieroneurl'}
        runner.invoke(cli, ['login', '--url', 'someotherregistry'], catch_exceptions=False)
        with open(os.path.join(str(tmpdir), '.docker/config.json')) as fd:
            data = json.load(fd)
        assert data['auths'] == {}
        assert data['credHelpers'] == {
            'pieroneurl': 'pierone',
            'someotherregistry': 'pierone',
        }


def test_scm_source(monkeypatch, tmpdir, mock_pierone_api):

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.cli.get_tags', MagicMock(return_value=[{'name': 'myart'}]))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['scm-source', 'myteam', 'myart', '1.0'], catch_exceptions=False)
        assert 'myrev123' in result.output
        assert 'git:somerepo' in result.output

    # no tags found
    monkeypatch.setattr('pierone.cli.get_tags', MagicMock(return_value=[]))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['scm-source', 'myteam', 'myart', '1.0'], catch_exceptions=False)
        assert 'Artifact or Team does not exist!' in result.output
        assert result.exit_code > 0


def test_image(monkeypatch, tmpdir):
    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))

    response = MagicMock()
    response.json.return_value = [{'name': '1.0', 'team': 'stups', 'artifact': 'kio'}]
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
        assert result.exit_code == 0
        assert 'kio' in result.output
        assert 'stups' in result.output
        assert '1.0' in result.output

    monkeypatch.setattr('pierone.api.session.request', MagicMock(side_effect=Exception("Some unknown error")))
    with runner.isolated_filesystem():
        try:
            runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
            assert False
        except Exception as e:
           assert e.args[0] == "Some unknown error"

    response404 = MagicMock()
    response404.status_code = 404
    monkeypatch.setattr('pierone.api.session.request', MagicMock(side_effect=HTTPError(response=response404)))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
        # assert result.exit_code != 0
        assert "not found" in result.output

    response412 = MagicMock()
    response412.status_code = 412
    monkeypatch.setattr('pierone.api.session.request', MagicMock(side_effect=HTTPError(response=response412)))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
        # assert result.exit_code != 0
        assert "more than one" in result.output


def test_tags(monkeypatch, tmpdir, mock_pierone_api):
    response = MagicMock()
    response.json.return_value = [
        # Former pierone payload
        {
            'name': '1.0',
            'created_by': 'myuser',
            'created': '2015-08-20T08:14:59.432Z'
        },
        # New pierone payload with clair but no information about CVEs -- old images
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": None,
            "severity_fix_available": None,
            "severity_no_fix_available": None
        },
        # New pierone payload with clair but no information about CVEs -- still processing
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "clair_details": "https://clair.example.org/foo/",
            "severity_fix_available": None,
            "severity_no_fix_available": None
        },
        # New pierone payload with clair but could not figure out
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "clair_details": "https://clair.example.org/foo/",
            "severity_fix_available": "clair:CouldntFigureOut",
            "severity_no_fix_available": "clair:CouldntFigureOut"
        },
        # New pierone payload with clair with no CVEs found
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "clair_details": "https://clair.example.org/foo/",
            "severity_fix_available": "clair:NoCVEsFound",
            "severity_no_fix_available": "clair:NoCVEsFound"
        },
        # New pierone payload with clair input and info about CVEs
        {
            "name": "1.2",
            "created": "2016-05-23T13:29:17.753Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "clair_details": "https://clair.example.org/foo/",
            "severity_fix_available": "High",
            "severity_no_fix_available": "Medium"
        },
        # New pierone payload with info about image trusted status
        {
            "name": "1.2",
            "created": "2016-05-23T13:29:17.753Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "clair_details": "https://clair.example.org/foo/",
            "severity_fix_available": "High",
            "severity_no_fix_available": "Medium",
            "trusted": "true"
        }
    ]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['tags', 'myteam', 'myart'], catch_exceptions=False)
        assert '1.0' in result.output

def test_tags_versions_limit(monkeypatch, tmpdir, mock_pierone_api):
    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['tags', 'myteam', '--limit=1'], catch_exceptions=False)
        assert '1.0' not in result.output
        assert '1.1' not in result.output
        assert '2.0' in result.output

def test_latest(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = [
            {'name': '1.0', 'created_by': 'myuser', 'created': '2015-08-20T08:14:59.432Z'},
            # 1.1 was pushed BEFORE 1.0, i.e. latest tag is actually "1.0"!
            {'name': '1.1', 'created_by': 'myuser', 'created': '2015-08-20T08:11:59.432Z'}]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'https://pierone.example.org'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['latest', 'myteam', 'myart'], catch_exceptions=False)
        assert '1.0' == result.output.rstrip()


def test_latest_not_found(monkeypatch, tmpdir):
    response = MagicMock()
    response.raise_for_status.side_effect = Exception('FAIL')
    response.status_code = 404
    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'https://pierone.example.org'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.api.session.request', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['latest', 'myteam', 'myart'], catch_exceptions=False)
        assert 'Error: Latest tag not found' == result.output.rstrip()
        assert result.exit_code == 1


def test_url_without_scheme(monkeypatch, tmpdir, mock_pierone_api):

    runner = CliRunner()
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['artifacts', 'myteam', '--url', 'example.org'], catch_exceptions=False)
        assert 'myteam app2' in result.output
