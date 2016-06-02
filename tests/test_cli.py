import json
import os
import re
from unittest.mock import MagicMock

from click.testing import CliRunner
from pierone.cli import cli


def test_version(monkeypatch):
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)
        assert 'Pier One CLI' in result.output


def test_login(monkeypatch, tmpdir):
    response = MagicMock()

    runner = CliRunner()

    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})
    monkeypatch.setattr('pierone.api.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        with open(os.path.join(str(tmpdir), '.docker/config.json')) as fd:
            data = json.load(fd)
        assert data['auths']['https://pieroneurl']['auth'] == 'b2F1dGgyOnRvazEyMw=='
        assert 'Storing Docker client configuration' in result.output
        assert result.output.rstrip().endswith('OK')


def test_login_arg_user(monkeypatch, tmpdir):
    arg_user = 'arg_user'
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock_docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
        assert arg_user == user

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    monkeypatch.setattr('pierone.cli.docker_login', mock_docker_login)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['login', '-U', arg_user], catch_exceptions=False, input='pieroneurl\n')


def test_login_zign_user(monkeypatch, tmpdir):
    zign_user = 'zign_user'
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock_docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
        assert zign_user == user

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': zign_user})
    monkeypatch.setattr('os.getenv', lambda: env_user)
    monkeypatch.setattr('pierone.cli.docker_login', mock_docker_login)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')


def test_login_env_user(monkeypatch, tmpdir):
    env_user = 'env_user'

    response = MagicMock()

    runner = CliRunner()

    def mock_docker_login(url, realm, name, user, password, token_url=None, use_keyring=True, prompt=False):
        assert env_user == user

    monkeypatch.setattr('zign.api.get_config', lambda: {'user': ''})
    monkeypatch.setattr('os.getenv', lambda x: env_user)
    monkeypatch.setattr('pierone.cli.docker_login', mock_docker_login)
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')


def test_login_given_url_option(monkeypatch, tmpdir):
    response = MagicMock()

    runner = CliRunner()

    config = {}

    def store(data, section):
        config.update(**data)

    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {})
    monkeypatch.setattr('stups_cli.config.store_config', store)
    monkeypatch.setattr('pierone.api.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('requests.get', lambda x, timeout: response)

    with runner.isolated_filesystem():
        runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        assert config == {'url': 'https://pieroneurl'}
        runner.invoke(cli, ['login', '--url', 'someotherregistry'], catch_exceptions=False)
        with open(os.path.join(str(tmpdir), '.docker/config.json')) as fd:
            data = json.load(fd)
        assert data['auths']['https://pieroneurl']['auth'] == 'b2F1dGgyOnRvazEyMw=='
        assert data['auths']['https://someotherregistry']['auth'] == 'b2F1dGgyOnRvazEyMw=='
        assert config == {'url': 'https://pieroneurl'}


def test_scm_source(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = {'url': 'git:somerepo', 'revision': 'myrev123'}

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.cli.get_tags', MagicMock(return_value={}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['scm-source', 'myteam', 'myart', '1.0'], catch_exceptions=False)
        assert 'myrev123' in result.output
        assert 'git:somerepo' in result.output


def test_image(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = [{'name': '1.0', 'team': 'stups', 'artifact': 'kio'}]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
        assert 'kio' in result.output
        assert 'stups' in result.output
        assert '1.0' in result.output


def test_tags(monkeypatch, tmpdir):
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
            "severity_fix_available": "High",
            "severity_no_fix_available": "Medium"
        }
    ]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['tags', 'myteam', 'myart'], catch_exceptions=False)
        assert '1.0' in result.output
        assert 'Fixable CVE Severity' in result.output
        assert 'Unfixable CVE Severity' in result.output
        assert 'TOO_OLD' in result.output
        assert 'NOT_PROCESSED_YET' in result.output
        assert 'NO_CVES_FOUND' in result.output
        assert re.search('HIGH\s+MEDIUM', result.output), 'Should how information about CVEs'


def test_cves(monkeypatch, tmpdir):
    pierone_service_payload = [
        # Former pierone payload
        {
            'name': '1.0',
            'created_by': 'myuser',
            'created': '2015-08-20T08:14:59.432Z'
        },
        # New pierone payload with clair but no information about CVEs
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": None,
            "severity_fix_available": None,
            "severity_no_fix_available": None
        },
        # New pierone payload with clair input and info about CVEs
        {
            "name": "1.2",
            "created": "2016-05-23T13:29:17.753Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "severity_fix_available": "High",
            "severity_no_fix_available": "Medium"
        }
    ]

    with open(os.path.join(os.path.dirname(__file__),
                           'fixtures', 'clair_response.json'), 'r') as fixture:
        clair_service_payload = json.loads(fixture.read())

    response = MagicMock()
    response.json.side_effect = [
        pierone_service_payload,
        clair_service_payload
    ]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar', 'clair_url': 'barfoo'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['cves', 'myteam', 'myart', '1.2'], catch_exceptions=False)
        assert 'CVE-2013-5123' in result.output
        assert re.match('[^\n]+\n[^\n]+HIGH', result.output), 'Results should be ordered by highest priority'


def test_no_cves_found(monkeypatch, tmpdir):
    pierone_service_payload = [
        # Former pierone payload
        {
            'name': '1.0',
            'created_by': 'myuser',
            'created': '2015-08-20T08:14:59.432Z'
        },
        # New pierone payload with clair but no information about CVEs
        {
            "name": "1.1",
            "created": "2016-05-19T15:23:41.065Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": None,
            "severity_fix_available": None,
            "severity_no_fix_available": None
        },
        # New pierone payload with clair input and info about CVEs
        {
            "name": "1.2",
            "created": "2016-05-23T13:29:17.753Z",
            "created_by": "myuser",
            "image": "sha256:here",
            "clair_id": "sha256:here",
            "severity_fix_available": "High",
            "severity_no_fix_available": "Medium"
        }
    ]

    no_cves_clair_payload = {
        "Layer": {
            "Name": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "NamespaceName": "ubuntu:16.04",
            "ParentName": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
            "IndexedByVersion": 2
        }
    }

    response = MagicMock()
    response.json.side_effect = [
        pierone_service_payload,
        no_cves_clair_payload
    ]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'foobar', 'clair_url': 'barfoo'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['cves', 'myteam', 'myart', '1.2'], catch_exceptions=False)
        assert re.match('^[^\n]+\n$', result.output), 'No results should be shown'


def test_latest(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = [
            {'name': '1.0', 'created_by': 'myuser', 'created': '2015-08-20T08:14:59.432Z'},
            # 1.1 was pushed BEFORE 1.0, i.e. latest tag is actually "1.0"!
            {'name': '1.1', 'created_by': 'myuser', 'created': '2015-08-20T08:11:59.432Z'}]

    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'https://pierone.example.org'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['latest', 'myteam', 'myart'], catch_exceptions=False)
        assert '1.0' == result.output.rstrip()


def test_latest_not_found(monkeypatch, tmpdir):
    response = MagicMock()
    response.raise_for_status.side_effect = Exception('FAIL')
    runner = CliRunner()
    monkeypatch.setattr('stups_cli.config.load_config', lambda x: {'url': 'https://pierone.example.org'})
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('pierone.api.get_existing_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['latest', 'myteam', 'myart'], catch_exceptions=False)
        assert 'None' == result.output.rstrip()


def test_url_without_scheme(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = [{'name': '1.0', 'created_by': 'myuser', 'created': '2015-08-20T08:14:59.432Z'}]

    def get(url, **kwargs):
        assert url == 'https://example.org/teams/myteam/artifacts'
        return response

    runner = CliRunner()
    monkeypatch.setattr('zign.api.get_token', MagicMock(return_value='tok123'))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', get)
    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['artifacts', 'myteam', '--url', 'example.org'], catch_exceptions=False)
        assert '1.0' in result.output
