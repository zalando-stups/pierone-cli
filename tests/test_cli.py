import json
from click.testing import CliRunner
from unittest.mock import MagicMock
import yaml
import zign.api
from pierone.cli import cli


def test_version(monkeypatch):
    runner = CliRunner()

    with runner.isolated_filesystem():
        result = runner.invoke(cli, ['--version'], catch_exceptions=False)
        assert 'Pier One CLI' in result.output


def test_login(monkeypatch, tmpdir):
    response = MagicMock()

    runner = CliRunner()

    monkeypatch.setattr('pierone.cli.CONFIG_FILE_PATH', 'config.yaml')
    monkeypatch.setattr('pierone.api.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            fd.write('')

        result = runner.invoke(cli, ['login'], catch_exceptions=False, input='pieroneurl\n')
        assert 'Storing Docker client configuration' in result.output
        assert result.output.rstrip().endswith('OK')


def test_scm_source(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = {'url': 'git:somerepo', 'revision': 'myrev123'}

    runner = CliRunner()
    monkeypatch.setattr('pierone.cli.CONFIG_FILE_PATH', 'config.yaml')
    monkeypatch.setattr('pierone.cli.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('pierone.cli.get_tags', MagicMock(return_value={}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            fd.write('')
        result = runner.invoke(cli, ['scm-source', 'myteam', 'myart', '1.0'], catch_exceptions=False)
        assert 'myrev123' in result.output
        assert 'git:somerepo' in result.output

def test_image(monkeypatch, tmpdir):
    response = MagicMock()
    response.json.return_value = [{'name': '1.0', 'team': 'stups', 'artifact': 'kio'}]

    runner = CliRunner()
    monkeypatch.setattr('pierone.cli.CONFIG_FILE_PATH', 'config.yaml')
    monkeypatch.setattr('pierone.cli.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))
    monkeypatch.setattr('pierone.api.session.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            fd.write('')
        result = runner.invoke(cli, ['image', 'abcd'], catch_exceptions=False)
        assert 'kio' in result.output
        assert 'stups' in result.output
        assert '1.0' in result.output
