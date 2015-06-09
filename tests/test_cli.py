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
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))

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
    monkeypatch.setattr('requests.get', MagicMock(return_value=response))
    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            fd.write('')
        result = runner.invoke(cli, ['scm-source', 'myteam', 'myart', '1.0'], catch_exceptions=False)
        assert 'myrev123' in result.output
        assert 'git:somerepo' in result.output
