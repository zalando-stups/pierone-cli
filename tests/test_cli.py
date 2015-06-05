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
    runner = CliRunner()

    monkeypatch.setattr('pierone.cli.CONFIG_FILE_PATH', 'config.yaml')
    monkeypatch.setattr('pierone.api.get_named_token', MagicMock(return_value={'access_token': 'tok123'}))
    monkeypatch.setattr('os.path.expanduser', lambda x: x.replace('~', str(tmpdir)))

    with runner.isolated_filesystem():
        with open('config.yaml', 'w') as fd:
            fd.write('')

        result = runner.invoke(cli, ['login'], catch_exceptions=False)
        assert 'Storing Docker client configuration' in result.output
        assert result.output.rstrip().endswith('OK')
